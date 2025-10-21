# automod.py
# Advanced automoderation module for disnake-based bots
# Drop-in: import and call check_and_enforce(bot, message) inside on_message before processing commands

from __future__ import annotations

import asyncio
import json
import os
import re
import time
from collections import deque, defaultdict
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Tuple

import disnake

# -------- Paths --------
DATA_DIR = os.path.join(os.getcwd(), "data")
CONFIG_PATH = os.path.join(DATA_DIR, "automod_config.json")
BLACKLISTS_PATH = os.path.join(DATA_DIR, "automod_blacklists.json")

# -------- In-memory state --------
_duplicate_cache: Dict[Tuple[int, int], deque] = defaultdict(lambda: deque(maxlen=10))  # (guild_id, user_id) -> deque[(hash, ts)]
_recent_messages_ts: Dict[Tuple[int, int], deque] = defaultdict(lambda: deque(maxlen=10))  # (guild_id, user_id) -> deque[timestamps]

# -------- Utilities --------

def _now() -> float:
    return time.time()


def _ensure_data_dir() -> None:
    os.makedirs(DATA_DIR, exist_ok=True)


# Default config and blacklists
_DEFAULT_CONFIG = {
    "enabled": True,
    "owner_id": None,
    "moderator_role_ids": [],
    "mute_role_name": "✘ Душный ✘",
    "embed_delete_after_seconds": 20,
    "log_channel_id": None,
    "filters": {
        "bad_words": {"enabled": False},  # keep off here; project may already handle it elsewhere
        "invite_link": {"enabled": True},
        "caps": {"enabled": True, "min_letters": 8, "ratio": 0.7},
        "spam": {"enabled": True, "window_seconds": 10, "max_messages": 6},
        "mass_mentions": {"enabled": True, "max_mentions": 5, "max_role_mentions": 2, "block_everyone": True},
        "emoji_spam": {"enabled": True, "max_emojis": 20, "max_unique": 15, "ratio_threshold": 0.5},
        "zalgo": {"enabled": True, "threshold": 5},
        "repeated_chars": {"enabled": True, "max_repeat": 6},
        "url_blacklist": {"enabled": True},
        "phrase_blacklist": {"enabled": True},
        "attachment_blocklist": {"enabled": True, "extensions": ["exe", "scr", "bat", "cmd", "ps1", "jar", "apk"]},
        "duplicate_messages": {"enabled": True, "window_seconds": 10, "max_duplicates": 2},
        "long_message": {"enabled": True, "max_chars": 3500, "max_lines": 45},
    },
    "punishments": {
        "invite_link": {"type": "timeout", "seconds": 3600},
        "caps": {"type": "timeout", "seconds": 900},
        "spam": {"type": "timeout", "seconds": 1200},
        "mass_mentions": {"type": "timeout", "seconds": 1800},
        "emoji_spam": {"type": "timeout", "seconds": 1200},
        "zalgo": {"type": "timeout", "seconds": 900},
        "repeated_chars": {"type": "timeout", "seconds": 900},
        "url_blacklist": {"type": "timeout", "seconds": 3600},
        "phrase_blacklist": {"type": "timeout", "seconds": 3600},
        "attachment_blocklist": {"type": "timeout", "seconds": 3600},
        "duplicate_messages": {"type": "timeout", "seconds": 1200},
        "long_message": {"type": "timeout", "seconds": 900},
    },
}

_DEFAULT_BLACKLISTS = {
    "domains": [
        "discordgift.site",
        "discorcl.com",
        "dlscord.com",
        "nitrofree.xyz",
        "steam-nitro.org",
        "steam-gifts.net",
        "xn--discord-g1a.com",
    ],
    "phrases": [
        "free nitro",
        "steam giveaway",
        "claim your nitro",
        "airdrop",
        "crypto pump",
        "you won",
        "забери нитро",
        "бесплатное нитро",
        "розыгрыш нитро",
    ],
}


def load_config() -> Dict[str, Any]:
    _ensure_data_dir()
    if not os.path.exists(CONFIG_PATH):
        with open(CONFIG_PATH, "w", encoding="utf-8") as f:
            json.dump(_DEFAULT_CONFIG, f, ensure_ascii=False, indent=2)
        return json.loads(json.dumps(_DEFAULT_CONFIG))
    with open(CONFIG_PATH, "r", encoding="utf-8") as f:
        try:
            cfg = json.load(f)
        except Exception:
            cfg = json.loads(json.dumps(_DEFAULT_CONFIG))
    return cfg


def load_blacklists() -> Dict[str, Any]:
    _ensure_data_dir()
    if not os.path.exists(BLACKLISTS_PATH):
        with open(BLACKLISTS_PATH, "w", encoding="utf-8") as f:
            json.dump(_DEFAULT_BLACKLISTS, f, ensure_ascii=False, indent=2)
        return json.loads(json.dumps(_DEFAULT_BLACKLISTS))
    with open(BLACKLISTS_PATH, "r", encoding="utf-8") as f:
        try:
            bl = json.load(f)
        except Exception:
            bl = json.loads(json.dumps(_DEFAULT_BLACKLISTS))
    return bl


# -------- Detection helpers --------
_URL_RE = re.compile(r"https?://[^\s)]+", re.IGNORECASE)
_DOMAIN_RE = re.compile(r"\b([a-z0-9][a-z0-9\-]{1,63}\.)+[a-z]{2,}\b", re.IGNORECASE)
_CUSTOM_EMOJI_RE = re.compile(r"<a?:\w+:(\d+)>")
# Basic unicode emoji range approximation
_UNICODE_EMOJI_RE = re.compile(
    r"[\U0001F300-\U0001F6FF\U0001F900-\U0001F9FF\U0001FA70-\U0001FAFF\u2600-\u26FF\u2700-\u27BF]"
)
_COMBINING_RE = re.compile(r"[\u0300-\u036F\u0483-\u0489\u1AB0-\u1AFF\u1DC0-\u1DFF\u20D0-\u20FF\uFE20-\uFE2F]")
_REPEAT_RE = re.compile(r"(.)\1{5,}")  # 6+ same chars in a row
_INVITE_RE = re.compile(r"discord(?:\.gg|app\.com/invite|\.com/invite)/[a-z0-9-]+", re.IGNORECASE)


@dataclass
class Violation:
    key: str
    reason: str
    snippet: str


def _text_from_message(msg: disnake.Message) -> str:
    return (msg.content or "").strip()


def _count_emojis(text: str) -> Tuple[int, int]:
    unicode_emojis = _UNICODE_EMOJI_RE.findall(text)
    custom_emojis = _CUSTOM_EMOJI_RE.findall(text)
    return len(unicode_emojis) + len(custom_emojis), len(set(unicode_emojis)) + len(set(custom_emojis))


def detect_mass_mentions(message: disnake.Message, cfg: Dict[str, Any]) -> Optional[Violation]:
    fcfg = cfg["filters"]["mass_mentions"]
    if not fcfg.get("enabled", True):
        return None
    mentions = len(message.mentions)
    role_mentions = len(message.role_mentions)
    everyone = message.mention_everyone
    if everyone and fcfg.get("block_everyone", True):
        return Violation("mass_mentions", "Запрещено упоминание @everyone/@here", _text_from_message(message)[:200])
    if mentions > fcfg.get("max_mentions", 5) or role_mentions > fcfg.get("max_role_mentions", 2):
        return Violation("mass_mentions", "Слишком много упоминаний в одном сообщении", _text_from_message(message)[:200])
    return None


def detect_invite_link(text: str, cfg: Dict[str, Any]) -> Optional[Violation]:
    if not cfg["filters"]["invite_link"].get("enabled", True):
        return None
    if _INVITE_RE.search(text):
        return Violation("invite_link", "Приглашения на сторонние сервера запрещены", text[:200])
    return None


def detect_caps(text: str, cfg: Dict[str, Any]) -> Optional[Violation]:
    fcfg = cfg["filters"]["caps"]
    if not fcfg.get("enabled", True):
        return None
    letters = [c for c in text if c.isalpha()]
    if len(letters) < fcfg.get("min_letters", 8):
        return None
    caps = sum(1 for c in letters if c.isupper())
    if len(letters) > 0 and (caps / len(letters)) >= fcfg.get("ratio", 0.7):
        return Violation("caps", "Слишком много КАПСА", text[:200])
    return None


def detect_emoji_spam(text: str, cfg: Dict[str, Any]) -> Optional[Violation]:
    fcfg = cfg["filters"]["emoji_spam"]
    if not fcfg.get("enabled", True):
        return None
    total, unique = _count_emojis(text)
    if total >= fcfg.get("max_emojis", 20) or unique >= fcfg.get("max_unique", 15):
        return Violation("emoji_spam", "Спам эмодзи", text[:200])
    # ratio vs visible chars
    vis = len([c for c in text if not c.isspace()])
    if vis >= 12 and (total / max(vis, 1)) >= fcfg.get("ratio_threshold", 0.5):
        return Violation("emoji_spam", "Слишком много эмодзи относительно текста", text[:200])
    return None


def detect_zalgo(text: str, cfg: Dict[str, Any]) -> Optional[Violation]:
    fcfg = cfg["filters"]["zalgo"]
    if not fcfg.get("enabled", True):
        return None
    comb = len(_COMBINING_RE.findall(text))
    if comb >= fcfg.get("threshold", 5):
        return Violation("zalgo", "Залго/декоративные символы запрещены", text[:200])
    return None


def detect_repeated_chars(text: str, cfg: Dict[str, Any]) -> Optional[Violation]:
    fcfg = cfg["filters"]["repeated_chars"]
    if not fcfg.get("enabled", True):
        return None
    if _REPEAT_RE.search(text):
        return Violation("repeated_chars", "Слишком много повторяющихся символов", text[:200])
    return None


def detect_url_or_domain_blacklist(text: str, cfg: Dict[str, Any], bl: Dict[str, Any]) -> Optional[Violation]:
    if not cfg["filters"]["url_blacklist"].get("enabled", True):
        return None
    domains = set(bl.get("domains", []))
    if not domains:
        return None
    urls = _URL_RE.findall(text)
    # Also raw domains
    urls += _DOMAIN_RE.findall(text)
    for u in urls:
        u_lower = u.lower()
        for d in domains:
            d = d.lower()
            if u_lower.endswith(d) or (d in u_lower):
                return Violation("url_blacklist", f"Запрещённый домен: {d}", text[:200])
    return None


def detect_phrase_blacklist(text: str, cfg: Dict[str, Any], bl: Dict[str, Any]) -> Optional[Violation]:
    if not cfg["filters"]["phrase_blacklist"].get("enabled", True):
        return None
    phrases = [p.lower() for p in bl.get("phrases", [])]
    t = text.lower()
    for p in phrases:
        if p and p in t:
            return Violation("phrase_blacklist", f"Запрещённая фраза: {p}", text[:200])
    return None


def detect_attachment_blocklist(message: disnake.Message, cfg: Dict[str, Any]) -> Optional[Violation]:
    fcfg = cfg["filters"]["attachment_blocklist"]
    if not fcfg.get("enabled", True):
        return None
    blocked = set(ext.lower().lstrip(".") for ext in fcfg.get("extensions", []))
    for att in message.attachments:
        _, dot, ext = att.filename.rpartition(".")
        if dot and ext.lower() in blocked:
            return Violation("attachment_blocklist", f"Запрещённый тип файла: .{ext.lower()}", att.filename)
    return None


def detect_duplicate_messages(message: disnake.Message, cfg: Dict[str, Any]) -> Optional[Violation]:
    fcfg = cfg["filters"]["duplicate_messages"]
    if not fcfg.get("enabled", True):
        return None
    key = (message.guild.id, message.author.id)
    window = fcfg.get("window_seconds", 10)
    max_dups = fcfg.get("max_duplicates", 2)
    dq = _duplicate_cache[key]
    now = _now()
    # prune
    while dq and now - dq[0][1] > window:
        dq.popleft()
    h = hash((_text_from_message(message) or "").strip())
    same = sum(1 for hh, ts in dq if hh == h)
    dq.append((h, now))
    if same + 1 > max_dups:
        return Violation("duplicate_messages", "Повторяющиеся сообщения (дубликаты)", _text_from_message(message)[:200])
    return None


def detect_long_message(text: str, cfg: Dict[str, Any]) -> Optional[Violation]:
    fcfg = cfg["filters"]["long_message"]
    if not fcfg.get("enabled", True):
        return None
    if len(text) > fcfg.get("max_chars", 3500) or text.count("\n") > fcfg.get("max_lines", 45):
        return Violation("long_message", "Слишком длинное сообщение", text[:200])
    return None


def detect_spam_rate(message: disnake.Message, cfg: Dict[str, Any]) -> Optional[Violation]:
    fcfg = cfg["filters"]["spam"]
    if not fcfg.get("enabled", True):
        return None
    key = (message.guild.id, message.author.id)
    dq = _recent_messages_ts[key]
    now = _now()
    window = fcfg.get("window_seconds", 10)
    limit = fcfg.get("max_messages", 6)
    dq.append(now)
    while dq and now - dq[0] > window:
        dq.popleft()
    if len(dq) > limit:
        return Violation("spam", "Слишком много сообщений за короткое время", _text_from_message(message)[:200])
    return None


# -------- Enforcement --------

async def _get_or_create_mute_role(guild: disnake.Guild, role_name: str) -> disnake.Role:
    role = disnake.utils.get(guild.roles, name=role_name)
    if role:
        return role
    role = await guild.create_role(name=role_name, color=disnake.Color.from_rgb(255, 0, 4), reason="Automod mute role")
    for channel in guild.channels:
        try:
            overwrites = channel.overwrites_for(role)
            changed = False
            if isinstance(channel, disnake.TextChannel):
                if overwrites.send_messages is not False:
                    overwrites.send_messages = False
                    changed = True
                if overwrites.add_reactions is not False:
                    overwrites.add_reactions = False
                    changed = True
            elif isinstance(channel, disnake.VoiceChannel):
                if overwrites.speak is not False:
                    overwrites.speak = False
                    changed = True
                if overwrites.connect is not False:
                    overwrites.connect = False
                    changed = True
            if changed:
                await channel.set_permissions(role, overwrite=overwrites)
        except Exception:
            continue
    return role


def _format_duration(seconds: int) -> str:
    if seconds <= 0:
        return "0с"
    d, rem = divmod(seconds, 86400)
    h, rem = divmod(rem, 3600)
    m, s = divmod(rem, 60)
    parts = []
    if d:
        parts.append(f"{d}д")
    if h:
        parts.append(f"{h}ч")
    if m:
        parts.append(f"{m}м")
    if s and not parts:
        parts.append(f"{s}с")
    return " ".join(parts)


def _violation_title(key: str) -> str:
    mapping = {
        "invite_link": "Запрещённая ссылка",
        "caps": "КАПСЛОК",
        "spam": "Спам",
        "mass_mentions": "Массовые упоминания",
        "emoji_spam": "Спам эмодзи",
        "zalgo": "Залго/декоративный текст",
        "repeated_chars": "Повтор символов",
        "url_blacklist": "Запрещённый домен",
        "phrase_blacklist": "Запрещённая фраза",
        "attachment_blocklist": "Запрещённый файл",
        "duplicate_messages": "Дубликат сообщения",
        "long_message": "Слишком длинное сообщение",
    }
    return mapping.get(key, key)


async def _send_punishment_embed(bot: disnake.Client, message: disnake.Message, v: Violation, seconds: int, cfg: Dict[str, Any]) -> None:
    color_map = {
        "spam": 0x9b59b6,
        "mass_mentions": 0xe67e22,
        "emoji_spam": 0x9b59b6,
        "invite_link": 0xf39c12,
        "url_blacklist": 0xf39c12,
        "phrase_blacklist": 0xf39c12,
        "caps": 0x3498db,
        "zalgo": 0x3498db,
        "repeated_chars": 0x3498db,
        "attachment_blocklist": 0xe74c3c,
        "duplicate_messages": 0x9b59b6,
        "long_message": 0x3498db,
    }
    color = color_map.get(v.key, 0xe74c3c)
    embed = disnake.Embed(
        title=f"🛡️ Нарушение: {_violation_title(v.key)}",
        description=(
            f"{message.author.mention} нарушил(а) правило: **{_violation_title(v.key)}**\n"
            f"Причина: {v.reason}\n"
            f"Наказание: **Тайм-аут { _format_duration(seconds) }**"
        ),
        color=color,
        timestamp=disnake.utils.utcnow(),
    )
    if v.snippet:
        snippet = v.snippet
        if len(snippet) > 512:
            snippet = snippet[:509] + "..."
        embed.add_field(name="Фрагмент", value=f"```{snippet}```", inline=False)
    embed.set_author(name=f"{message.author.display_name}", icon_url=message.author.display_avatar.url)
    embed.set_footer(text=f"ID пользователя: {message.author.id}")

    try:
        sent = await message.channel.send(embed=embed)
        delay = int(cfg.get("embed_delete_after_seconds", 20) or 0)
        if delay > 0:
            async def _auto_delete():
                await asyncio.sleep(delay)
                try:
                    await sent.delete()
                except Exception:
                    pass
            asyncio.create_task(_auto_delete())
    except Exception:
        pass

    # Optional: log channel
    try:
        log_id = cfg.get("log_channel_id")
        if log_id:
            ch = bot.get_channel(int(log_id))
            if ch and ch.id != message.channel.id:
                await ch.send(embed=embed)
    except Exception:
        pass


async def _apply_punishment(bot: disnake.Client, message: disnake.Message, v: Violation, cfg: Dict[str, Any]) -> None:
    punish_cfg = cfg.get("punishments", {}).get(v.key) or {"type": "timeout", "seconds": 600}
    ptype = punish_cfg.get("type", "timeout")
    seconds = int(punish_cfg.get("seconds", 600))

    # delete offending message
    try:
        await message.delete()
    except Exception:
        pass

    member: disnake.Member = message.author  # type: ignore
    if not isinstance(member, disnake.Member):
        try:
            member = await message.guild.fetch_member(message.author.id)  # type: ignore
        except Exception:
            member = message.author  # type: ignore

    if ptype == "timeout":
        # Prefer native timeout (a.k.a. mute)
        try:
            await member.timeout(duration=disnake.utils.utcnow() + disnake.utils.timedelta(seconds=seconds), reason=f"Automod: {v.key}")  # type: ignore
        except Exception:
            # Fallback to mute role
            try:
                role = await _get_or_create_mute_role(message.guild, cfg.get("mute_role_name", "✘ Душный ✘"))
                await member.add_roles(role, reason=f"Automod: {v.key}")
            except Exception:
                pass
    elif ptype == "mute_role":
        try:
            role = await _get_or_create_mute_role(message.guild, cfg.get("mute_role_name", "✘ Душный ✘"))
            await member.add_roles(role, reason=f"Automod: {v.key}")
        except Exception:
            pass

    await _send_punishment_embed(bot, message, v, seconds, cfg)


def _is_privileged(member: disnake.Member, cfg: Dict[str, Any]) -> bool:
    try:
        owner_id = cfg.get("owner_id")
        if owner_id and int(owner_id) == member.id:
            return True
    except Exception:
        pass
    try:
        mod_role_ids = set(int(x) for x in cfg.get("moderator_role_ids", []) if x)
        for r in member.roles:
            if r.id in mod_role_ids:
                return True
    except Exception:
        pass
    if member.guild_permissions.administrator:
        return True
    return False


async def check_and_enforce(bot: disnake.Client, message: disnake.Message, config: Optional[Dict[str, Any]] = None, blacklists: Optional[Dict[str, Any]] = None) -> Optional[str]:
    """
    Run automod checks and enforce if violation is detected.
    Returns violation key if action was taken; otherwise None.
    """
    if message.guild is None or message.author.bot:
        return None

    cfg = config or load_config()
    if not cfg.get("enabled", True):
        return None

    # Skip privileged
    try:
        member: disnake.Member = message.author  # type: ignore
        if _is_privileged(member, cfg):
            return None
    except Exception:
        pass

    text = _text_from_message(message)

    # Order of checks: fast to heavy
    detectors = [
        lambda: detect_mass_mentions(message, cfg),
        lambda: detect_invite_link(text, cfg),
        lambda: detect_attachment_blocklist(message, cfg),
        lambda: detect_caps(text, cfg),
        lambda: detect_emoji_spam(text, cfg),
        lambda: detect_zalgo(text, cfg),
        lambda: detect_repeated_chars(text, cfg),
        lambda: detect_duplicate_messages(message, cfg),
        lambda: detect_spam_rate(message, cfg),
        lambda: detect_long_message(text, cfg),
        lambda: detect_url_or_domain_blacklist(text, cfg, blacklists or load_blacklists()),
        lambda: detect_phrase_blacklist(text, cfg, blacklists or load_blacklists()),
    ]

    violation: Optional[Violation] = None
    for fn in detectors:
        try:
            v = fn()
        except Exception:
            v = None
        if v is not None:
            violation = v
            break

    if violation is None:
        return None

    await _apply_punishment(bot, message, violation, cfg)
    return violation.key


__all__ = [
    "check_and_enforce",
    "load_config",
    "load_blacklists",
]