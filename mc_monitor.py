# mc_monitor.py
# High-fidelity Minecraft Java server status with pretty embeds
# Drop-in helpers to integrate with a disnake bot.

from __future__ import annotations

import asyncio
import json
import struct
import time
from typing import Any, Dict, Optional

import disnake

# -------- Minecraft protocol helpers --------

# Known protocol versions list evolves, any value works for status. 765 (1.20.4) is fine.
PROTOCOL_VERSION = 765


def _pack_varint(value: int) -> bytes:
    out = bytearray()
    v = value & 0xFFFFFFFF
    while True:
        temp = v & 0x7F
        v >>= 7
        if v != 0:
            temp |= 0x80
        out.append(temp)
        if v == 0:
            break
    return bytes(out)


def _unpack_varint_from(buf: bytes, offset: int = 0) -> tuple[int, int]:
    num = 0
    num_read = 0
    while True:
        if offset + num_read >= len(buf):
            raise ValueError("buffer ended while reading varint")
        b = buf[offset + num_read]
        value = b & 0x7F
        num |= value << (7 * num_read)
        num_read += 1
        if num_read > 5:
            raise ValueError("VarInt too big")
        if (b & 0x80) == 0:
            break
    return num, offset + num_read


def _pack_string(s: str) -> bytes:
    data = s.encode("utf-8")
    return _pack_varint(len(data)) + data


async def _read_varint(reader: asyncio.StreamReader) -> int:
    num = 0
    num_read = 0
    while True:
        b = await reader.readexactly(1)
        bb = b[0]
        value = bb & 0x7F
        num |= value << (7 * num_read)
        num_read += 1
        if num_read > 5:
            raise ValueError("VarInt too big")
        if (bb & 0x80) == 0:
            break
    return num


async def query_minecraft_status(host: str, port: int = 25565, timeout: float = 5.0) -> Dict[str, Any]:
    """Perform a real Minecraft Java status query using the Server List Ping protocol.
    Returns a dict with: online(bool), players{}, version(str), description(str), ping(int), error(Optional[str])
    """
    start_connect = time.perf_counter()
    try:
        reader, writer = await asyncio.wait_for(asyncio.open_connection(host, port), timeout=timeout)
    except Exception as e:
        return {
            "online": False,
            "players": {"online": 0, "max": 0},
            "version": "—",
            "description": "Сервер недоступен",
            "ping": 0,
            "error": str(e),
        }

    try:
        # Handshake (packet 0x00)
        payload = bytearray()
        payload += _pack_varint(0x00)  # packet id
        payload += _pack_varint(PROTOCOL_VERSION)
        payload += _pack_string(host)
        payload += struct.pack(">H", port)
        payload += _pack_varint(1)  # next state: status
        packet = _pack_varint(len(payload)) + payload
        writer.write(packet)

        # Status request (packet 0x00, no payload)
        writer.write(b"\x01\x00")
        await writer.drain()

        # Response
        length = await _read_varint(reader)
        data = await reader.readexactly(length)
        # Parse: packet id varint, then json length varint, then json bytes
        pid, off = _unpack_varint_from(data, 0)
        if pid != 0x00:
            raise ValueError(f"Unexpected packet id {pid}")
        json_len, off2 = _unpack_varint_from(data, off)
        json_bytes = data[off2 : off2 + json_len]
        status = json.loads(json_bytes.decode("utf-8", errors="replace"))

        # Ping phase (packet 0x01 with 8-byte payload)
        send_time = int(time.time() * 1000)
        ping_payload = struct.pack(">q", send_time)
        ping_packet = _pack_varint(1 + len(ping_payload)) + b"\x01" + ping_payload
        t0 = time.perf_counter()
        writer.write(ping_packet)
        await writer.drain()

        # Read pong
        pong_len = await _read_varint(reader)
        pong_data = await reader.readexactly(pong_len)
        pong_pid, p_off = _unpack_varint_from(pong_data, 0)
        if pong_pid != 0x01:
            raise ValueError("Unexpected pong packet id")
        _ = pong_data[p_off : p_off + 8]  # echo payload (not needed)
        rtt_ms = int((time.perf_counter() - t0) * 1000)

        # Extract fields
        players = status.get("players", {}) or {}
        version_name = (status.get("version", {}) or {}).get("name", "—")
        desc = status.get("description", {})
        description = _motd_to_string(desc)

        return {
            "online": True,
            "players": {"online": int(players.get("online") or 0), "max": int(players.get("max") or 0), "sample": players.get("sample") or []},
            "version": version_name,
            "description": description,
            "ping": rtt_ms,
            "favicon": status.get("favicon"),
            "error": None,
        }
    except Exception as e:
        return {
            "online": False,
            "players": {"online": 0, "max": 0},
            "version": "—",
            "description": "Сервер недоступен",
            "ping": 0,
            "error": str(e),
        }
    finally:
        try:
            writer.close()
            await writer.wait_closed()
        except Exception:
            pass


def _motd_to_string(desc: Any) -> str:
    if isinstance(desc, str):
        return desc
    if isinstance(desc, dict):
        parts = []
        if "text" in desc:
            parts.append(str(desc.get("text") or ""))
        if "extra" in desc and isinstance(desc["extra"], list):
            for it in desc["extra"]:
                if isinstance(it, dict):
                    parts.append(str(it.get("text") or ""))
                elif isinstance(it, str):
                    parts.append(it)
        return "".join(parts) or "—"
    if isinstance(desc, list):
        return "".join(_motd_to_string(x) for x in desc)
    return "—"


# -------- High-level wrapper with cache --------

class MinecraftServer:
    def __init__(self, name: str, host: str, port: int = 25565, cache_seconds: int = 30):
        self.name = name
        self.host = host
        self.port = int(port)
        self.cache_seconds = cache_seconds
        self._last_ts: float = 0.0
        self._cached: Optional[Dict[str, Any]] = None

    async def get_status(self) -> Dict[str, Any]:
        now = time.time()
        if self._cached and (now - self._last_ts) < self.cache_seconds:
            return self._cached
        data = await query_minecraft_status(self.host, self.port)
        self._cached = data
        self._last_ts = now
        return data


# -------- Pretty Embed --------

def _quality_emoji(ping_ms: int) -> str:
    if ping_ms <= 0:
        return "⚪"
    if ping_ms < 100:
        return "🟢"
    if ping_ms < 250:
        return "🟡"
    return "🔴"


def _progress_bar(current: int, maximum: int, width: int = 20) -> tuple[str, int]:
    if maximum <= 0:
        return "░" * width, 0
    filled = max(0, min(width, round(width * (current / maximum))))
    return ("█" * filled + "░" * (width - filled)), int((current / maximum) * 100)


async def create_minecraft_status_embed(server_name: str, server_data: Dict[str, Any]) -> disnake.Embed:
    online = bool(server_data.get("online"))
    color = 0x2ecc71 if online else 0xe74c3c
    status_icon = "🟢 ONLINE" if online else "🔴 OFFLINE"

    embed = disnake.Embed(
        title=f"🎮 {server_name}",
        description=f"**Статус:** {status_icon}",
        color=color,
        timestamp=disnake.utils.utcnow(),
    )

    if online:
        players = server_data.get("players", {}) or {}
        online_count = int(players.get("online") or 0)
        max_count = int(players.get("max") or 0)
        bar, pct = _progress_bar(online_count, max_count or 1, width=22)
        ping = int(server_data.get("ping") or 0)
        q = _quality_emoji(ping)
        version = server_data.get("version", "—")
        motd = server_data.get("description", "—")

        # Players block
        embed.add_field(
            name="📊 Игроки",
            value=(
                f"`{online_count}/{max_count}` • {pct}%\n"
                f"``\n{bar}\n```"
            ),
            inline=False,
        )

        # Tech block
        embed.add_field(
            name="🔧 Технически",
            value=(
                f"**Версия:** `{version}`\n"
                f"**Пинг:** `{ping} мс` {q}\n"
                f"**MOTD:** {motd}"
            ),
            inline=False,
        )

        # Sample players if present
        sample = players.get("sample") or []
        if isinstance(sample, list) and sample:
            names = []
            for p in sample[:10]:
                if isinstance(p, dict):
                    n = p.get("name") or p.get("id")
                else:
                    n = str(p)
                if n:
                    names.append(str(n))
            if names:
                embed.add_field(
                    name=f"👥 Примеры игроков ({len(names)})",
                    value=", ".join(f"`{n}`" for n in names),
                    inline=False,
                )

        embed.set_footer(text="Coldfire Monitoring • Обновляется каждые 5 минут")
    else:
        err = server_data.get("error") or "Неизвестная ошибка"
        embed.add_field(
            name="❌ Сервер недоступен",
            value=f"```diff\n- {err}\n```\nПроверьте адрес, порт или доступность сервера.",
            inline=False,
        )
        embed.set_footer(text="Coldfire Monitoring • Попробуем ещё раз позже")

    return embed


# -------- Convenience updater --------

async def update_monitor_message(bot: disnake.Client, channel_id: int, server_name: str, host: str, port: int = 25565, message_id: Optional[int] = None) -> Optional[int]:
    """Fetch status and create/update a message in the specified channel.
    Returns the message id (new or existing) or None on failure.
    """
    ch = bot.get_channel(int(channel_id))
    if not ch or not isinstance(ch, disnake.TextChannel):
        return None
    server = MinecraftServer(server_name, host, port)
    data = await server.get_status()
    embed = await create_minecraft_status_embed(server_name, data)
    try:
        if message_id:
            try:
                msg = await ch.fetch_message(int(message_id))
                await msg.edit(embed=embed)
                return msg.id
            except Exception:
                # fallback to sending anew
                pass
        msg = await ch.send(embed=embed)
        return msg.id
    except Exception:
        return None
