#!/usr/bin/env python3
"""
IRON - Secure Reverse TCP Tunnel
Hub runs on the public/IR server. Agent runs near the real services/EU server.
Standard-library only: asyncio + ssl + hmac.
"""
from __future__ import annotations

import argparse
import asyncio
import contextlib
import hashlib
import hmac
import json
import logging
import os
import secrets
import signal
import socket
import ssl
import struct
import sys
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, Optional, Tuple

VERSION = "1.1.0"
MAGIC = b"IRON/1\n"
MAX_FRAME = 16 * 1024 * 1024
HDR = struct.Struct("!BI")  # type, stream id, payload length is separate? keep 1+4+4
HDR2 = struct.Struct("!BII")

T_OPEN = 1
T_DATA = 2
T_CLOSE = 3
T_PING = 4
T_PONG = 5
T_ERROR = 6
T_INFO = 7

log = logging.getLogger("iron")


@dataclass
class Stream:
    reader: asyncio.StreamReader
    writer: asyncio.StreamWriter
    pump_tasks: list[asyncio.Task]


def load_json(path: str) -> Dict[str, Any]:
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def get_required(cfg: Dict[str, Any], key: str) -> Any:
    if key not in cfg:
        raise SystemExit(f"missing required config key: {key}")
    return cfg[key]


def hmac_hex(token: str, *parts: bytes) -> str:
    key = token.encode("utf-8")
    msg = b"|".join(parts)
    return hmac.new(key, msg, hashlib.sha256).hexdigest()


async def read_exact(reader: asyncio.StreamReader, n: int) -> bytes:
    data = await reader.readexactly(n)
    return data


async def send_json_line(writer: asyncio.StreamWriter, obj: Dict[str, Any]) -> None:
    raw = json.dumps(obj, separators=(",", ":")).encode() + b"\n"
    writer.write(raw)
    await writer.drain()


async def read_json_line(reader: asyncio.StreamReader, limit: int = 65536) -> Dict[str, Any]:
    raw = await reader.readline()
    if not raw or len(raw) > limit:
        raise ConnectionError("invalid or oversized handshake line")
    return json.loads(raw.decode())


async def send_frame(writer: asyncio.StreamWriter, ftype: int, sid: int, payload: bytes = b"") -> None:
    if len(payload) > MAX_FRAME:
        raise ValueError("frame too large")
    writer.write(HDR2.pack(ftype, sid, len(payload)) + payload)
    await writer.drain()


async def read_frame(reader: asyncio.StreamReader) -> Tuple[int, int, bytes]:
    hdr = await read_exact(reader, HDR2.size)
    ftype, sid, length = HDR2.unpack(hdr)
    if length > MAX_FRAME:
        raise ConnectionError("frame too large")
    payload = await read_exact(reader, length) if length else b""
    return ftype, sid, payload


def tune_socket(writer: asyncio.StreamWriter) -> None:
    sock = writer.get_extra_info("socket")
    if not sock:
        return
    with contextlib.suppress(Exception):
        sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
    with contextlib.suppress(Exception):
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)


def make_server_ssl(cfg: Dict[str, Any]) -> ssl.SSLContext:
    cert = get_required(cfg, "certfile")
    key = get_required(cfg, "keyfile")
    ctx = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    ctx.load_cert_chain(cert, key)
    ca = cfg.get("client_ca")
    if ca:
        ctx.load_verify_locations(cafile=ca)
        ctx.verify_mode = ssl.CERT_REQUIRED
    return ctx


def make_client_ssl(cfg: Dict[str, Any]) -> ssl.SSLContext:
    if cfg.get("insecure_skip_verify", False):
        ctx = ssl._create_unverified_context()  # explicit opt-in for lab/self-test only
    else:
        ca = cfg.get("ca_file")
        ctx = ssl.create_default_context(ssl.Purpose.SERVER_AUTH, cafile=ca)
        ctx.check_hostname = bool(cfg.get("server_name"))
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    cert = cfg.get("certfile")
    key = cfg.get("keyfile")
    if cert and key:
        ctx.load_cert_chain(cert, key)
    return ctx


class Hub:
    def __init__(self, cfg: Dict[str, Any]):
        self.cfg = cfg
        self.token = get_required(cfg, "token")
        self.control_host = cfg.get("control_host", "0.0.0.0")
        self.control_port = int(cfg.get("control_port", 9443))
        self.agent_id = cfg.get("agent_id", "default")
        self.streams: Dict[int, Stream] = {}
        self.control_writer: Optional[asyncio.StreamWriter] = None
        self.control_lock = asyncio.Lock()
        self.next_sid = 10
        self.public_servers: list[asyncio.AbstractServer] = []
        self.stop_event = asyncio.Event()

    async def start(self) -> None:
        ssl_ctx = make_server_ssl(self.cfg)
        srv = await asyncio.start_server(self.handle_agent, self.control_host, self.control_port, ssl=ssl_ctx)
        log.info("hub control listening on %s:%s", self.control_host, self.control_port)
        async with srv:
            await self.start_public_listeners()
            await self.stop_event.wait()

    async def start_public_listeners(self) -> None:
        ports = self.cfg.get("ports", [])
        if not ports:
            raise SystemExit("hub config has no ports")
        for item in ports:
            listen_host = item.get("listen_host", "0.0.0.0")
            listen_port = int(item["listen_port"])
            server = await asyncio.start_server(lambda r, w, m=item: self.handle_public(r, w, m), listen_host, listen_port)
            self.public_servers.append(server)
            dest = f"{item.get('target_host','127.0.0.1')}:{item.get('target_port', listen_port)}"
            log.info("public listener %s:%d -> agent %s", listen_host, listen_port, dest)

    async def handle_agent(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        peer = writer.get_extra_info("peername")
        tune_socket(writer)
        try:
            magic = await read_exact(reader, len(MAGIC))
            if magic != MAGIC:
                raise ConnectionError("bad magic")
            hello = await read_json_line(reader)
            if hello.get("role") != "agent":
                raise ConnectionError("bad role")
            agent_id = hello.get("agent_id", "default")
            nonce = secrets.token_hex(24)
            await send_json_line(writer, {"type": "challenge", "nonce": nonce, "version": VERSION})
            resp = await read_json_line(reader)
            expected = hmac_hex(self.token, nonce.encode(), str(agent_id).encode())
            if not hmac.compare_digest(resp.get("hmac", ""), expected):
                raise ConnectionError("auth failed")
            if self.agent_id != "*" and agent_id != self.agent_id:
                raise ConnectionError("agent_id not allowed")
            await send_json_line(writer, {"type": "ok", "server_time": int(time.time())})
            async with self.control_lock:
                if self.control_writer:
                    log.warning("replacing existing agent connection")
                    self.control_writer.close()
                self.control_writer = writer
            log.info("agent connected: %s from %s", agent_id, peer)
            await self.control_loop(reader, writer)
        except Exception as e:
            log.warning("agent connection closed: %s", e)
        finally:
            if self.control_writer is writer:
                self.control_writer = None
            await self.close_all_streams()
            with contextlib.suppress(Exception):
                writer.close(); await writer.wait_closed()

    async def control_loop(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        heartbeat = asyncio.create_task(self.heartbeat(writer))
        try:
            while True:
                ftype, sid, payload = await read_frame(reader)
                if ftype == T_DATA:
                    st = self.streams.get(sid)
                    if st:
                        st.writer.write(payload)
                        await st.writer.drain()
                elif ftype == T_CLOSE:
                    await self.close_stream(sid)
                elif ftype == T_PING:
                    await send_frame(writer, T_PONG, 0, payload)
                elif ftype == T_PONG:
                    pass
                elif ftype == T_ERROR:
                    log.warning("agent error sid=%s: %s", sid, payload.decode(errors="replace"))
                    await self.close_stream(sid)
                elif ftype == T_INFO:
                    log.info("agent info: %s", payload.decode(errors="replace"))
        finally:
            heartbeat.cancel()
            with contextlib.suppress(Exception):
                await heartbeat

    async def heartbeat(self, writer: asyncio.StreamWriter) -> None:
        interval = int(self.cfg.get("heartbeat_seconds", 20))
        while True:
            await asyncio.sleep(interval)
            await send_frame(writer, T_PING, 0, str(int(time.time())).encode())

    async def handle_public(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter, mapping: Dict[str, Any]) -> None:
        tune_socket(writer)
        if not self.control_writer:
            writer.close(); await writer.wait_closed(); return
        sid = self.next_sid
        self.next_sid += 1
        target_host = mapping.get("target_host", "127.0.0.1")
        target_port = int(mapping.get("target_port", mapping["listen_port"]))
        self.streams[sid] = Stream(reader, writer, [])
        payload = json.dumps({"host": target_host, "port": target_port}, separators=(",", ":")).encode()
        try:
            await send_frame(self.control_writer, T_OPEN, sid, payload)
            task = asyncio.create_task(self.pump_public_to_agent(sid, reader))
            self.streams[sid].pump_tasks.append(task)
        except Exception as e:
            log.warning("open stream failed: %s", e)
            await self.close_stream(sid)

    async def pump_public_to_agent(self, sid: int, reader: asyncio.StreamReader) -> None:
        try:
            while True:
                data = await reader.read(int(self.cfg.get("buffer_size", 65536)))
                if not data:
                    break
                if self.control_writer:
                    await send_frame(self.control_writer, T_DATA, sid, data)
        except Exception:
            pass
        finally:
            if self.control_writer:
                with contextlib.suppress(Exception):
                    await send_frame(self.control_writer, T_CLOSE, sid)
            await self.close_stream(sid, send_close=False)

    async def close_stream(self, sid: int, send_close: bool = False) -> None:
        st = self.streams.pop(sid, None)
        if not st:
            return
        for t in st.pump_tasks:
            t.cancel()
        with contextlib.suppress(Exception):
            st.writer.close(); await st.writer.wait_closed()
        if send_close and self.control_writer:
            with contextlib.suppress(Exception):
                await send_frame(self.control_writer, T_CLOSE, sid)

    async def close_all_streams(self) -> None:
        for sid in list(self.streams):
            await self.close_stream(sid)


class Agent:
    def __init__(self, cfg: Dict[str, Any]):
        self.cfg = cfg
        self.token = get_required(cfg, "token")
        self.agent_id = cfg.get("agent_id", "default")
        self.hub_host = get_required(cfg, "hub_host")
        self.hub_port = int(cfg.get("hub_port", 9443))
        self.streams: Dict[int, Stream] = {}
        self.control_writer: Optional[asyncio.StreamWriter] = None

    async def start(self) -> None:
        delay = 1
        while True:
            try:
                await self.connect_once()
                delay = 1
            except asyncio.CancelledError:
                raise
            except Exception as e:
                log.warning("agent disconnected: %s", e)
                await self.close_all_streams()
                await asyncio.sleep(delay)
                delay = min(delay * 2, int(self.cfg.get("max_reconnect_seconds", 30)))

    async def connect_once(self) -> None:
        ssl_ctx = make_client_ssl(self.cfg)
        server_name = self.cfg.get("server_name") or self.hub_host
        reader, writer = await asyncio.open_connection(self.hub_host, self.hub_port, ssl=ssl_ctx, server_hostname=server_name if not self.cfg.get("insecure_skip_verify", False) else None)
        tune_socket(writer)
        self.control_writer = writer
        writer.write(MAGIC)
        await writer.drain()
        await send_json_line(writer, {"role": "agent", "agent_id": self.agent_id, "version": VERSION})
        challenge = await read_json_line(reader)
        nonce = challenge["nonce"]
        await send_json_line(writer, {"hmac": hmac_hex(self.token, nonce.encode(), self.agent_id.encode())})
        ok = await read_json_line(reader)
        if ok.get("type") != "ok":
            raise ConnectionError("hub rejected authentication")
        log.info("connected to hub %s:%d", self.hub_host, self.hub_port)
        await self.control_loop(reader, writer)

    async def control_loop(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        while True:
            ftype, sid, payload = await read_frame(reader)
            if ftype == T_OPEN:
                meta = json.loads(payload.decode())
                await self.open_local(sid, meta["host"], int(meta["port"]))
            elif ftype == T_DATA:
                st = self.streams.get(sid)
                if st:
                    st.writer.write(payload)
                    await st.writer.drain()
            elif ftype == T_CLOSE:
                await self.close_stream(sid)
            elif ftype == T_PING:
                await send_frame(writer, T_PONG, 0, payload)
            elif ftype == T_PONG:
                pass

    async def open_local(self, sid: int, host: str, port: int) -> None:
        try:
            reader, writer = await asyncio.open_connection(host, port)
            tune_socket(writer)
            st = Stream(reader, writer, [])
            self.streams[sid] = st
            task = asyncio.create_task(self.pump_local_to_hub(sid, reader))
            st.pump_tasks.append(task)
        except Exception as e:
            if self.control_writer:
                await send_frame(self.control_writer, T_ERROR, sid, str(e).encode())
                await send_frame(self.control_writer, T_CLOSE, sid)

    async def pump_local_to_hub(self, sid: int, reader: asyncio.StreamReader) -> None:
        try:
            while True:
                data = await reader.read(int(self.cfg.get("buffer_size", 65536)))
                if not data:
                    break
                if self.control_writer:
                    await send_frame(self.control_writer, T_DATA, sid, data)
        except Exception:
            pass
        finally:
            if self.control_writer:
                with contextlib.suppress(Exception):
                    await send_frame(self.control_writer, T_CLOSE, sid)
            await self.close_stream(sid, send_close=False)

    async def close_stream(self, sid: int, send_close: bool = False) -> None:
        st = self.streams.pop(sid, None)
        if not st:
            return
        for t in st.pump_tasks:
            t.cancel()
        with contextlib.suppress(Exception):
            st.writer.close(); await st.writer.wait_closed()
        if send_close and self.control_writer:
            with contextlib.suppress(Exception):
                await send_frame(self.control_writer, T_CLOSE, sid)

    async def close_all_streams(self) -> None:
        for sid in list(self.streams):
            await self.close_stream(sid)


def setup_logging(level: str) -> None:
    logging.basicConfig(level=getattr(logging, level.upper(), logging.INFO), format="%(asctime)s %(levelname)s %(message)s")


def write_token() -> str:
    return secrets.token_urlsafe(48)


def main() -> int:
    p = argparse.ArgumentParser(description="IRON secure reverse TCP tunnel")
    p.add_argument("mode", choices=["hub", "agent", "token"])
    p.add_argument("-c", "--config", help="config json path")
    p.add_argument("--log-level", default=os.getenv("IRON_LOG_LEVEL", "INFO"))
    p.add_argument("--version", action="store_true")
    args = p.parse_args()
    if args.version:
        print(VERSION)
        return 0
    if args.mode == "token":
        print(write_token())
        return 0
    if not args.config:
        raise SystemExit("--config is required")
    setup_logging(args.log_level)
    cfg = load_json(args.config)
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    for sig in (signal.SIGINT, signal.SIGTERM):
        with contextlib.suppress(NotImplementedError):
            loop.add_signal_handler(sig, loop.stop)
    try:
        if args.mode == "hub":
            loop.run_until_complete(Hub(cfg).start())
        else:
            loop.run_until_complete(Agent(cfg).start())
    finally:
        loop.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
