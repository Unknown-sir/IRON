#!/usr/bin/env python3
"""
IRON - Secure Reverse TCP Tunnel
Hub runs on the public/IR server. Agent runs near the real services/EU server.
Standard-library only: asyncio + ssl + hmac.

v1.2.x focuses on load stability:
- serialized control-channel writes, preventing frame corruption under concurrency
- heartbeat watchdog that force-closes stuck control sockets
- per-stream outbound queues so one slow stream cannot block the whole tunnel
- stream limits, open/connect timeouts, drain timeouts, and safer cleanup
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
from dataclasses import dataclass, field
from typing import Any, Dict, Optional, Tuple

VERSION = "1.2.0"
MAGIC = b"IRON/1\n"
MAX_FRAME = 16 * 1024 * 1024
HDR = struct.Struct("!BII")  # type, stream id, payload length

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
    pump_tasks: list[asyncio.Task] = field(default_factory=list)
    out_q: Optional[asyncio.Queue] = None
    closing: bool = False


def load_json(path: str) -> Dict[str, Any]:
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def get_required(cfg: Dict[str, Any], key: str) -> Any:
    if key not in cfg:
        raise SystemExit(f"missing required config key: {key}")
    return cfg[key]


def hmac_hex(token: str, *parts: bytes) -> str:
    return hmac.new(token.encode(), b"|".join(parts), hashlib.sha256).hexdigest()


async def send_json_line(writer: asyncio.StreamWriter, obj: Dict[str, Any]) -> None:
    writer.write(json.dumps(obj, separators=(",", ":")).encode() + b"\n")
    await writer.drain()


async def read_json_line(reader: asyncio.StreamReader, limit: int = 65536) -> Dict[str, Any]:
    raw = await reader.readline()
    if not raw or len(raw) > limit:
        raise ConnectionError("invalid or oversized handshake line")
    return json.loads(raw.decode())


async def send_frame(writer: asyncio.StreamWriter, ftype: int, sid: int, payload: bytes = b"") -> None:
    if len(payload) > MAX_FRAME:
        raise ValueError("frame too large")
    writer.write(HDR.pack(ftype, sid, len(payload)) + payload)
    await writer.drain()


async def read_frame(reader: asyncio.StreamReader) -> Tuple[int, int, bytes]:
    hdr = await reader.readexactly(HDR.size)
    ftype, sid, length = HDR.unpack(hdr)
    if length > MAX_FRAME:
        raise ConnectionError("frame too large")
    payload = await reader.readexactly(length) if length else b""
    return ftype, sid, payload


def tune_socket(writer: asyncio.StreamWriter, cfg: Optional[Dict[str, Any]] = None) -> None:
    sock = writer.get_extra_info("socket")
    if not sock:
        return
    with contextlib.suppress(Exception):
        sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
    with contextlib.suppress(Exception):
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
    with contextlib.suppress(Exception):
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, int((cfg or {}).get("socket_send_buffer", 4 * 1024 * 1024)))
    with contextlib.suppress(Exception):
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, int((cfg or {}).get("socket_recv_buffer", 4 * 1024 * 1024)))


def make_server_ssl(cfg: Dict[str, Any]) -> ssl.SSLContext:
    ctx = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    ctx.load_cert_chain(get_required(cfg, "certfile"), get_required(cfg, "keyfile"))
    ca = cfg.get("client_ca")
    if ca:
        ctx.load_verify_locations(cafile=ca)
        ctx.verify_mode = ssl.CERT_REQUIRED
    return ctx


def make_client_ssl(cfg: Dict[str, Any]) -> ssl.SSLContext:
    if cfg.get("insecure_skip_verify", False):
        ctx = ssl._create_unverified_context()
    else:
        ctx = ssl.create_default_context(ssl.Purpose.SERVER_AUTH, cafile=cfg.get("ca_file"))
        ctx.check_hostname = bool(cfg.get("server_name"))
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    if cfg.get("certfile") and cfg.get("keyfile"):
        ctx.load_cert_chain(cfg["certfile"], cfg["keyfile"])
    return ctx


def cfg_int(cfg: Dict[str, Any], key: str, default: int) -> int:
    return int(cfg.get(key, default))


class BasePeer:
    def __init__(self, cfg: Dict[str, Any]):
        self.cfg = cfg
        self.streams: Dict[int, Stream] = {}
        self.control_writer: Optional[asyncio.StreamWriter] = None
        self.control_lock = asyncio.Lock()
        self.last_pong = time.monotonic()
        self.buffer_size = cfg_int(cfg, "buffer_size", 65536)
        self.send_timeout = cfg_int(cfg, "send_timeout_seconds", 15)
        self.local_drain_timeout = cfg_int(cfg, "local_drain_timeout_seconds", 20)
        self.stream_queue_size = cfg_int(cfg, "stream_queue_size", 256)
        self.max_streams = cfg_int(cfg, "max_streams", 4096)

    async def send_control(self, ftype: int, sid: int, payload: bytes = b"") -> None:
        writer = self.control_writer
        if writer is None or writer.is_closing():
            raise ConnectionError("control channel is not connected")
        async with self.control_lock:
            if self.control_writer is not writer or writer.is_closing():
                raise ConnectionError("control channel changed/closed")
            await asyncio.wait_for(send_frame(writer, ftype, sid, payload), timeout=self.send_timeout)

    async def force_close_control(self) -> None:
        writer = self.control_writer
        if writer:
            with contextlib.suppress(Exception):
                writer.close()
            with contextlib.suppress(Exception):
                await writer.wait_closed()

    async def heartbeat(self, writer: asyncio.StreamWriter) -> None:
        interval = cfg_int(self.cfg, "heartbeat_seconds", 10)
        timeout = cfg_int(self.cfg, "heartbeat_timeout_seconds", max(30, interval * 3))
        while True:
            await asyncio.sleep(interval)
            if time.monotonic() - self.last_pong > timeout:
                raise ConnectionError("heartbeat timeout")
            await self.send_control(T_PING, 0, str(int(time.time())).encode())

    async def writer_loop(self, sid: int, st: Stream, label: str) -> None:
        assert st.out_q is not None
        try:
            while True:
                data = await st.out_q.get()
                if data is None:
                    break
                st.writer.write(data)
                await asyncio.wait_for(st.writer.drain(), timeout=self.local_drain_timeout)
        except Exception as e:
            log.debug("%s writer loop sid=%s closed: %s", label, sid, e)
        finally:
            await self.close_stream(sid, send_close=True)

    async def enqueue_to_stream(self, sid: int, payload: bytes, label: str) -> None:
        st = self.streams.get(sid)
        if not st or not st.out_q:
            return
        try:
            await asyncio.wait_for(st.out_q.put(payload), timeout=self.local_drain_timeout)
        except Exception as e:
            log.warning("%s stream queue blocked sid=%s: %s", label, sid, e)
            await self.close_stream(sid, send_close=True)

    async def close_stream(self, sid: int, send_close: bool = False) -> None:
        st = self.streams.pop(sid, None)
        if not st or st.closing:
            return
        st.closing = True
        if st.out_q:
            with contextlib.suppress(Exception):
                st.out_q.put_nowait(None)
        for t in list(st.pump_tasks):
            if t is not asyncio.current_task():
                t.cancel()
        with contextlib.suppress(Exception):
            st.writer.close()
            await st.writer.wait_closed()
        if send_close:
            with contextlib.suppress(Exception):
                await self.send_control(T_CLOSE, sid)

    async def close_all_streams(self) -> None:
        for sid in list(self.streams):
            await self.close_stream(sid)


class Hub(BasePeer):
    def __init__(self, cfg: Dict[str, Any]):
        super().__init__(cfg)
        self.token = get_required(cfg, "token")
        self.control_host = cfg.get("control_host", "0.0.0.0")
        self.control_port = cfg_int(cfg, "control_port", 9443)
        self.agent_id = cfg.get("agent_id", "default")
        self.next_sid = 10
        self.public_servers: list[asyncio.AbstractServer] = []
        self.stop_event = asyncio.Event()

    async def start(self) -> None:
        ssl_ctx = make_server_ssl(self.cfg)
        srv = await asyncio.start_server(
            self.handle_agent,
            self.control_host,
            self.control_port,
            ssl=ssl_ctx,
            backlog=cfg_int(self.cfg, "listen_backlog", 4096),
        )
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
            server = await asyncio.start_server(
                lambda r, w, m=item: self.handle_public(r, w, m),
                listen_host,
                listen_port,
                backlog=cfg_int(self.cfg, "listen_backlog", 4096),
            )
            self.public_servers.append(server)
            dest = f"{item.get('target_host', '127.0.0.1')}:{item.get('target_port', listen_port)}"
            log.info("public listener %s:%d -> agent %s", listen_host, listen_port, dest)

    async def handle_agent(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        peer = writer.get_extra_info("peername")
        tune_socket(writer, self.cfg)
        try:
            if await reader.readexactly(len(MAGIC)) != MAGIC:
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
            if self.control_writer:
                log.warning("replacing existing agent connection")
                await self.force_close_control()
            self.control_writer = writer
            self.last_pong = time.monotonic()
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
                    await self.enqueue_to_stream(sid, payload, "hub")
                elif ftype == T_CLOSE:
                    await self.close_stream(sid)
                elif ftype == T_PING:
                    await self.send_control(T_PONG, 0, payload)
                elif ftype == T_PONG:
                    self.last_pong = time.monotonic()
                elif ftype == T_ERROR:
                    log.warning("agent error sid=%s: %s", sid, payload.decode(errors="replace"))
                    await self.close_stream(sid)
                elif ftype == T_INFO:
                    log.info("agent info: %s", payload.decode(errors="replace"))
        finally:
            heartbeat.cancel()
            with contextlib.suppress(Exception):
                await heartbeat

    async def handle_public(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter, mapping: Dict[str, Any]) -> None:
        tune_socket(writer, self.cfg)
        if not self.control_writer:
            writer.close(); await writer.wait_closed(); return
        if len(self.streams) >= self.max_streams:
            log.warning("max streams reached; rejecting public connection")
            writer.close(); await writer.wait_closed(); return
        sid = self.next_sid
        self.next_sid = 10 if self.next_sid >= 0x7FFFFFF0 else self.next_sid + 1
        target_host = mapping.get("target_host", "127.0.0.1")
        target_port = int(mapping.get("target_port", mapping["listen_port"]))
        st = Stream(reader, writer, out_q=asyncio.Queue(maxsize=self.stream_queue_size))
        self.streams[sid] = st
        st.pump_tasks.append(asyncio.create_task(self.writer_loop(sid, st, "hub-public")))
        payload = json.dumps({"host": target_host, "port": target_port}, separators=(",", ":")).encode()
        try:
            await self.send_control(T_OPEN, sid, payload)
            st.pump_tasks.append(asyncio.create_task(self.pump_public_to_agent(sid, reader)))
        except Exception as e:
            log.warning("open stream failed sid=%s: %s", sid, e)
            await self.close_stream(sid)

    async def pump_public_to_agent(self, sid: int, reader: asyncio.StreamReader) -> None:
        try:
            while True:
                data = await reader.read(self.buffer_size)
                if not data:
                    break
                await self.send_control(T_DATA, sid, data)
        except Exception as e:
            log.debug("public->agent pump closed sid=%s: %s", sid, e)
        finally:
            await self.close_stream(sid, send_close=True)


class Agent(BasePeer):
    def __init__(self, cfg: Dict[str, Any]):
        super().__init__(cfg)
        self.token = get_required(cfg, "token")
        self.agent_id = cfg.get("agent_id", "default")
        self.hub_host = get_required(cfg, "hub_host")
        self.hub_port = cfg_int(cfg, "hub_port", 9443)

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
                await self.force_close_control()
                await self.close_all_streams()
                await asyncio.sleep(delay)
                delay = min(delay * 2, cfg_int(self.cfg, "max_reconnect_seconds", 30))

    async def connect_once(self) -> None:
        ssl_ctx = make_client_ssl(self.cfg)
        server_name = self.cfg.get("server_name") or self.hub_host
        connect_timeout = cfg_int(self.cfg, "connect_timeout_seconds", 15)
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(
                self.hub_host,
                self.hub_port,
                ssl=ssl_ctx,
                server_hostname=server_name if not self.cfg.get("insecure_skip_verify", False) else None,
            ),
            timeout=connect_timeout,
        )
        tune_socket(writer, self.cfg)
        self.control_writer = writer
        self.last_pong = time.monotonic()
        try:
            writer.write(MAGIC)
            await writer.drain()
            await send_json_line(writer, {"role": "agent", "agent_id": self.agent_id, "version": VERSION})
            challenge = await asyncio.wait_for(read_json_line(reader), timeout=connect_timeout)
            nonce = challenge["nonce"]
            await send_json_line(writer, {"hmac": hmac_hex(self.token, nonce.encode(), self.agent_id.encode())})
            ok = await asyncio.wait_for(read_json_line(reader), timeout=connect_timeout)
            if ok.get("type") != "ok":
                raise ConnectionError("hub rejected authentication")
            log.info("connected to hub %s:%d", self.hub_host, self.hub_port)
            await self.control_loop(reader, writer)
        finally:
            if self.control_writer is writer:
                self.control_writer = None
            with contextlib.suppress(Exception):
                writer.close(); await writer.wait_closed()

    async def control_loop(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        heartbeat = asyncio.create_task(self.heartbeat(writer))
        try:
            while True:
                ftype, sid, payload = await read_frame(reader)
                if ftype == T_OPEN:
                    meta = json.loads(payload.decode())
                    await self.open_local(sid, meta["host"], int(meta["port"]))
                elif ftype == T_DATA:
                    await self.enqueue_to_stream(sid, payload, "agent")
                elif ftype == T_CLOSE:
                    await self.close_stream(sid)
                elif ftype == T_PING:
                    await self.send_control(T_PONG, 0, payload)
                elif ftype == T_PONG:
                    self.last_pong = time.monotonic()
        finally:
            heartbeat.cancel()
            with contextlib.suppress(Exception):
                await heartbeat

    async def open_local(self, sid: int, host: str, port: int) -> None:
        if len(self.streams) >= self.max_streams:
            await self.send_control(T_ERROR, sid, b"agent max_streams reached")
            await self.send_control(T_CLOSE, sid)
            return
        try:
            timeout = cfg_int(self.cfg, "local_connect_timeout_seconds", 10)
            reader, writer = await asyncio.wait_for(asyncio.open_connection(host, port), timeout=timeout)
            tune_socket(writer, self.cfg)
            st = Stream(reader, writer, out_q=asyncio.Queue(maxsize=self.stream_queue_size))
            self.streams[sid] = st
            st.pump_tasks.append(asyncio.create_task(self.writer_loop(sid, st, "agent-local")))
            st.pump_tasks.append(asyncio.create_task(self.pump_local_to_hub(sid, reader)))
        except Exception as e:
            with contextlib.suppress(Exception):
                await self.send_control(T_ERROR, sid, str(e).encode())
                await self.send_control(T_CLOSE, sid)

    async def pump_local_to_hub(self, sid: int, reader: asyncio.StreamReader) -> None:
        try:
            while True:
                data = await reader.read(self.buffer_size)
                if not data:
                    break
                await self.send_control(T_DATA, sid, data)
        except Exception as e:
            log.debug("local->hub pump closed sid=%s: %s", sid, e)
        finally:
            await self.close_stream(sid, send_close=True)


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
