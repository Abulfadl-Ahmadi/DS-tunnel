#!/usr/bin/env python3
from __future__ import annotations

import json
import logging
import socket
import struct
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

try:
    from scapy.all import IP, UDP, send
except ImportError as exc:  # pragma: no cover - runtime dependency check
    raise SystemExit("Scapy is required. Install dependencies with: pip install -r requirements.txt") from exc

logging.basicConfig(level=logging.INFO, format="%(asctime)s [OUT] %(message)s")
log = logging.getLogger(__name__)

# ========== CONFIGURATION ==========
CONFIG_PATH = Path(__file__).with_name("out_config.json")
DEFAULT_CONFIG = {
    "vps_in_ip": "1.2.3.4",
    "spoof_ip": "5.6.7.8",
    "udp_port": 10808,
    "control_port": 8888,
    "listen_host": "0.0.0.0",
    "udp_mtu": 1200,
    "resend_interval": 1.0,
    "keepalive_interval": 3.0,
    "keepalive_timeout": 10.0,
    "max_retries": 5,
    "target_connect_timeout": 10.0,
}


def load_config() -> dict[str, object]:
    config = dict(DEFAULT_CONFIG)
    if CONFIG_PATH.exists():
        try:
            loaded = json.loads(CONFIG_PATH.read_text(encoding="utf-8"))
            if isinstance(loaded, dict):
                config.update(loaded)
            else:
                log.warning("config file %s ignored because it is not a JSON object", CONFIG_PATH)
        except Exception as exc:
            log.warning("failed to load %s: %s", CONFIG_PATH, exc)
    else:
        log.info("config file %s not found, using built-in defaults", CONFIG_PATH)
    return config


CONFIG = load_config()
VPS_IN_IP = str(CONFIG["vps_in_ip"])
SPOOF_IP = str(CONFIG["spoof_ip"])
UDP_PORT = int(CONFIG["udp_port"])
CONTROL_PORT = int(CONFIG["control_port"])
LISTEN_HOST = str(CONFIG["listen_host"])
UDP_MTU = int(CONFIG["udp_mtu"])
RESEND_INTERVAL = float(CONFIG["resend_interval"])
KEEPALIVE_INTERVAL = float(CONFIG["keepalive_interval"])
KEEPALIVE_TIMEOUT = float(CONFIG["keepalive_timeout"])
MAX_RETRIES = int(CONFIG["max_retries"])
TARGET_CONNECT_TIMEOUT = float(CONFIG["target_connect_timeout"])

MAGIC = b"HTUN"
VERSION = 1
TYPE_HELLO = 1
TYPE_READY = 2
TYPE_DATA = 3
TYPE_PING = 4
TYPE_PONG = 5
TYPE_ACK = 6
TYPE_CLOSE = 7
TYPE_ERROR = 8
# ===================================

TCP_HEADER = struct.Struct("!4sBBII")
UDP_HEADER = struct.Struct("!4sIIBH")
MAX_UDP_PAYLOAD = UDP_MTU - 20 - 8 - UDP_HEADER.size


def validate_configuration() -> None:
    if VPS_IN_IP in {"1.2.3.4", "5.6.7.8"}:
        log.warning("VPS_IN_IP still has a placeholder value: %s", VPS_IN_IP)
    if SPOOF_IP in {"1.2.3.4", "5.6.7.8"}:
        log.warning("SPOOF_IP still has a placeholder value: %s", SPOOF_IP)
    log.info("Configured UDP MTU=%s, max payload=%s bytes", UDP_MTU, MAX_UDP_PAYLOAD)
    log.info("Raw UDP will be sent with spoofed source=%s to destination=%s:%s", SPOOF_IP, VPS_IN_IP, UDP_PORT)


def recv_exact(sock_obj: socket.socket, size: int) -> bytes:
    data = bytearray()
    while len(data) < size:
        chunk = sock_obj.recv(size - len(data))
        if not chunk:
            raise ConnectionError("socket closed while reading")
        data.extend(chunk)
    return bytes(data)


def recv_frame(sock_obj: socket.socket) -> tuple[int, int, bytes]:
    header = recv_exact(sock_obj, TCP_HEADER.size)
    magic, version, message_type, session_id, payload_len = TCP_HEADER.unpack(header)
    if magic != MAGIC:
        raise ValueError("invalid control frame magic")
    if version != VERSION:
        raise ValueError(f"unsupported protocol version {version}")
    payload = recv_exact(sock_obj, payload_len) if payload_len else b""
    return message_type, session_id, payload


def send_frame(sock_obj: socket.socket, message_type: int, session_id: int, payload: bytes = b"", lock: Optional[threading.Lock] = None) -> None:
    frame = TCP_HEADER.pack(MAGIC, VERSION, message_type, session_id, len(payload)) + payload
    if lock is None:
        sock_obj.sendall(frame)
        return
    with lock:
        sock_obj.sendall(frame)


def close_socket(sock_obj: socket.socket) -> None:
    try:
        sock_obj.shutdown(socket.SHUT_RDWR)
    except OSError:
        pass
    except Exception:
        pass
    try:
        sock_obj.close()
    except Exception:
        pass


@dataclass
class BufferedChunk:
    payload: bytes
    attempts: int = 1
    last_sent: float = field(default_factory=time.monotonic)


@dataclass
class SessionState:
    session_id: int
    control_sock: socket.socket
    target_sock: socket.socket
    client_addr: tuple[str, int]
    target_host: str
    target_port: int
    send_lock: threading.Lock = field(default_factory=threading.Lock)
    state_lock: threading.Lock = field(default_factory=threading.Lock)
    stop_event: threading.Event = field(default_factory=threading.Event)
    last_pong: float = field(default_factory=time.monotonic)
    acked_upto: int = -1
    next_seq: int = 0
    chunks_sent: int = 0
    bytes_to_target: int = 0
    bytes_to_in: int = 0
    acks_received: int = 0
    last_ack_seq: int = -1
    tx_chunk_payload_limit: int = MAX_UDP_PAYLOAD
    send_buffer: dict[int, BufferedChunk] = field(default_factory=dict)
    control_error: str = ""


sessions: dict[int, SessionState] = {}
sessions_lock = threading.Lock()
session_stats_lock = threading.Lock()
session_stats = {
    "accepted": 0,
    "last_close": "",
}


def emit_status_snapshot(reason: str) -> None:
    with sessions_lock:
        active = len(sessions)
    with session_stats_lock:
        accepted = session_stats["accepted"]
        last_close = session_stats["last_close"]
    if last_close:
        log.info(
            "status reason=%s active_sessions=%s accepted_sessions=%s last_close=%s",
            reason,
            active,
            accepted,
            last_close,
        )
        return
    log.info(
        "status reason=%s active_sessions=%s accepted_sessions=%s",
        reason,
        active,
        accepted,
    )


def register_session(session: SessionState) -> None:
    with sessions_lock:
        sessions[session.session_id] = session
    with session_stats_lock:
        session_stats["accepted"] += 1
    emit_status_snapshot("session_open")


def unregister_session(session_id: int) -> None:
    with sessions_lock:
        sessions.pop(session_id, None)


def close_session(session: SessionState, reason: str) -> None:
    with session.state_lock:
        if session.stop_event.is_set():
            return
        session.stop_event.set()
        session.control_error = reason
    unregister_session(session.session_id)
    with session_stats_lock:
        session_stats["last_close"] = reason
    log.info(
        "session=%s closing reason=%s bytes_to_target=%s bytes_to_in=%s chunks_sent=%s acked_upto=%s acks_received=%s last_ack_seq=%s pending_chunks=%s",
        session.session_id,
        reason,
        session.bytes_to_target,
        session.bytes_to_in,
        session.chunks_sent,
        session.acked_upto,
        session.acks_received,
        session.last_ack_seq,
        len(session.send_buffer),
    )
    close_socket(session.control_sock)
    close_socket(session.target_sock)
    emit_status_snapshot("session_close")


def send_udp_chunk(session: SessionState, seq_num: int, payload: bytes, flags: int = 0) -> None:
    packet = UDP_HEADER.pack(MAGIC, session.session_id, seq_num, flags, len(payload)) + payload
    ip_layer = IP(src=SPOOF_IP, dst=VPS_IN_IP)
    udp_layer = UDP(sport=UDP_PORT, dport=UDP_PORT)
    send(ip_layer / udp_layer / packet, verbose=False)


def send_chunk_with_tracking(session: SessionState, payload: bytes, flags: int = 0) -> None:
    with session.state_lock:
        if session.stop_event.is_set():
            return
        seq_num = session.next_seq
        session.next_seq += 1
        session.send_buffer[seq_num] = BufferedChunk(payload=payload)
        session.chunks_sent += 1
    send_udp_chunk(session, seq_num, payload, flags=flags)


def send_control_ready(session: SessionState, target_info: dict[str, object]) -> None:
    payload = json.dumps(target_info, separators=(",", ":")).encode("utf-8")
    send_frame(session.control_sock, TYPE_READY, session.session_id, payload, session.send_lock)


def send_control_error(session: SessionState, message: str) -> None:
    try:
        send_frame(session.control_sock, TYPE_ERROR, session.session_id, message.encode("utf-8", errors="replace"), session.send_lock)
    except Exception:
        pass


def handle_control_reader(session: SessionState) -> None:
    try:
        while not session.stop_event.is_set():
            message_type, message_session_id, payload = recv_frame(session.control_sock)
            if message_session_id != session.session_id:
                log.warning(
                    "session=%s received frame for mismatched session=%s type=%s",
                    session.session_id,
                    message_session_id,
                    message_type,
                )
                continue

            if message_type == TYPE_DATA:
                session.target_sock.sendall(payload)
                session.bytes_to_target += len(payload)
            elif message_type == TYPE_PING:
                send_frame(session.control_sock, TYPE_PONG, session.session_id, payload, session.send_lock)
            elif message_type == TYPE_PONG:
                session.last_pong = time.monotonic()
            elif message_type == TYPE_ACK:
                if len(payload) == 4:
                    ack_seq = struct.unpack("!I", payload)[0]
                    with session.state_lock:
                        session.acks_received += 1
                        session.last_ack_seq = ack_seq
                        if ack_seq > session.acked_upto:
                            for seq_num in list(session.send_buffer.keys()):
                                if seq_num <= ack_seq:
                                    session.send_buffer.pop(seq_num, None)
                            session.acked_upto = ack_seq
                    log.debug("session=%s acked upto seq=%s remaining=%s", session.session_id, ack_seq, len(session.send_buffer))
            elif message_type == TYPE_CLOSE:
                close_session(session, "peer closed session")
                return
            elif message_type == TYPE_ERROR:
                message = payload.decode("utf-8", errors="replace") if payload else "unknown error"
                close_session(session, f"peer error: {message}")
                return
            else:
                log.debug("session=%s ignored control type=%s payload=%s bytes", session.session_id, message_type, len(payload))
    except Exception as exc:
        if not session.stop_event.is_set():
            close_session(session, f"control reader failed: {exc}")


def handle_target_reader(session: SessionState) -> None:
    try:
        while not session.stop_event.is_set():
            data = session.target_sock.recv(8192)
            if not data:
                break
            chunk_limit = max(256, session.tx_chunk_payload_limit)
            for offset in range(0, len(data), chunk_limit):
                chunk = data[offset : offset + chunk_limit]
                send_chunk_with_tracking(session, chunk)
                session.bytes_to_in += len(chunk)
    except Exception as exc:
        if not session.stop_event.is_set():
            close_session(session, f"target read failed: {exc}")
    finally:
        if not session.stop_event.is_set():
            try:
                send_control_error(session, "target closed connection")
                send_frame(session.control_sock, TYPE_CLOSE, session.session_id, b"target closed", session.send_lock)
            except Exception:
                pass
            close_session(session, "target closed connection")


def handle_retransmissions(session: SessionState) -> None:
    while not session.stop_event.is_set():
        time.sleep(0.25)
        if session.stop_event.is_set():
            break

        now = time.monotonic()
        resend_list: list[tuple[int, BufferedChunk]] = []
        with session.state_lock:
            for seq_num, buffered in list(session.send_buffer.items()):
                if seq_num <= session.acked_upto:
                    session.send_buffer.pop(seq_num, None)
                    continue
                if now - buffered.last_sent >= RESEND_INTERVAL:
                    resend_list.append((seq_num, buffered))

        for seq_num, buffered in resend_list:
            if session.stop_event.is_set():
                break
            with session.state_lock:
                current = session.send_buffer.get(seq_num)
                if current is None:
                    continue
                current.attempts += 1
                current.last_sent = time.monotonic()
                attempts = current.attempts
            if attempts > MAX_RETRIES:
                close_session(session, f"retransmit limit reached for seq {seq_num}")
                break
            try:
                send_udp_chunk(session, seq_num, buffered.payload)
                log.debug("session=%s resent seq=%s attempt=%s", session.session_id, seq_num, attempts)
            except Exception as exc:
                close_session(session, f"UDP send failed: {exc}")
                break


def handle_keepalive(session: SessionState) -> None:
    while not session.stop_event.is_set():
        time.sleep(KEEPALIVE_INTERVAL)
        if session.stop_event.is_set():
            break
        try:
            send_frame(session.control_sock, TYPE_PING, session.session_id, struct.pack("!d", time.time()), session.send_lock)
        except Exception as exc:
            close_session(session, f"keepalive send failed: {exc}")
            break
        if time.monotonic() - session.last_pong > KEEPALIVE_TIMEOUT:
            close_session(session, "keepalive timeout")
            break


def log_status_loop() -> None:
    while True:
        time.sleep(15.0)
        with sessions_lock:
            snapshot = list(sessions.values())
        with session_stats_lock:
            accepted = session_stats["accepted"]
            last_close = session_stats["last_close"]
        if not snapshot:
            if last_close:
                log.info("status active_sessions=0 accepted_sessions=%s last_close=%s", accepted, last_close)
            else:
                log.info(
                    "status active_sessions=0 accepted_sessions=%s waiting_for_in_connection=1",
                    accepted,
                )
            continue
        total_chunks = sum(session.chunks_sent for session in snapshot)
        total_to_target = sum(session.bytes_to_target for session in snapshot)
        total_to_in = sum(session.bytes_to_in for session in snapshot)
        sessions_waiting_ack = sum(1 for session in snapshot if session.chunks_sent > 0 and session.acks_received == 0)
        pending_chunks = sum(len(session.send_buffer) for session in snapshot)
        log.info(
            "status active_sessions=%s accepted_sessions=%s total_chunks=%s bytes_to_target=%s bytes_to_in=%s sessions_waiting_ack=%s pending_chunks=%s",
            len(snapshot),
            accepted,
            total_chunks,
            total_to_target,
            total_to_in,
            sessions_waiting_ack,
            pending_chunks,
        )


def handle_control_conn(control_sock: socket.socket, client_addr: tuple[str, int]) -> None:
    session: Optional[SessionState] = None
    target_sock: Optional[socket.socket] = None
    try:
        control_sock.settimeout(TARGET_CONNECT_TIMEOUT)
        message_type, session_id, payload = recv_frame(control_sock)
        if message_type != TYPE_HELLO:
            raise ValueError(f"expected HELLO frame, got type {message_type}")

        hello = json.loads(payload.decode("utf-8"))
        target_host = str(hello["target_host"])
        target_port = int(hello["target_port"])
        in_advertised_mtu = int(hello.get("udp_mtu", UDP_MTU))
        in_advertised_max_payload = int(hello.get("max_udp_payload", MAX_UDP_PAYLOAD))
        negotiated_payload = min(MAX_UDP_PAYLOAD, in_advertised_max_payload)
        if negotiated_payload < 256:
            raise ValueError(
                f"invalid negotiated payload size {negotiated_payload} (in_advertised_max_payload={in_advertised_max_payload})"
            )
        log.info("session=%s client=%s target=%s:%s", session_id, client_addr, target_host, target_port)
        if in_advertised_mtu != UDP_MTU:
            log.warning(
                "session=%s MTU mismatch IN=%s OUT=%s negotiated_payload=%s",
                session_id,
                in_advertised_mtu,
                UDP_MTU,
                negotiated_payload,
            )

        target_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        target_sock.settimeout(TARGET_CONNECT_TIMEOUT)
        target_sock.connect((target_host, target_port))
        target_sock.settimeout(None)

        session = SessionState(
            session_id=session_id,
            control_sock=control_sock,
            target_sock=target_sock,
            client_addr=client_addr,
            target_host=target_host,
            target_port=target_port,
            tx_chunk_payload_limit=negotiated_payload,
        )
        register_session(session)

        send_control_ready(
            session,
            {
                "status": "ready",
                "target_host": target_host,
                "target_port": target_port,
                "udp_mtu": UDP_MTU,
                "max_udp_payload": MAX_UDP_PAYLOAD,
                "negotiated_payload": negotiated_payload,
                "spoof_ip": SPOOF_IP,
            },
        )
        control_sock.settimeout(None)

        threading.Thread(target=handle_control_reader, args=(session,), daemon=True).start()
        threading.Thread(target=handle_target_reader, args=(session,), daemon=True).start()
        threading.Thread(target=handle_retransmissions, args=(session,), daemon=True).start()
        threading.Thread(target=handle_keepalive, args=(session,), daemon=True).start()

        while not session.stop_event.is_set():
            time.sleep(0.2)
    except Exception as exc:
        log.error("control connection from %s failed: %s", client_addr, exc)
        if session is not None:
            send_control_error(session, str(exc))
            close_session(session, str(exc))
        else:
            close_socket(control_sock)
            if target_sock is not None:
                close_socket(target_sock)
    finally:
        if session is not None and not session.stop_event.is_set():
            close_session(session, "session finished")
        else:
            close_socket(control_sock)
            if target_sock is not None:
                close_socket(target_sock)


def main() -> None:
    validate_configuration()
    threading.Thread(target=log_status_loop, daemon=True).start()

    listen_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listen_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listen_sock.bind((LISTEN_HOST, CONTROL_PORT))
    listen_sock.listen(64)
    log.info("listening for control TCP on %s:%s", LISTEN_HOST, CONTROL_PORT)

    while True:
        control_sock, addr = listen_sock.accept()
        threading.Thread(target=handle_control_conn, args=(control_sock, addr), daemon=True).start()


if __name__ == "__main__":
    main()