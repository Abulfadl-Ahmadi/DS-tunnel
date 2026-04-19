#!/usr/bin/env python3
from __future__ import annotations

import json
import logging
from logging.handlers import RotatingFileHandler
import socket
import struct
import subprocess
import shutil
import atexit
import threading
import time
import os
from dotenv import load_dotenv
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
    "retransmit_scan_interval": 0.05,
    "max_resends_per_tick": 64,
    "resend_backoff_factor": 1.4,
    "max_pending_chunks": 8192,
    "target_recv_size": 65536,
    "socket_buffer_bytes": 1048576,
    "udp_plain_fallback_enabled": True,
    "log_file": "log_out_runtime.log",
    "log_level": "INFO",
    "log_max_bytes": 20971520,
    "log_backup_count": 5,
    "session_close_grace": 0.8,
    "keepalive_interval": 3.0,
    "keepalive_timeout": 10.0,
    "max_retries": 5,
    "target_connect_timeout": 10.0,
    "go_downstream_sender_enabled": True,
    "go_sender_project_dir": "spoof-tunnel",
    "go_sender_build_dir": ".go-bin",
    "go_sender_binary_name": "downstream-sender",
    "go_sender_send_only": True,
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
    
    # Override IPs from environment variables
    env_file = Path(__file__).parent / ".env"
    if env_file.exists():
        load_dotenv(env_file)
    
    config["vps_in_ip"] = os.getenv("VPS_IN_IP", config.get("vps_in_ip", "1.2.3.4"))
    config["spoof_ip"] = os.getenv("SPOOF_IP", config.get("spoof_ip", "5.6.7.8"))
    
    return config
    
    return config


def parse_bool(value: object, default: bool) -> bool:
    if isinstance(value, bool):
        return value
    if isinstance(value, (int, float)):
        return value != 0
    if isinstance(value, str):
        return value.strip().lower() in {"1", "true", "yes", "on"}
    if value is None:
        return default
    return bool(value)


def configure_logging(config: dict[str, object]) -> Path:
    log_level_name = str(config.get("log_level", "INFO")).upper()
    log_level = getattr(logging, log_level_name, logging.INFO)
    log_file_raw = str(config.get("log_file", "log_out_runtime.log"))
    log_file = Path(log_file_raw)
    if not log_file.is_absolute():
        log_file = Path(__file__).with_name(log_file_raw)

    log_max_bytes = int(config.get("log_max_bytes", 20 * 1024 * 1024))
    log_backup_count = int(config.get("log_backup_count", 5))
    formatter = logging.Formatter("%(asctime)s [OUT] %(message)s")

    handlers: list[logging.Handler] = []
    stream_handler = logging.StreamHandler()
    stream_handler.setFormatter(formatter)
    handlers.append(stream_handler)

    try:
        file_handler = RotatingFileHandler(
            log_file,
            maxBytes=log_max_bytes,
            backupCount=log_backup_count,
            encoding="utf-8",
        )
        file_handler.setFormatter(formatter)
        handlers.append(file_handler)
    except Exception as exc:
        logging.getLogger(__name__).warning("failed to initialize file logging at %s: %s", log_file, exc)

    logging.basicConfig(level=log_level, handlers=handlers, force=True)
    return log_file


CONFIG = load_config()
LOG_FILE_PATH = configure_logging(CONFIG)
log = logging.getLogger(__name__)
VPS_IN_IP = str(CONFIG["vps_in_ip"])
SPOOF_IP = str(CONFIG["spoof_ip"])
UDP_PORT = int(CONFIG["udp_port"])
CONTROL_PORT = int(CONFIG["control_port"])
LISTEN_HOST = str(CONFIG["listen_host"])
UDP_MTU = int(CONFIG["udp_mtu"])
RESEND_INTERVAL = float(CONFIG["resend_interval"])
RETRANSMIT_SCAN_INTERVAL = float(CONFIG["retransmit_scan_interval"])
MAX_RESENDS_PER_TICK = int(CONFIG["max_resends_per_tick"])
RESEND_BACKOFF_FACTOR = float(CONFIG["resend_backoff_factor"])
MAX_PENDING_CHUNKS = int(CONFIG["max_pending_chunks"])
TARGET_RECV_SIZE = int(CONFIG["target_recv_size"])
SOCKET_BUFFER_BYTES = int(CONFIG["socket_buffer_bytes"])
UDP_PLAIN_FALLBACK_ENABLED = parse_bool(CONFIG.get("udp_plain_fallback_enabled", True), True)
SESSION_CLOSE_GRACE = float(CONFIG["session_close_grace"])
KEEPALIVE_INTERVAL = float(CONFIG["keepalive_interval"])
KEEPALIVE_TIMEOUT = float(CONFIG["keepalive_timeout"])
MAX_RETRIES = int(CONFIG["max_retries"])
TARGET_CONNECT_TIMEOUT = float(CONFIG["target_connect_timeout"])
GO_DOWNSTREAM_SENDER_ENABLED = parse_bool(CONFIG.get("go_downstream_sender_enabled", True), True)
GO_SENDER_PROJECT_DIR = str(CONFIG.get("go_sender_project_dir", "spoof-tunnel"))
GO_SENDER_BUILD_DIR = str(CONFIG.get("go_sender_build_dir", ".go-bin"))
GO_SENDER_BINARY_NAME = str(CONFIG.get("go_sender_binary_name", "downstream-sender"))
GO_SENDER_SEND_ONLY = parse_bool(CONFIG.get("go_sender_send_only", True), True)

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
ACK_SACK_WINDOW = 64
ACK_SACK_FORMAT = struct.Struct("!IQ")
MAX_UDP_PAYLOAD = UDP_MTU - 20 - 8 - UDP_HEADER.size


def validate_configuration() -> None:
    if VPS_IN_IP in {"1.2.3.4", "5.6.7.8"}:
        log.warning("VPS_IN_IP still has a placeholder value: %s", VPS_IN_IP)
    if SPOOF_IP in {"1.2.3.4", "5.6.7.8"}:
        log.warning("SPOOF_IP still has a placeholder value: %s", SPOOF_IP)
    log.info("Configured UDP MTU=%s, max payload=%s bytes", UDP_MTU, MAX_UDP_PAYLOAD)
    log.info("Raw UDP will be sent with spoofed source=%s to destination=%s:%s", SPOOF_IP, VPS_IN_IP, UDP_PORT)
    log.info(
        "Retransmit scan=%ss max_resends_per_tick=%s max_pending_chunks=%s recv_size=%s socket_buffer=%s close_grace=%s udp_plain_fallback=%s",
        RETRANSMIT_SCAN_INTERVAL,
        MAX_RESENDS_PER_TICK,
        MAX_PENDING_CHUNKS,
        TARGET_RECV_SIZE,
        SOCKET_BUFFER_BYTES,
        SESSION_CLOSE_GRACE,
        UDP_PLAIN_FALLBACK_ENABLED,
    )
    log.info("Runtime logs are being written to %s", LOG_FILE_PATH)


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


def tune_tcp_socket(sock_obj: socket.socket) -> None:
    try:
        sock_obj.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
    except OSError:
        pass
    try:
        sock_obj.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, SOCKET_BUFFER_BYTES)
    except OSError:
        pass
    try:
        sock_obj.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, SOCKET_BUFFER_BYTES)
    except OSError:
        pass


_udp_plain_sock_lock = threading.Lock()
_udp_plain_sock: Optional[socket.socket] = None


class GoDownstreamSender:
    def __init__(self, process: subprocess.Popen[bytes], binary_path: Path) -> None:
        self.process = process
        self.binary_path = binary_path
        self._lock = threading.Lock()

    def send(self, payload: bytes) -> None:
        if self.process.stdin is None:
            raise RuntimeError("go sender stdin is unavailable")
        frame = struct.pack("!I", len(payload)) + payload
        with self._lock:
            if self.process.poll() is not None:
                raise RuntimeError(f"go sender exited with code {self.process.returncode}")
            self.process.stdin.write(frame)
            self.process.stdin.flush()

    def close(self) -> None:
        with self._lock:
            proc = self.process
            if proc.stdin is not None:
                try:
                    proc.stdin.close()
                except Exception:
                    pass
            if proc.poll() is None:
                proc.terminate()
                try:
                    proc.wait(timeout=1.0)
                except Exception:
                    proc.kill()


go_sender_lock = threading.Lock()
go_sender: Optional[GoDownstreamSender] = None


def build_go_sender_binary() -> Optional[Path]:
    if not GO_DOWNSTREAM_SENDER_ENABLED:
        return None
    go_cmd = shutil.which("go")
    if go_cmd is None:
        log.warning("go is not installed; downstream sender disabled, using Python send path")
        return None

    project_dir = Path(__file__).parent / GO_SENDER_PROJECT_DIR
    sender_cmd_dir = project_dir / "cmd" / "downstream-sender"
    if not sender_cmd_dir.exists():
        log.warning("go sender source not found at %s; using Python send path", sender_cmd_dir)
        return None

    build_dir = Path(__file__).parent / GO_SENDER_BUILD_DIR
    build_dir.mkdir(parents=True, exist_ok=True)
    binary_path = build_dir / GO_SENDER_BINARY_NAME

    build_cmd = [
        go_cmd,
        "build",
        "-o",
        str(binary_path),
        "./cmd/downstream-sender",
    ]

    try:
        completed = subprocess.run(
            build_cmd,
            cwd=project_dir,
            check=True,
            capture_output=True,
            text=True,
        )
        if completed.stderr.strip():
            log.debug("go build stderr: %s", completed.stderr.strip())
    except Exception as exc:
        log.warning("failed to build go downstream sender (%s); using Python send path", exc)
        return None

    return binary_path


def init_go_sender() -> None:
    global go_sender
    if not GO_DOWNSTREAM_SENDER_ENABLED:
        return

    binary_path = build_go_sender_binary()
    if binary_path is None:
        return

    command = [
        str(binary_path),
        "-source-ip",
        SPOOF_IP,
        "-dest-ip",
        VPS_IN_IP,
        "-dest-port",
        str(UDP_PORT),
        "-listen-port",
        str(UDP_PORT),
        "-buffer-size",
        str(SOCKET_BUFFER_BYTES),
    ]

    try:
        proc: subprocess.Popen[bytes] = subprocess.Popen(
            command,
            stdin=subprocess.PIPE,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            cwd=binary_path.parent,
        )
        go_sender = GoDownstreamSender(proc, binary_path)
        log.info("go downstream sender enabled: %s", binary_path)
    except Exception as exc:
        log.warning("failed to start go downstream sender (%s); using Python send path", exc)
        go_sender = None


def disable_go_sender(reason: str) -> None:
    global go_sender
    with go_sender_lock:
        if go_sender is None:
            return
        log.warning("disabling go downstream sender: %s", reason)
        go_sender.close()
        go_sender = None


atexit.register(lambda: disable_go_sender("process exit"))


def get_udp_plain_sock() -> socket.socket:
    global _udp_plain_sock
    with _udp_plain_sock_lock:
        if _udp_plain_sock is not None:
            return _udp_plain_sock
        sock_obj = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            sock_obj.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, SOCKET_BUFFER_BYTES)
        except OSError:
            pass
        _udp_plain_sock = sock_obj
        return sock_obj


@dataclass
class BufferedChunk:
    payload: bytes
    attempts: int = 1
    last_sent: float = field(default_factory=time.monotonic)
    retry_interval: float = RESEND_INTERVAL
    next_retry_at: float = field(default_factory=lambda: time.monotonic() + RESEND_INTERVAL)


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
    first_chunk_sent_at: Optional[float] = None
    first_ack_received_at: Optional[float] = None
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


def first_ack_latency_ms(session: SessionState) -> Optional[int]:
    if session.first_chunk_sent_at is None or session.first_ack_received_at is None:
        return None
    latency = int((session.first_ack_received_at - session.first_chunk_sent_at) * 1000)
    return max(latency, 0)


def close_session(session: SessionState, reason: str) -> None:
    with session.state_lock:
        if session.stop_event.is_set():
            return
        session.stop_event.set()
        session.control_error = reason
    unregister_session(session.session_id)
    with session_stats_lock:
        session_stats["last_close"] = reason
    ack_latency = first_ack_latency_ms(session)
    log.info(
        "session=%s closing reason=%s bytes_to_target=%s bytes_to_in=%s chunks_sent=%s acked_upto=%s acks_received=%s last_ack_seq=%s pending_chunks=%s first_ack_latency_ms=%s",
        session.session_id,
        reason,
        session.bytes_to_target,
        session.bytes_to_in,
        session.chunks_sent,
        session.acked_upto,
        session.acks_received,
        session.last_ack_seq,
        len(session.send_buffer),
        ack_latency,
    )
    close_socket(session.control_sock)
    close_socket(session.target_sock)
    emit_status_snapshot("session_close")


def send_udp_chunk(session: SessionState, seq_num: int, payload: bytes, flags: int = 0) -> None:
    packet = UDP_HEADER.pack(MAGIC, session.session_id, seq_num, flags, len(payload)) + payload
    if GO_SENDER_SEND_ONLY:
        with go_sender_lock:
            active_sender = go_sender
        if active_sender is not None:
            try:
                active_sender.send(packet)
                return
            except Exception as exc:
                disable_go_sender(f"go sender send failed: {exc}")

    sent_any = False
    spoof_error: Optional[Exception] = None

    try:
        ip_layer = IP(src=SPOOF_IP, dst=VPS_IN_IP)
        udp_layer = UDP(sport=UDP_PORT, dport=UDP_PORT)
        send(ip_layer / udp_layer / packet, verbose=False)
        sent_any = True
    except Exception as exc:
        spoof_error = exc

    if UDP_PLAIN_FALLBACK_ENABLED:
        try:
            plain_sock = get_udp_plain_sock()
            plain_sock.sendto(packet, (VPS_IN_IP, UDP_PORT))
            sent_any = True
        except Exception as exc:
            if spoof_error is None:
                spoof_error = exc

    if not sent_any:
        if spoof_error is None:
            raise RuntimeError("failed to send UDP chunk")
        raise RuntimeError(f"failed to send UDP chunk: {spoof_error}")


def send_chunk_with_tracking(session: SessionState, payload: bytes, flags: int = 0) -> None:
    while not session.stop_event.is_set():
        with session.state_lock:
            if len(session.send_buffer) < MAX_PENDING_CHUNKS:
                break
        time.sleep(0.002)

    with session.state_lock:
        if session.stop_event.is_set():
            return
        seq_num = session.next_seq
        session.next_seq += 1
        if session.first_chunk_sent_at is None:
            session.first_chunk_sent_at = time.monotonic()
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


def wait_for_pending_acks(session: SessionState, timeout_seconds: float) -> None:
    deadline = time.monotonic() + timeout_seconds
    while not session.stop_event.is_set() and time.monotonic() < deadline:
        with session.state_lock:
            pending = len(session.send_buffer)
        if pending == 0:
            return
        time.sleep(0.02)


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
                        if session.first_ack_received_at is None:
                            session.first_ack_received_at = time.monotonic()
                        if ack_seq > session.acked_upto:
                            for seq_num in list(session.send_buffer.keys()):
                                if seq_num <= ack_seq:
                                    session.send_buffer.pop(seq_num, None)
                            session.acked_upto = ack_seq
                    log.debug("session=%s acked upto seq=%s remaining=%s", session.session_id, ack_seq, len(session.send_buffer))
                elif len(payload) == ACK_SACK_FORMAT.size:
                    ack_base_raw, ack_mask = ACK_SACK_FORMAT.unpack(payload)
                    ack_base = -1 if ack_base_raw == 0xFFFFFFFF else ack_base_raw
                    removed = 0
                    with session.state_lock:
                        session.acks_received += 1
                        session.last_ack_seq = ack_base
                        if session.first_ack_received_at is None:
                            session.first_ack_received_at = time.monotonic()
                        if ack_base > session.acked_upto:
                            session.acked_upto = ack_base
                        for seq_num in list(session.send_buffer.keys()):
                            if seq_num <= ack_base:
                                session.send_buffer.pop(seq_num, None)
                                removed += 1
                                continue
                            delta = seq_num - ack_base
                            if 1 <= delta <= ACK_SACK_WINDOW and (ack_mask & (1 << (delta - 1))):
                                session.send_buffer.pop(seq_num, None)
                                removed += 1
                    log.debug(
                        "session=%s sack ack_base=%s ack_mask=0x%016x removed=%s remaining=%s",
                        session.session_id,
                        ack_base,
                        ack_mask,
                        removed,
                        len(session.send_buffer),
                    )
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
            data = session.target_sock.recv(TARGET_RECV_SIZE)
            if not data:
                break
            chunk_limit = max(512, session.tx_chunk_payload_limit)
            for offset in range(0, len(data), chunk_limit):
                chunk = data[offset : offset + chunk_limit]
                send_chunk_with_tracking(session, chunk)
                session.bytes_to_in += len(chunk)
    except Exception as exc:
        if not session.stop_event.is_set():
            close_session(session, f"target read failed: {exc}")
    finally:
        if not session.stop_event.is_set():
            wait_for_pending_acks(session, SESSION_CLOSE_GRACE)
            try:
                send_control_error(session, "target closed connection")
                send_frame(session.control_sock, TYPE_CLOSE, session.session_id, b"target closed", session.send_lock)
            except Exception:
                pass
            close_session(session, "target closed connection")


def handle_retransmissions(session: SessionState) -> None:
    while not session.stop_event.is_set():
        time.sleep(RETRANSMIT_SCAN_INTERVAL)
        if session.stop_event.is_set():
            break

        now = time.monotonic()
        resend_list: list[tuple[int, BufferedChunk]] = []
        with session.state_lock:
            for seq_num, buffered in list(session.send_buffer.items()):
                if seq_num <= session.acked_upto:
                    session.send_buffer.pop(seq_num, None)
                    continue
                if now >= buffered.next_retry_at:
                    resend_list.append((seq_num, buffered))

        resend_list.sort(key=lambda item: item[0])
        if len(resend_list) > MAX_RESENDS_PER_TICK:
            resend_list = resend_list[:MAX_RESENDS_PER_TICK]

        for seq_num, buffered in resend_list:
            if session.stop_event.is_set():
                break
            with session.state_lock:
                current = session.send_buffer.get(seq_num)
                if current is None:
                    continue
                current.attempts += 1
                now = time.monotonic()
                current.last_sent = now
                current.retry_interval = min(current.retry_interval * RESEND_BACKOFF_FACTOR, 3.0)
                current.next_retry_at = now + current.retry_interval
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
        ack_latencies = []
        for session in snapshot:
            latency = first_ack_latency_ms(session)
            if latency is not None:
                ack_latencies.append(latency)
        avg_first_ack_ms = int(sum(ack_latencies) / len(ack_latencies)) if ack_latencies else -1
        log.info(
            "status active_sessions=%s accepted_sessions=%s total_chunks=%s bytes_to_target=%s bytes_to_in=%s sessions_waiting_ack=%s pending_chunks=%s avg_first_ack_ms=%s",
            len(snapshot),
            accepted,
            total_chunks,
            total_to_target,
            total_to_in,
            sessions_waiting_ack,
            pending_chunks,
            avg_first_ack_ms,
        )


def handle_control_conn(control_sock: socket.socket, client_addr: tuple[str, int]) -> None:
    session: Optional[SessionState] = None
    target_sock: Optional[socket.socket] = None
    try:
        tune_tcp_socket(control_sock)
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
        tune_tcp_socket(target_sock)
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
                "ack_sack_window": ACK_SACK_WINDOW,
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
    init_go_sender()
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