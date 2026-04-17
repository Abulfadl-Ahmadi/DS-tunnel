#!/usr/bin/env python3
from __future__ import annotations

import json
import logging
from logging.handlers import RotatingFileHandler
import secrets
import socket
import struct
import threading
import time
import os
from dotenv import load_dotenv
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

try:
    import socks  # PySocks
except ImportError as exc:  # pragma: no cover - runtime dependency check
    raise SystemExit("PySocks is required. Install dependencies with: pip install -r requirements.txt") from exc

logging.basicConfig(level=logging.INFO, format="%(asctime)s [IN] %(message)s")
log = logging.getLogger(__name__)

# ========== CONFIGURATION ==========
CONFIG_PATH = Path(__file__).with_name("in_config.json")
DEFAULT_CONFIG = {
    "socks5_proxy_host": "127.0.0.1",
    "socks5_proxy_port": 18001,
    "vps_out_ip": "5.6.7.8",
    "vps_out_control_port": 8888,
    "udp_listen_port": 10808,
    "socks5_listen_host": "127.0.0.1",
    "socks5_listen_port": 10808,
    "udp_mtu": 1200,
    "udp_recv_buffer_bytes": 1048576,
    "socket_buffer_bytes": 1048576,
    "client_recv_size": 65536,
    "log_file": "log_in_runtime.log",
    "log_level": "INFO",
    "log_max_bytes": 20971520,
    "log_backup_count": 5,
    "keepalive_interval": 3.0,
    "keepalive_timeout": 10.0,
    "control_timeout": 15.0,
    "socks5_connect_timeout": 10.0,
    "session_close_grace": 1.0,
}
# ===================================

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
    
    config["vps_out_ip"] = os.getenv("VPS_OUT_IP", config.get("vps_out_ip", "5.6.7.8"))
    
    return config
    
    return config


def configure_logging(config: dict[str, object]) -> Path:
    log_level_name = str(config.get("log_level", "INFO")).upper()
    log_level = getattr(logging, log_level_name, logging.INFO)
    log_file_raw = str(config.get("log_file", "log_in_runtime.log"))
    log_file = Path(log_file_raw)
    if not log_file.is_absolute():
        log_file = Path(__file__).with_name(log_file_raw)

    log_max_bytes = int(config.get("log_max_bytes", 20 * 1024 * 1024))
    log_backup_count = int(config.get("log_backup_count", 5))
    formatter = logging.Formatter("%(asctime)s [IN] %(message)s")

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
SOCKS5_PROXY = (str(CONFIG["socks5_proxy_host"]), int(CONFIG["socks5_proxy_port"]))
VPS_OUT_IP = str(CONFIG["vps_out_ip"])
VPS_OUT_CONTROL_PORT = int(CONFIG["vps_out_control_port"])
UDP_LISTEN_PORT = int(CONFIG["udp_listen_port"])
SOCKS5_LISTEN_HOST = str(CONFIG["socks5_listen_host"])
SOCKS5_LISTEN_PORT = int(CONFIG["socks5_listen_port"])
UDP_MTU = int(CONFIG["udp_mtu"])
UDP_RECV_BUFFER_BYTES = int(CONFIG["udp_recv_buffer_bytes"])
SOCKET_BUFFER_BYTES = int(CONFIG["socket_buffer_bytes"])
CLIENT_RECV_SIZE = int(CONFIG["client_recv_size"])
KEEPALIVE_INTERVAL = float(CONFIG["keepalive_interval"])
KEEPALIVE_TIMEOUT = float(CONFIG["keepalive_timeout"])
CONTROL_TIMEOUT = float(CONFIG["control_timeout"])
SOCKS5_CONNECT_TIMEOUT = float(CONFIG["socks5_connect_timeout"])
SESSION_CLOSE_GRACE = float(CONFIG["session_close_grace"])
MAGIC = b"HTUN"
VERSION = 1
MAX_UDP_HEADER_SIZE = struct.calcsize("!4sIIBH")
MAX_UDP_PAYLOAD = UDP_MTU - 20 - 8 - MAX_UDP_HEADER_SIZE
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


def validate_configuration() -> None:
    if VPS_OUT_IP in {"5.6.7.8", "1.2.3.4"}:
        log.warning("VPS_OUT_IP still has a placeholder value: %s", VPS_OUT_IP)
    if SOCKS5_PROXY[0] == "127.0.0.1" and SOCKS5_PROXY[1] == 18001:
        log.info("Using local SOCKS5 proxy at %s:%s", SOCKS5_PROXY[0], SOCKS5_PROXY[1])
    log.info("Configured UDP MTU=%s, max payload=%s bytes", UDP_MTU, MAX_UDP_PAYLOAD)
    log.info(
        "Configured buffers udp_recv=%s socket_buffer=%s client_recv=%s",
        UDP_RECV_BUFFER_BYTES,
        SOCKET_BUFFER_BYTES,
        CLIENT_RECV_SIZE,
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


def send_socks5_reply(client_sock: socket.socket, reply_code: int) -> None:
    client_sock.sendall(b"\x05" + bytes([reply_code]) + b"\x00\x01\x00\x00\x00\x00\x00\x00")


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


def parse_socks5_request(client_sock: socket.socket) -> tuple[int, str, int]:
    first = recv_exact(client_sock, 2)
    version, method_count = first[0], first[1]
    if version != 5:
        raise ValueError(f"unexpected SOCKS version {version}")
    methods = recv_exact(client_sock, method_count)
    if 0 not in methods:
        raise ValueError("SOCKS5 client does not support no-auth")
    client_sock.sendall(b"\x05\x00")

    request = recv_exact(client_sock, 4)
    version, command, _reserved, address_type = request
    if version != 5:
        raise ValueError(f"unexpected SOCKS request version {version}")
    if command not in {1, 3}:
        raise ValueError(f"unsupported SOCKS command {command}")

    if address_type == 1:
        host = socket.inet_ntoa(recv_exact(client_sock, 4))
    elif address_type == 3:
        length = recv_exact(client_sock, 1)[0]
        host = recv_exact(client_sock, length).decode("idna")
    elif address_type == 4:
        host = socket.inet_ntop(socket.AF_INET6, recv_exact(client_sock, 16))
    else:
        raise ValueError(f"unsupported SOCKS address type {address_type}")

    port = struct.unpack("!H", recv_exact(client_sock, 2))[0]
    return command, host, port


@dataclass
class SessionState:
    session_id: int
    client_sock: socket.socket
    control_sock: socket.socket
    client_addr: tuple[str, int]
    target_host: str
    target_port: int
    send_lock: threading.Lock = field(default_factory=threading.Lock)
    state_lock: threading.Lock = field(default_factory=threading.Lock)
    stop_event: threading.Event = field(default_factory=threading.Event)
    ready_event: threading.Event = field(default_factory=threading.Event)
    pending_udp: dict[int, bytes] = field(default_factory=dict)
    next_udp_seq: int = 0
    highest_delivered_seq: int = -1
    bytes_from_client: int = 0
    bytes_from_out: int = 0
    chunks_from_out: int = 0
    acks_sent: int = 0
    acks_failed: int = 0
    last_acked_seq: int = -1
    last_pong: float = field(default_factory=time.monotonic)
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


def run_preflight_checks() -> None:
    log.info("preflight checking local SOCKS5 proxy at %s:%s", SOCKS5_PROXY[0], SOCKS5_PROXY[1])
    try:
        with socket.create_connection(SOCKS5_PROXY, timeout=SOCKS5_CONNECT_TIMEOUT):
            pass
        log.info("preflight local SOCKS5 proxy reachable")
    except Exception as exc:
        log.error("preflight local SOCKS5 proxy check failed: %s", exc)
        return

    log.info("preflight checking OUT control via SOCKS5 %s:%s", VPS_OUT_IP, VPS_OUT_CONTROL_PORT)
    try:
        probe = socks.socksocket()
        probe.set_proxy(socks.SOCKS5, SOCKS5_PROXY[0], SOCKS5_PROXY[1])
        probe.settimeout(SOCKS5_CONNECT_TIMEOUT)
        probe.connect((VPS_OUT_IP, VPS_OUT_CONTROL_PORT))
        probe.close()
        log.info("preflight OUT control is reachable via SOCKS5")
    except Exception as exc:
        log.error("preflight OUT control check failed: %s", exc)


def register_session(session: SessionState) -> None:
    with sessions_lock:
        sessions[session.session_id] = session
    with session_stats_lock:
        session_stats["accepted"] += 1
    emit_status_snapshot("session_open")


def unregister_session(session_id: int) -> None:
    with sessions_lock:
        sessions.pop(session_id, None)


def get_session(session_id: int) -> Optional[SessionState]:
    with sessions_lock:
        return sessions.get(session_id)


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
        "session=%s closing reason=%s bytes_from_client=%s bytes_from_out=%s chunks_from_out=%s acks_sent=%s acks_failed=%s last_acked_seq=%s",
        session.session_id,
        reason,
        session.bytes_from_client,
        session.bytes_from_out,
        session.chunks_from_out,
        session.acks_sent,
        session.acks_failed,
        session.last_acked_seq,
    )
    for sock_obj in (session.client_sock, session.control_sock):
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
    emit_status_snapshot("session_close")


def udp_receiver() -> None:
    udp_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    udp_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    udp_sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, UDP_RECV_BUFFER_BYTES)
    udp_sock.bind(("0.0.0.0", UDP_LISTEN_PORT))
    log.info("UDP receiver listening on %s", UDP_LISTEN_PORT)

    while True:
        data, addr = udp_sock.recvfrom(UDP_MTU + 128)
        if len(data) < UDP_HEADER.size:
            log.warning("dropped short UDP packet from %s len=%s", addr, len(data))
            continue

        try:
            magic, session_id, seq_num, flags, payload_len = UDP_HEADER.unpack_from(data)
        except struct.error:
            log.warning("dropped malformed UDP packet from %s", addr)
            continue

        if magic != MAGIC:
            log.debug("dropped UDP packet with unknown magic from %s", addr)
            continue

        if payload_len != len(data) - UDP_HEADER.size:
            log.warning(
                "session=%s UDP length mismatch seq=%s declared=%s actual=%s",
                session_id,
                seq_num,
                payload_len,
                len(data) - UDP_HEADER.size,
            )
            continue

        payload = data[UDP_HEADER.size:]
        session = get_session(session_id)
        if session is None:
            log.debug("dropping UDP packet for unknown session=%s from %s", session_id, addr)
            continue

        ack_base = -1
        ack_mask = 0
        should_ack = False
        with session.state_lock:
            if session.stop_event.is_set():
                continue
            log.debug("session=%s UDP source=%s seq=%s flags=%s", session_id, addr[0], seq_num, flags)
            if seq_num < session.next_udp_seq:
                ack_base = session.highest_delivered_seq
                should_ack = True
            else:
                if seq_num not in session.pending_udp:
                    session.pending_udp[seq_num] = payload
                    should_ack = True

            delivered = False
            while session.next_udp_seq in session.pending_udp:
                chunk = session.pending_udp.pop(session.next_udp_seq)
                try:
                    session.client_sock.sendall(chunk)
                except Exception as exc:
                    close_session(session, f"client write failed: {exc}")
                    break
                session.bytes_from_out += len(chunk)
                session.chunks_from_out += 1
                session.highest_delivered_seq = session.next_udp_seq
                session.next_udp_seq += 1
                delivered = True

            if delivered:
                should_ack = True

            ack_base = session.highest_delivered_seq
            for pending_seq in session.pending_udp.keys():
                delta = pending_seq - ack_base
                if 1 <= delta <= ACK_SACK_WINDOW:
                    ack_mask |= 1 << (delta - 1)

        if should_ack and not session.stop_event.is_set():
            try:
                ack_base_raw = 0xFFFFFFFF if ack_base < 0 else ack_base
                payload = ACK_SACK_FORMAT.pack(ack_base_raw, ack_mask)
                send_frame(session.control_sock, TYPE_ACK, session.session_id, payload, session.send_lock)
                with session.state_lock:
                    session.acks_sent += 1
                    session.last_acked_seq = ack_base
                log.debug(
                    "session=%s acked seq=%s mask=0x%016x bytes_from_out=%s chunks=%s",
                    session.session_id,
                    ack_base,
                    ack_mask,
                    session.bytes_from_out,
                    session.chunks_from_out,
                )
            except Exception as exc:
                with session.state_lock:
                    session.acks_failed += 1
                close_session(session, f"failed to send ACK: {exc}")


def connect_control_channel(target_host: str, target_port: int, client_addr: tuple[str, int]) -> socket.socket:
    control_sock = socks.socksocket()
    tune_tcp_socket(control_sock)
    control_sock.set_proxy(socks.SOCKS5, SOCKS5_PROXY[0], SOCKS5_PROXY[1])
    control_sock.settimeout(SOCKS5_CONNECT_TIMEOUT)
    control_sock.connect((VPS_OUT_IP, VPS_OUT_CONTROL_PORT))
    control_sock.settimeout(None)
    log.info(
        "control connection established via socks5=%s:%s to out=%s:%s for %s:%s",
        SOCKS5_PROXY[0],
        SOCKS5_PROXY[1],
        VPS_OUT_IP,
        VPS_OUT_CONTROL_PORT,
        client_addr[0],
        client_addr[1],
    )
    return control_sock


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

            if message_type == TYPE_READY:
                session.ready_event.set()
                log.info(
                    "session=%s ready target=%s:%s",
                    session.session_id,
                    session.target_host,
                    session.target_port,
                )
            elif message_type == TYPE_PONG:
                session.last_pong = time.monotonic()
            elif message_type == TYPE_ERROR:
                error_text = payload.decode("utf-8", errors="replace") if payload else "unknown error"
                close_session(session, f"out error: {error_text}")
                return
            elif message_type == TYPE_CLOSE:
                close_session(session, "peer closed session")
                return
            elif message_type == TYPE_ACK:
                log.debug("session=%s received unexpected ACK from OUT", session.session_id)
            else:
                log.debug("session=%s ignored control type=%s payload=%s bytes", session.session_id, message_type, len(payload))
    except Exception as exc:
        if not session.stop_event.is_set():
            close_session(session, f"control reader failed: {exc}")


def handle_client_to_out(session: SessionState) -> None:
    try:
        while not session.stop_event.is_set():
            data = session.client_sock.recv(CLIENT_RECV_SIZE)
            if not data:
                break
            session.bytes_from_client += len(data)
            send_frame(session.control_sock, TYPE_DATA, session.session_id, data, session.send_lock)
    except Exception as exc:
        if not session.stop_event.is_set():
            close_session(session, f"client read failed: {exc}")
    finally:
        if not session.stop_event.is_set():
            try:
                send_frame(session.control_sock, TYPE_CLOSE, session.session_id, b"client disconnected", session.send_lock)
            except Exception:
                pass
            close_session(session, "client disconnected")


def handle_keepalive(session: SessionState) -> None:
    missed_pongs = 0
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
            missed_pongs += 1
            log.warning("session=%s missed keepalive pong count=%s", session.session_id, missed_pongs)
            if missed_pongs >= 2:
                close_session(session, "keepalive timeout")
                break
        else:
            missed_pongs = 0


def handle_socks5_client(client_sock: socket.socket, client_addr: tuple[str, int]) -> None:
    session: Optional[SessionState] = None
    try:
        command, target_host, target_port = parse_socks5_request(client_sock)
        if command == 3:
            log.warning("client=%s requested UDP ASSOCIATE for %s:%s; not supported", client_addr, target_host, target_port)
            send_socks5_reply(client_sock, 7)
            return
        session_id = secrets.randbits(32)
        log.info("session=%s client=%s target=%s:%s", session_id, client_addr, target_host, target_port)

        control_sock = connect_control_channel(target_host, target_port, client_addr)
        session = SessionState(
            session_id=session_id,
            client_sock=client_sock,
            control_sock=control_sock,
            client_addr=client_addr,
            target_host=target_host,
            target_port=target_port,
        )
        tune_tcp_socket(client_sock)
        register_session(session)

        hello_payload = json.dumps(
            {
                "target_host": target_host,
                "target_port": target_port,
                "client_addr": f"{client_addr[0]}:{client_addr[1]}",
                "udp_listen_port": UDP_LISTEN_PORT,
                "udp_mtu": UDP_MTU,
                "max_udp_payload": MAX_UDP_PAYLOAD,
                "ack_sack_window": ACK_SACK_WINDOW,
            },
            separators=(",", ":"),
        ).encode("utf-8")
        send_frame(control_sock, TYPE_HELLO, session_id, hello_payload, session.send_lock)

        control_sock.settimeout(CONTROL_TIMEOUT)
        message_type, message_session_id, payload = recv_frame(control_sock)
        control_sock.settimeout(None)
        if message_session_id != session_id:
            raise ValueError(f"session mismatch during handshake: {message_session_id}")
        if message_type != TYPE_READY:
            error_text = payload.decode("utf-8", errors="replace") if payload else f"unexpected type {message_type}"
            raise RuntimeError(error_text)

        session.ready_event.set()
        send_socks5_reply(client_sock, 0)
        log.info("session=%s SOCKS5 CONNECT established", session.session_id)

        threading.Thread(target=handle_control_reader, args=(session,), daemon=True).start()
        threading.Thread(target=handle_client_to_out, args=(session,), daemon=True).start()
        threading.Thread(target=handle_keepalive, args=(session,), daemon=True).start()

        while not session.stop_event.is_set():
            time.sleep(0.2)
    except Exception as exc:
        log.error("client=%s failed: %s", client_addr, exc)
        try:
            send_socks5_reply(client_sock, 1)
        except Exception:
            pass
        if session is not None:
            close_session(session, str(exc))
        else:
            try:
                client_sock.close()
            except Exception:
                pass
    finally:
        if session is not None and not session.stop_event.is_set():
            close_session(session, "session finished")
        else:
            try:
                client_sock.close()
            except Exception:
                pass


def socks5_server() -> None:
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind((SOCKS5_LISTEN_HOST, SOCKS5_LISTEN_PORT))
    server.listen(64)
    log.info("SOCKS5 tunnel listening on %s:%s", SOCKS5_LISTEN_HOST, SOCKS5_LISTEN_PORT)

    while True:
        client_sock, addr = server.accept()
        threading.Thread(target=handle_socks5_client, args=(client_sock, addr), daemon=True).start()


if __name__ == "__main__":
    validate_configuration()
    run_preflight_checks()
    threading.Thread(target=udp_receiver, daemon=True).start()
    socks5_server()