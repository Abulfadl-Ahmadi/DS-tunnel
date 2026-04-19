# DS Tunnel

This project is a custom tunnel with two paths:

- TCP from VPS IN to VPS OUT goes through the local SOCKS5 proxy at `127.0.0.1:18001`
- UDP from VPS OUT back to VPS IN uses spoofed source IP packets with an MTU budget of `1200`

## Files

- `in.py` runs on VPS IN
- `out.py` runs on VPS OUT

## Dependencies

Install the Python packages listed in `requirements.txt`.

```bash
pip install -r requirements.txt
```

`out.py` also needs permission to send raw spoofed packets. On Linux this usually means running as root or granting the Python interpreter the required capabilities.

## Configuration

Update these placeholders before running:

- `in.py`: `VPS_OUT_IP`
- `out.py`: `VPS_IN_IP`
- `out.py`: `SPOOF_IP`

The local SOCKS5 proxy on VPS IN must be reachable at `127.0.0.1:18001`.

## Start order

1. Start `out.py` on VPS OUT.
2. Start `in.py` on VPS IN.
3. Point your client at the SOCKS5 listener on VPS IN: `127.0.0.1:10808`.

## What good startup logs look like

On `out.py`:

- `listening for control TCP on 0.0.0.0:8888`
- `session=... target=host:port`
- `status active_sessions=...`

On `in.py`:

- `UDP receiver listening on 10808`
- `SOCKS5 tunnel listening on 127.0.0.1:10808`
- `session=... ready target=host:port`

## What fails most often

- Placeholder IPs were not replaced
- VPS OUT cannot reach the target host or port
- VPS IN cannot reach the SOCKS5 proxy on `127.0.0.1:18001`
- `out.py` does not have permission to send raw packets
- Firewalls or security groups block TCP `8888` or UDP `10808`
- The target path is lossy enough that retransmits hit the retry limit
- SOCKS5 UDP ASSOCIATE is currently rejected by `in.py`; disable UDP/QUIC in the client or add UDP support before expecting DNS-over-UDP to work

## Notes

The tunnel now uses framed control messages, session IDs, ACKs, and retransmits for UDP delivery. That makes failures visible in logs instead of silently mixing protocol bytes on one TCP stream.

## Performance model

- IN to OUT traffic uses framed TCP control messages (`TYPE_DATA`)
- OUT to IN traffic uses UDP chunks with sequence numbers
- IN sends cumulative ACK base plus a 64-bit selective ACK bitmap
- OUT removes both cumulatively ACKed and selectively ACKed chunks from retransmit buffer

This reduces unnecessary retransmissions when packets arrive out of order.

## Downstream acceleration with Go sender

`out.py` can now use a Go-based downstream sender from `spoof-tunnel` to emit spoofed UDP packets faster than Scapy.

- Upstream is unchanged and still goes through SOCKS5 `127.0.0.1:18001`
- Only OUT -> IN UDP downstream send path is switched to Go
- If Go build/start fails, `out.py` automatically falls back to the previous Python send path

New `out_config.json` keys:

- `go_downstream_sender_enabled` (default `true`)
- `go_sender_project_dir` (default `spoof-tunnel`)
- `go_sender_build_dir` (default `.go-bin`)
- `go_sender_binary_name` (default `downstream-sender`)
- `go_sender_send_only` (default `true`)

Requirements for acceleration on VPS OUT:

- Go toolchain installed (`go` in `PATH`)
- Raw packet permission (root or equivalent capabilities)

## Recommended production tuning

In `out_config.json`:

- `resend_interval`: start at `0.30` to `0.40`
- `retransmit_scan_interval`: `0.05`
- `max_resends_per_tick`: `64` (raise to `96` for high RTT/loss)
- `max_pending_chunks`: `8192` (raise if memory is sufficient)
- `socket_buffer_bytes`: `4194304`

In `in_config.json`:

- `udp_recv_buffer_bytes`: `4194304`
- `socket_buffer_bytes`: `4194304`
- `client_recv_size`: `65536`

After changes, restart both endpoints and monitor:

- OUT status: `sessions_waiting_ack`, `pending_chunks`, `avg_first_ack_ms`
- OUT close lines: `acks_received`, `pending_chunks`, `first_ack_latency_ms`

If `pending_chunks` keeps growing while `acks_received` stays low, the path is still ACK-starved and needs either lower MTU, faster ACK return path, or architecture change.
