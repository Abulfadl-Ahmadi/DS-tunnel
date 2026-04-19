# DS Tunnel

This project is a custom tunnel with two paths:

- TCP from VPS IN to VPS OUT goes through the local SOCKS5 proxy at `127.0.0.1:18001`
- UDP from VPS OUT back to VPS IN uses spoofed source IP packets with an MTU budget of `1200`

## Files

- `spoof-tunnel/cmd/spoof` is the Go binary for both VPS IN and VPS OUT
- `in.py` and `out.py` are legacy Python endpoints and are no longer the recommended runtime path

## Dependencies

Build and run the Go binary from `spoof-tunnel`.

```bash
cd spoof-tunnel
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -ldflags="-s -w" -o spoof ./cmd/spoof/
```

`spoof` needs permission to send raw spoofed packets. On Linux this usually means running as root or granting the binary `CAP_NET_RAW`.

## Configuration

Use these config files instead:

- `spoof-tunnel/client-config.json`
- `spoof-tunnel/server-config.json`

Set `server.address` on the client to the VPS OUT public IP.
Set `spoof.source_ip` on each side to the spoofed source IP you want that side to emit.
Set `spoof.peer_spoof_ip` on each side to the spoofed IP expected from the peer.

The local SOCKS5 proxy on VPS IN must be reachable at `127.0.0.1:18001` if you use the current IN-side SOCKS5 setup.

## Start order

1. Start the Go server binary on VPS OUT: `sudo ./spoof -c server-config.json`
2. Start the Go client binary on VPS IN: `sudo ./spoof -c client-config.json`
3. Point your client at the SOCKS5 listener on VPS IN: `127.0.0.1:1080`

## What good startup logs look like

On the Go server:

- `Server listening on port ...`
- `Transport: udp` or `Transport: syn_udp`
- `Expected client spoof IP ...`

On the Go client:

- `Tunneling to <server-ip>:<port> via ...`
- `[inbound] SOCKS5 proxy on 127.0.0.1:1080`

## What fails most often

- Placeholder IPs were not replaced
- VPS OUT cannot reach the target host or port
- VPS IN cannot reach the SOCKS5 proxy on `127.0.0.1:18001`
- `spoof` does not have permission to send raw packets
- Firewalls or security groups block TCP `8888` or UDP `10808`
- The target path is lossy enough that retransmits hit the retry limit
- SOCKS5 UDP ASSOCIATE is currently rejected by the Go client; disable UDP/QUIC in the client or add UDP support before expecting DNS-over-UDP to work

## Notes

The tunnel now uses framed control messages, session IDs, ACKs, and retransmits for UDP delivery. That makes failures visible in logs instead of silently mixing protocol bytes on one TCP stream.

## Performance model

- IN to OUT traffic uses framed TCP control messages (`TYPE_DATA`)
- OUT to IN traffic uses UDP chunks with sequence numbers
- IN sends cumulative ACK base plus a 64-bit selective ACK bitmap
- OUT removes both cumulatively ACKed and selectively ACKed chunks from retransmit buffer

This reduces unnecessary retransmissions when packets arrive out of order.

## Go-only operation

If you want to remove Python from the runtime entirely, use only the Go binary on both ends.

- Build `spoof` once and deploy it to both VPS IN and VPS OUT
- Do not run `out.py` or `in.py`
- Use `server-config.json` on VPS OUT and `client-config.json` on VPS IN
- The Go binary covers spoofing, reliability, transport, SOCKS5 inbound, and direct relay paths

Recommended OUT systemd command:

```bash
sudo ./spoof -c server-config.json
```

Recommended IN systemd command:

```bash
sudo ./spoof -c client-config.json
```

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
