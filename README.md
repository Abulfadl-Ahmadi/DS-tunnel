# Hyper Tunnel

This project is a proof-of-concept tunnel with two paths:

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

## Notes

The tunnel now uses framed control messages, session IDs, ACKs, and retransmits for UDP delivery. That makes failures visible in logs instead of silently mixing protocol bytes on one TCP stream.
