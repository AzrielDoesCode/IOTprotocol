#!/usr/bin/env python3
import socket
import struct
import time
import hmac
import hashlib
from datetime import datetime

MASTER_SECRET = b"MASTER_STATIC_SECRET"   # same as device-side for demo
HMAC_TRUNC_BYTES = 8

device_id = "DEV01"        # must match device running
device_ip = "127.0.0.1"    # change to Pi IP if testing remotely
device_port = 12001

def compute_expected_hmac(key, nonce, ts, device_id):
    msg = struct.pack('>Q I', nonce, ts) + device_id.encode()
    return hmac.new(key, msg, hashlib.sha256).digest()[:HMAC_TRUNC_BYTES]

def main():
    print("[SERVER] starting...")
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(3.0)

    # ---- step 1: send challenge request ----
    nonce = int(time.time() * 1000) & ((1 << 64) - 1)  # unique per request
    ts = int(time.time())                              # timestamp used as nonce also for replay ctrl

    challenge = struct.pack('>Q I', nonce, ts)
    print(f"[SERVER] Sending challenge: nonce={nonce}, ts={ts}")
    sock.sendto(challenge, (device_ip, device_port))

    # ---- receive response ----
    try:
        resp, addr = sock.recvfrom(512)
        print(f"[SERVER] Got response from {addr}: {resp.hex()}")
    except socket.timeout:
        print("❌ Device not responding (timeout)")
        return

    # ---- parse response ----
    mac = resp[:HMAC_TRUNC_BYTES]      # HMAC
    ts_resp = struct.unpack('>I', resp[HMAC_TRUNC_BYTES:HMAC_TRUNC_BYTES+4])[0]
    dev_id = resp[HMAC_TRUNC_BYTES+4: HMAC_TRUNC_BYTES+12].decode(errors="ignore")

    print(f"[SERVER] Response ts={ts_resp}, device_id={dev_id}")

    # ---- recompute expected HMAC ----
    expected_key_material = hashlib.sha256(MASTER_SECRET + device_id.encode()).digest()[:16]
    expected_mac = compute_expected_hmac(expected_key_material, nonce, ts, device_id)

    if expected_mac == mac:
        print("🟢 Authentication SUCCESS — Device is genuine")
    else:
        print("❌ Authentication FAILED — MAC mismatch")
        return

    # ---- step 2: send a command after auth success ----
    message = b"HELLO_DEVICE"
    print("[SERVER] Sending secure command message:", message.decode())
    sock.sendto(message, (device_ip, device_port))

    print("🎉 DEMO COMPLETE — Works as expected")

if __name__ == "__main__":
    main()
