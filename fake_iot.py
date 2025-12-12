#!/usr/bin/env python3
import socket
import struct
import time
import hmac
import hashlib
import sys

# --- Configuration ---
# Malicious/Fake Secret Key
FAKE_SECRET = b"WRONG_SECRET_BYTES" 
HMAC_TRUNC_BYTES = 8

DEVICE_ID = "DEV01"  # Trying to impersonate DEV01
PORT = 12001

def main():
    print("[FAKE DEVICE] Starting malicious emulator...")
    print(f"[FAKE DEVICE] Impersonating: {DEVICE_ID}")
    print(f"[FAKE DEVICE] Using Key:     {FAKE_SECRET} (Invalid)")
    
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(('0.0.0.0', PORT))
    print(f"[FAKE DEVICE] Listening on UDP {PORT}...")

    while True:
        try:
            data, addr = sock.recvfrom(512)
            if len(data) < 12:
                continue

            print(f"[FAKE DEVICE] Intercepted challenge from {addr}")

            # Parse Challenge
            nonce = struct.unpack('>Q', data[:8])[0]
            ts = struct.unpack('>I', data[8:12])[0]

            # Construct Fake Response
            # 1. We use the CORRECT structure
            # 2. But we use the WRONG Key
            msg = struct.pack('>Q I', nonce, ts) + DEVICE_ID.encode()
            
            # Compute INVALID MAC
            fake_mac = hmac.new(FAKE_SECRET, msg, hashlib.sha256).digest()[:HMAC_TRUNC_BYTES]

            ts_resp = int(time.time())
            
            # Pack Response: MAC || TS || ID
            resp = fake_mac + struct.pack('>I', ts_resp) + DEVICE_ID.encode()
            # Pad ID to 8 bytes if needed
            while len(resp) < 8 + 4 + 8:
                resp += b'\0'

            time.sleep(0.1) # Simulate processing
            sock.sendto(resp, addr)
            print(f"[FAKE DEVICE] Sent FAKE response (MAC={fake_mac.hex()})")

        except KeyboardInterrupt:
            print("\n[FAKE DEVICE] Stopping.")
            break
        except Exception as e:
            print(f"[FAKE DEVICE] Error: {e}")

if __name__ == "__main__":
    main()
