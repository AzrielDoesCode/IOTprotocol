# IoT Security Protocol: In-Depth Architecture & Codebase Report

## 1. Executive Summary

This project implements a secure, lightweight Unilateral Authentication Protocol designed specifically for constrained IoT devices. It demonstrates a robust defense against common network vulnerabilities such as Replay Attacks, Spoofing, and Brute Force attacks. 

The core narrative of this project is **Hardware-Intrinsic Security for Lightweight IoT**. Instead of relying on heavy TCP/TLS handshakes which consume too much battery and memory on microcontrollers, this protocol uses raw UDP datagrams secured by HMAC-SHA256 signatures, temporal nonces (timestamps), and a simulated Physical Unclonable Function (PUF).

### Why C++ for the Device?
The `device.cpp` file is written in C++17. This is a critical design choice:
*   **Peak Performance & Low Latency**: C++ executes close to the metal. When handling incoming UDP floods or performing cryptographic operations (SHA256), C++ outpaces interpreted languages drastically.
*   **Memory Determinism**: C++ allows precise control over memory allocation (avoiding garbage collection pauses). In a real IoT environment (like an ESP32 or ARM Cortex-M), memory footprint is strictly limited.
*   **Minimal Overhead**: By using raw sockets (`<sys/socket.h>`/`winsock2.h`) and OpenSSL's EVP API, the binary size remains extremely small compared to pulling in massive runtime environments.

### Why Python for the Server & Adversary Tools?
The server (`server.py`) and attack simulators (`adversary.py`, `fake_iot.py`) are written in Python.
*   **Rapid Iteration**: The server logic and attack simulations don't run on constrained hardware. Python allows for rapid development of network logic, easy struct packing/unpacking, and simple multi-threading.
*   **Standard Library Dominance**: Python's `socket`, `struct`, and `hmac` libraries make it exceptionally easy to format binary payloads for network transmission.

---

## 2. In-Depth File Breakdown

### A. `device.cpp` - The Edge Node
This file represents the firmware running on the IoT device.

**1. Network & Crypto Setup (Lines 1-102)**
*   The code uses cross-platform socket headers (Winsock for Windows, POSIX for Linux) ensuring it can be compiled anywhere.
*   `sha256_bytes` and `hmac_sha256_trunc`: These are wrappers around OpenSSL's EVP API. They perform the cryptographic heavy lifting. `hmac_sha256_trunc` specifically truncates the HMAC to 8 bytes (`HMAC_TRUNC_BYTES`). This saves network bandwidth, which is crucial for IoT (e.g., LoRaWAN or NB-IoT), while still providing $2^{64}$ security against guessing attacks.

**2. PUFEmulator Class (Lines 121-174)**
*   **Reasoning**: Storing secret keys on an IoT device's flash memory is dangerous; attackers can physically extract the chip and dump the memory to steal the key. A PUF (Physical Unclonable Function) uses microscopic manufacturing variations in the silicon to generate a unique key *only when powered on*.
*   **Implementation**: `PUFEmulator` mimics this by deriving a unique fingerprint from the `device_id` and injecting artificial noise via `noisy_read()`. 

**3. ReplayCache Class (Lines 179-242)**
*   **Reasoning**: UDP is stateless. If an attacker records a valid authentication packet, they could re-send it later to trick the device.
*   **Implementation**: The device stores recently seen timestamps in `cache.csv`. If a packet arrives with a timestamp older than `TS_WINDOW_SEC` (10 seconds), or if the timestamp is exactly the same as one in the cache, the device drops the packet immediately.

**4. AuditLogger Class (Lines 247-274)**
*   **Reasoning**: For SIEM integration and debugging, the device logs all critical events (Startup, Replay Rejects, Auth Successes) to a local CSV file.

**5. Main Loop (Lines 279-461)**
*   The device binds to UDP Port 12001 and enters a `while(true)` listen loop.
*   Upon receiving a packet, it extracts the 8-byte Nonce and 4-byte Timestamp.
*   It checks the `ReplayCache`. If valid, it computes an HMAC signature using its PUF-derived key (or a hardcoded stored key in demo mode) over the payload: `MAC(Key, Nonce || Timestamp || DeviceID)`.
*   It sends back the MAC, a new timestamp, and its ID.
*   If the device receives a packet starting with `"HELLO_"`, it treats it as an authorized command.

### B. `server.py` - The Command Center
This file represents the central backend or cloud server trying to communicate securely with the edge device.

**1. The Challenge (Lines 25-31)**
*   The server generates a highly random 64-bit `nonce` (using the current time in milliseconds) and a 32-bit `timestamp`.
*   It packs them into binary using `struct.pack('>Q I', nonce, ts)` (Big-Endian format) and sends this challenge to the device over UDP.

**2. The Verification (Lines 41-59)**
*   The server waits for a response. Upon receiving it, it unpacks the binary payload to extract the device's MAC, Timestamp, and Device ID.
*   It runs the exact same HMAC algorithm (`compute_expected_hmac`) using its own copy of the shared secret (or mathematical equivalent for PUF).
*   If the MAC computed by the server exactly matches the MAC sent by the device, the server *knows mathematically* that the device is genuine and the packet wasn't tampered with.

**3. The Command (Lines 61-66)**
*   Only after authentication succeeds does the server send the plaintext `"HELLO_DEVICE"` command. 

### C. `fake_iot.py` - Identity Spoofing Demo
This script demonstrates what happens when an attacker tries to trick the server into thinking a malicious device is the real `DEV01`.

*   **Logic**: It binds to the same port and listens for challenges from the server. When it receives a challenge, it correctly parses the Nonce and Timestamp. It constructs a structurally perfect response payload.
*   **The Catch**: It uses `FAKE_SECRET = b"WRONG_SECRET_BYTES"` to compute the HMAC.
*   **Result**: When the server receives the response, the cryptographic verification fails, and the server drops the connection, successfully preventing the spoofing attack.

### D. `adversary.py` - The Network Attacker
This script is a comprehensive penetration testing tool built to validate the protocol's defenses.

**1. Replay Attack (`run_replay_attack`)**
*   **Logic**: It acts as a Man-In-The-Middle. It sends a valid challenge to the real device, captures the valid response, and then re-sends that exact same challenge a moment later.
*   **Defense Demonstrated**: The C++ device's `ReplayCache` detects the duplicate timestamp and blocks the second request entirely.

**2. Brute Force / Fuzzing (`run_brute_force_fuzzing`)**
*   **Logic**: Floods the device with malformed packets (too short, garbage data, or structurally valid but mathematically random data).
*   **Defense Demonstrated**: Proves that the C++ firmware is robust. It won't crash from buffer overflows (thanks to length checks) and cleanly rejects invalid packets without spending CPU cycles on crypto if the packet size is wrong.

**3. HMAC Cracking Sim (`run_hmac_cracking_sim`)**
*   **Logic**: A theoretical demonstration. It captures a valid MAC and simulates how long it would take an attacker to brute-force the 128-bit key locally on a GPU.
*   **Defense Demonstrated**: Calculates that even at 2 billion keys per second, it would take astronomical amounts of time to guess the key, proving the math behind the protocol is sound.

---

## 3. Conclusion

This project effectively demonstrates a highly optimized, hardware-conscious security architecture. 
1. The **C++ Edge Device** provides the speed, memory safety, and low-level control required for real-world microcontrollers.
2. The **Python Backend** provides the agility needed for cloud-scale verification.
3. The **Cryptographic implementation** (Truncated HMAC + Temporal Nonces) successfully defends against the most common and dangerous network-layer attacks targeting IoT ecosystems today.
