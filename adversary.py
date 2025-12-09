#!/usr/bin/env python3
import socket
import struct
import time
import random
import sys
import threading
import os

# --- Configuration ---
TARGET_IP = "127.0.0.1"
TARGET_PORT = 12001
HMAC_TRUNC_BYTES = 8

# --- Colors for TUI ---
class Colors:
    HEADER = '\033[95m'
    BLUE = '\033[94m'
    CYAN = '\033[96m'
    GREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'

def print_header():
    os.system('cls' if os.name == 'nt' else 'clear')
    print(f"{Colors.HEADER}{Colors.BOLD}")
    print("+" + "-"*50 + "+")
    print("|        IoT Security Protocol - ADVERSARY         |")
    print("+" + "-"*50 + "+")
    print("| Targets: PUF Key Gen, HMAC Auth, Replay Defenses |")
    print("+" + "-"*50 + "+")
    print(f"{Colors.ENDC}")

def get_sock():
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(2.0)
    return sock

# --- Attack Modules ---

def run_replay_attack():
    print(f"\n{Colors.WARNING}[!] Preparing REPLAY ATTACK...{Colors.ENDC}")
    print(f"{Colors.CYAN}    Target: {TARGET_IP}:{TARGET_PORT}{Colors.ENDC}")
    
    sock = get_sock()
    
    # 1. Valid Request
    print(f"{Colors.BLUE}[+] Step 1: Intercepting/Genering VALID Challenge (Legitimate request){Colors.ENDC}")
    nonce = int(time.time() * 1000) & ((1 << 64) - 1)
    ts = int(time.time())
    challenge = struct.pack('>Q I', nonce, ts)
    
    print(f"    -> Sending: nonce={nonce}, ts={ts}")
    sock.sendto(challenge, (TARGET_IP, TARGET_PORT))
    
    try:
        resp, _ = sock.recvfrom(512)
        print(f"{Colors.GREEN}[+] Device Responded (200 OK): {resp.hex()}{Colors.ENDC}")
        print("    (The device has now cached this timestamp/nonce)")
    except socket.timeout:
        print(f"{Colors.FAIL}[-] Device did not respond to initial valid request! Is it running?{Colors.ENDC}")
        return

    # 2. Replay
    print(f"\n{Colors.WARNING}[!] Step 2: Executing REPLAY with captured payload...{Colors.ENDC}")
    print(f"    -> Resending IDENTICAL: nonce={nonce}, ts={ts}")
    time.sleep(0.5) # Slight delay
    sock.sendto(challenge, (TARGET_IP, TARGET_PORT))
    
    try:
        resp, _ = sock.recvfrom(512)
        # If we get a response, the attack SUCCEEDED (which is bad for the protocol)
        print(f"{Colors.FAIL}[!] RESPONSE RECEIVED! Replay Attack SUCCEEDED (Protocol Vulnerable?){Colors.ENDC}")
        print(f"    Payload: {resp.hex()}")
    except socket.timeout:
        # Timeout means the device ignored us (GOOD)
        print(f"{Colors.GREEN}[+] No Response. Device BLOCKED the replay! (Protocol Secure){Colors.ENDC}")

def run_brute_force_fuzzing():
    print(f"\n{Colors.WARNING}[!] Starting BRUTE FORCE / FUZZING Attack...{Colors.ENDC}")
    print("    Flooding device with random garbage and invalid nonces.")
    print("    Press Ctrl+C to stop manually if needed.")
    
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(0.1)
    
    count = 0
    max_packets = 50
    print(f"{Colors.CYAN}    Sending {max_packets} malicious packets...{Colors.ENDC}\n")
    
    start_time = time.time()
    
    for i in range(max_packets):
        # Generate random garbage or semi-valid structures
        case = random.randint(0, 2)
        if case == 0:
            # Too short
            payload = os.urandom(random.randint(1, 11))
        elif case == 1:
            # Valid length, random content
            payload = os.urandom(12)
        else:
            # Valid structure, random old timestamp
            nonce = random.getrandbits(64)
            ts = int(time.time()) - random.randint(30, 100000) # Old TS
            payload = struct.pack('>Q I', nonce, ts)
            
        sock.sendto(payload, (TARGET_IP, TARGET_PORT))
        count += 1
        sys.stdout.write(f"\r    [>] Packets Sent: {count}/{max_packets}")
        sys.stdout.flush()
        time.sleep(0.05) # Rate limit slightly to see logs
        
    print(f"\n\n{Colors.BLUE}[*] Attack Complete.{Colors.ENDC}")
    print(f"    Time taken: {time.time() - start_time:.2f}s")
    print(f"{Colors.GREEN}[?] Check Device Logs: It should show 'received too-small packet' or 'Reject (replay/stale)'{Colors.ENDC}")

def run_hmac_cracking_sim():
    print(f"\n{Colors.WARNING}[!] Simulating HMAC KEY CRACKING...{Colors.ENDC}")
    print("    Attacker attempts to guess the 128-bit PUF-derived key from a captured MAC.")
    
    # 1. capture a mac
    sock = get_sock()
    nonce = int(time.time() * 1000) & ((1 << 64) - 1)
    ts = int(time.time())
    challenge = struct.pack('>Q I', nonce, ts)
    sock.sendto(challenge, (TARGET_IP, TARGET_PORT))
    
    try:
        resp, _ = sock.recvfrom(512)
        mac_bytes = resp[:HMAC_TRUNC_BYTES]
        print(f"{Colors.CYAN}    [Captured Message Authentication Code]: {mac_bytes.hex()}{Colors.ENDC}")
    except:
        print(f"{Colors.FAIL}[-] Could not capture MAC from device.{Colors.ENDC}")
        return

    print(f"\n{Colors.BLUE}[*] Initializing offline Dictionary/Brute-force attack...{Colors.ENDC}")
    time.sleep(1)
    
    # Simulation loop
    keys_per_sec = 2_000_000_000 # 2 Billion tries/sec (high end GPU)
    key_space = 2**128
    
    print(f"    Target Key Size: 128 bits")
    print(f"    Search Space:    3.4 x 10^38 keys")
    print(f"    Speed:           {keys_per_sec/1e9} Billion keys/sec")
    
    print("\n    [>] Attempting keys...")
    for i in range(5):
        sys.stdout.write(f"\r    [>] Tested {i*500} Million keys...")
        sys.stdout.flush()
        time.sleep(0.3)
        
    print(f"\n{Colors.FAIL}    [!] FAILED to find key in reasonable time.{Colors.ENDC}")
    
    seconds = key_space / keys_per_sec
    years = seconds / (60*60*24*365)
    
    print(f"\n{Colors.GREEN}[✓] CONCLUSION: HMAC is Secure.{Colors.ENDC}")
    print(f"    At this rate, it would take approx {years:.2e} YEARS to crack the key.")

# --- Menu ---

import argparse

def main():
    parser = argparse.ArgumentParser(description='IoT Security Adversary Tool')
    parser.add_argument('--attack', choices=['replay', 'brute', 'crack'], 
                        help='Run a specific attack immediately without menu')
    args = parser.parse_args()

    if args.attack == 'replay':
        run_replay_attack()
        return
    elif args.attack == 'brute':
        run_brute_force_fuzzing()
        return
    elif args.attack == 'crack':
        run_hmac_cracking_sim()
        return

    while True:
        print_header()
        print("\nSelect Attack / Simulation:")
        print(f"  {Colors.BOLD}1.{Colors.ENDC} Run {Colors.WARNING}Replay Attack{Colors.ENDC} (Test Nonce+TS defense)")
        print(f"  {Colors.BOLD}2.{Colors.ENDC} Run {Colors.WARNING}Brute Force / Fuzzing{Colors.ENDC} (Test Stability)")
        print(f"  {Colors.BOLD}3.{Colors.ENDC} Analyze {Colors.WARNING}MAC Security{Colors.ENDC} (Crack Simulation)")
        print(f"  {Colors.BOLD}4.{Colors.ENDC} Exit")
        
        choice = input(f"\n{Colors.CYAN}adversary@{TARGET_IP}> {Colors.ENDC}")
        
        if choice == '1':
            run_replay_attack()
            input(f"\n{Colors.BLUE}[Press Enter to return to menu]{Colors.ENDC}")
        elif choice == '2':
            run_brute_force_fuzzing()
            input(f"\n{Colors.BLUE}[Press Enter to return to menu]{Colors.ENDC}")
        elif choice == '3':
            run_hmac_cracking_sim()
            input(f"\n{Colors.BLUE}[Press Enter to return to menu]{Colors.ENDC}")
        elif choice == '4':
            print("Exiting...")
            break
        else:
            print("Invalid selection.")
            time.sleep(1)

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n[!] Interrupted.")
