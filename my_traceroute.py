import argparse
import socket
import struct
import time
import select
import sys
import platform


def parse_args():
    """
    Parse and return the command-line arguments.
    """
    parser = argparse.ArgumentParser(description='Custom traceroute utility')
    parser.add_argument('destination', help='Target hostname or IP')
    parser.add_argument('-n', action='store_true',
                        help='Numeric output only, no reverse DNS lookup')
    parser.add_argument('-q', '--nqueries', type=int, default=3,
                        help='Number of probes per TTL (default=3)')
    parser.add_argument('-S', action='store_true',
                        help='Show summary of unanswered probes per hop')
    return parser.parse_args()


def resolve_hostname(hostname):
    """
    Resolve a hostname to its IP address. Return the IP as a string.
    If resolution fails, print an error and exit.
    """
    try:
        return socket.gethostbyname(hostname)
    except socket.gaierror:
        print(f"traceroute: unknown host {hostname}")
        sys.exit(1)


def reverse_dns_lookup(ip_address):
    """
    Attempt a reverse DNS lookup of the given IP address, returning
    either the resolved hostname or the IP if resolution fails.
    """
    try:
        return socket.gethostbyaddr(ip_address)[0]
    except socket.herror:
        return ip_address


def main():
    args = parse_args()

    MAX_HOPS = 30               # typical traceroute default
    TIMEOUT_PER_PROBE = 3.0     # seconds to wait for each probe
    BASE_UDP_PORT = 33434       # typical starting port for traceroute

    destination_ip = resolve_hostname(args.destination)
    print(f"traceroute to {args.destination} ({destination_ip}), "
          f"{MAX_HOPS} hops max, {args.nqueries} probes per hop")

    # On Windows, using IPPROTO_IP for setting TTL often avoids "invalid argument" errors.
    # On Linux/Mac, SOL_IP is typically fine.
    if platform.system().lower().startswith('win'):
        IP_TTL_LEVEL = socket.IPPROTO_IP
    else:
        IP_TTL_LEVEL = socket.SOL_IP

    # Create a raw socket for receiving ICMP messages
    try:
        icmp_sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
        icmp_sock.settimeout(TIMEOUT_PER_PROBE)
    except PermissionError:
        print("Error: Insufficient privileges to create raw socket. Run as Administrator/root.")
        sys.exit(1)

    unanswered_counts = {}  # If -S is used, keep track of unanswered probes at each hop

    reached_destination = False
    for ttl in range(1, MAX_HOPS + 1):
        print(f"{ttl:2d} ", end='', flush=True)

        hop_ips = []   # track distinct IP addresses that reply at this TTL
        rtt_list = []  # store round-trip times for each reply
        lost_this_hop = 0

        for probe_index in range(args.nqueries):
            # Create a UDP socket for each probe
            send_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)

            # Attempt to set the TTL. On Windows, use IPPROTO_IP. On Linux/Mac, use SOL_IP.
            # If the TTL is invalid or if there's a platform issue, you may see WinError 10022.
            try:
                send_sock.setsockopt(IP_TTL_LEVEL, socket.IP_TTL, ttl)
            except OSError as e:
                print(f"\nError setting socket TTL: {e}")
                send_sock.close()
                return  # bail out of the program or handle gracefully

            send_sock.bind(("", 0))  # ephemeral source port
            send_time = time.time()

            # Send an empty UDP packet to a port unlikely to be open
            dest_port = BASE_UDP_PORT + ttl
            try:
                send_sock.sendto(b'', (destination_ip, dest_port))
            except Exception as e:
                print(f"\nError sending probe: {e}")
                send_sock.close()
                break

            # Now wait for an ICMP response
            addr = None
            icmp_type = None
            icmp_code = None

            try:
                packet, addr_info = icmp_sock.recvfrom(1024)
                rcv_time = time.time()

                addr = addr_info[0]
                # ICMP header starts at byte 20 (assuming no IP options)
                icmp_header = packet[20:28]
                icmp_type, icmp_code, _, _, _ = struct.unpack('!BBHHH', icmp_header)

                rtt_ms = (rcv_time - send_time) * 1000
                rtt_list.append(rtt_ms)

                if addr not in hop_ips:
                    hop_ips.append(addr)

            except socket.timeout:
                lost_this_hop += 1
                pass
            finally:
                send_sock.close()

        # Output for this hop
        if hop_ips:
            # If the user does not want numeric-only, try reverse DNS
            hop_labels = []
            for ip in hop_ips:
                if args.n:
                    hop_labels.append(ip)
                else:
                    # Attempt reverse DNS
                    hostname = reverse_dns_lookup(ip)
                    if hostname == ip:
                        hop_labels.append(ip)
                    else:
                        hop_labels.append(f"{hostname} ({ip})")

            # Print the IP/host info
            print(" ".join(hop_labels), end=' ')

            # Print each RTT
            for rtt_ms in rtt_list:
                print(f"{rtt_ms:.3f} ms", end=' ')
            print()  # newline

        else:
            # No IP resolved => all probes timed out for this TTL
            print("* * *")

        if args.S:
            unanswered_counts[ttl] = lost_this_hop

        # If we got an ICMP "destination unreachable" (type=3) from the actual target IP,
        # it's likely we've reached the final destination. Typically code=3 means "Port Unreachable."
        if hop_ips and (destination_ip in hop_ips) and (icmp_type == 3):
            reached_destination = True
            break

    # End of loop
    if args.S:
        print("\nSummary of unanswered probes per hop:")
        for hop_ttl in sorted(unanswered_counts.keys()):
            print(f"  TTL={hop_ttl}: {unanswered_counts[hop_ttl]} unanswered out of {args.nqueries}")

    if reached_destination:
        pass  # We ended early because we arrived
    else:
        pass  # Possibly we reached MAX_HOPS without getting an explicit port-unreachable
        # or the final host never responded
        

if __name__ == '__main__':
    main()