import argparse
import socket
import struct
import time
import os
import select
import sys

def parse_args():
    parser = argparse.ArgumentParser(description='Custom ping utility')
    parser.add_argument('destination', help='Host to ping')
    parser.add_argument('-c', '--count', type=int, default=None,
                        help='Stop after sending count ECHO_REQUEST packets')
    parser.add_argument('-i', '--interval', type=float, default=1.0,
                        help='Wait interval seconds between sending each packet')
    parser.add_argument('-s', '--size', type=int, default=56,
                        help='Number of data bytes to be sent')
    parser.add_argument('-t', '--timeout', type=int, default=None,
                        help='Timeout in seconds before ping exits')
    return parser.parse_args()

def create_socket():
    # AF_INET (IPv4), SOCK_RAW (raw socket), IPPROTO_ICMP (ICMP protocol)
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
        
    except PermissionError:
        raise Exception("access privileges not met")
    return s

def checksum(source_bytes):
    # If the total length is odd, pad with one byte of zeros
    if len(source_bytes) % 2:
        source_bytes += b'\x00'
    csum = 0
    count = 0
    while count < len(source_bytes):
        this_val = (source_bytes[count + 1] << 8) + source_bytes[count]
        csum += this_val
        csum = (csum & 0xffff) + (csum >> 16)
        count += 2
    csum = ~csum & 0xffff
    return csum

def build_icmp_packet(identifier, sequence, packet_size):
    # Type=8 (echo), Code=0, Checksum=0 initially
    header = struct.pack('!BBHHH', 8, 0, 0, identifier, sequence)
    # payload of 'packet_size' bytes (the assignment says 56 by default, not counting the header)
    # Typically the entire packet is 64 bytes (8 bytes ICMP header + 56 bytes data)
    data = b'Q' * packet_size  # or any arbitrary data
    # Compute the checksum on the entire packet (header + data)
    packet_chksum = checksum(header + data)
    # Rebuild header with correct checksum
    header = struct.pack('!BBHHH', 8, 0, socket.htons(packet_chksum), identifier, sequence)
    return header + data

def send_icmp_request(sock, dest_addr, identifier, sequence, packet_size):
    packet = build_icmp_packet(identifier, sequence, packet_size)
    sock.sendto(packet, (dest_addr, 0))
    return time.time()  # record time sent

def receive_icmp_reply(sock, identifier, timeout):
    # Use select for the timeout
    start_select = time.time()
    while True:
        # If we have a global or dynamic timeout
        remaining_time = timeout - (time.time() - start_select)
        if remaining_time <= 0:
            return None, 0
        ready = select.select([sock], [], [], remaining_time)
        if ready[0] == []:
            return None, 0  # timeout
        time_received = time.time()
        packet, addr = sock.recvfrom(1024)
        # Parse the ICMP header (starting from IP header offset)
        icmp_header = packet[20:28]  # IP header is 20 bytes (assuming no IP options)
        icmp_type, icmp_code, icmp_chksum, icmp_id, icmp_seq = struct.unpack('!BBHHH', icmp_header)
        if icmp_id == identifier:
            return addr, time_received
        


def main():
    """
    Main function that orchestrates the flow:
      1) Parse arguments
      2) Resolve destination to IP
      3) Create raw socket
      4) Send/receive pings in a loop
      5) Print statistics and exit
    """
    args = parse_args()

    # Attempt to resolve the destination to an IP address
    try:
        dest_ip = socket.gethostbyname(args.destination)
    except socket.gaierror:
        print(f"ping: cannot resolve {args.destination}: Unknown host")
        sys.exit(2)

    # Print some initial info like the standard ping does
    print(f"PING {args.destination} ({dest_ip}) {args.size}({args.size+8}) bytes of data.")

    # Create the raw socket
    try:
        sock = create_socket()
    except Exception as e:
        print(e)
        sys.exit(1)

    # We will use the process ID as the ICMP packet identifier
    pid = os.getpid() & 0xFFFF

    # Statistics
    packets_sent = 0
    packets_received = 0
    rtt_list = []

    # Keep track of the time we started pinging
    start_time = time.time()

    # If we have a count (number of packets to send) we'll loop up to that
    # Otherwise we keep going until a timeout or keyboard interrupt (CTRL+C)
    sequence = 1  # ICMP sequence numbers typically start at 1

    try:
        while True:
            # If overall timeout is specified, check if we've exceeded it
            if args.timeout is not None:
                elapsed = time.time() - start_time
                if elapsed > args.timeout:
                    break  # we've hit the overall timeout

            # Send one ICMP Echo Request
            send_time = send_icmp_request(sock, dest_ip, pid, sequence, args.size)
            packets_sent += 1

            # Wait for a reply (we'll give each packet up to 2 seconds, for example)
            # You can adjust this receive timeout as you wish (often ping uses 1-2s).
            addr, receive_time = receive_icmp_reply(sock, pid, 2)
            if addr:
                # Calculate RTT in milliseconds
                rtt_ms = (receive_time - send_time) * 1000
                rtt_list.append(rtt_ms)
                packets_received += 1

                print(f"{len(build_icmp_packet(pid, sequence, args.size))} bytes from "
                      f"{addr[0]}: icmp_seq={sequence} time={rtt_ms:.3f} ms")
            else:
                print(f"Request timeout for icmp_seq {sequence}")

            sequence += 1

            # If user specified -c (count), stop once we've sent that many
            if args.count is not None and packets_sent >= args.count:
                break

            # Wait the interval (if it won't exceed overall timeout)
            if args.timeout is not None:
                # If next send would exceed overall timeout, we can break out
                if (time.time() - start_time) + args.interval > args.timeout:
                    break

            # Sleep the specified interval before sending the next packet
            time.sleep(args.interval)

    except KeyboardInterrupt:
        # If user hits Ctrl+C, we break from the loop
        print("\nKeyboard interrupt received, stopping ping.")
    finally:
        # Calculate and print statistics
        print()
        print(f"--- {args.destination} ping statistics ---")
        print(f"{packets_sent} packets transmitted, {packets_received} received, "
              f"{(packets_sent - packets_received) / packets_sent * 100:.0f}% packet loss")

        # RTT stats
        if rtt_list:
            min_rtt = min(rtt_list)
            max_rtt = max(rtt_list)
            avg_rtt = sum(rtt_list) / len(rtt_list)
            # Optional: compute a rudimentary mdev (mean deviation)
            mdev = (sum([(x - avg_rtt)**2 for x in rtt_list]) / len(rtt_list))**0.5
            print(f"rtt min/avg/max/mdev = {min_rtt:.3f}/{avg_rtt:.3f}/{max_rtt:.3f}/{mdev:.3f} ms")


if __name__ == '__main__':
    main()