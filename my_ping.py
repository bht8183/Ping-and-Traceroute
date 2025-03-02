"""
my_ping.py

Custom ping util that sends ICMP Echo Requests and listens for ICMP Echo Replies.
Basic functionality:

Options:
  -c COUNT        Number of ECHO_REQUEST packets to send.
  -i INTERVAL     Seconds to wait between sending each packet. Set the default to 1.
  -s SIZE         Number of data bytes to send. The default is 56.
  -t TIMEOUT      Max time in seconds before exit.
Usage:
  python my_ping.py <dest> [options]

Ex:
  python my_ping.py google.com -c 4 -i 1 -s 56 -t 10
"""

import argparse
import socket
import struct
import time
import os
import select
import sys

def parse_args():
    """
    Parse and return the command-line arguments.
    """
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
    """
    Create a raw socket for sending and receiving ICMP packets.

    :return: A raw socket bound to IPPROTO_ICMP.
    :raises: Exception if user lacks permissions to create raw socket.
    """
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
        
    except PermissionError:
        raise Exception("access privileges not met")
    return s

def checksum(source_bytes):
    """
    Compute Internet Checksum of supplied data.
    The data is as 16-bit words. A ones complement is done at the end btw.

    :param: The bytes that need a checksum.
    :return: 16-bit computed checksum (as an int).
    """
    if len(source_bytes) % 2: # If the total length is odd, pad with one zero byte
        source_bytes += b'\x00'
    csum = 0
    count = 0
     
    # Sum all 16-bit words
    while count < len(source_bytes):
        # Combine two adjacent bytes into 16-bit word
        this_val = (source_bytes[count + 1] << 8) + source_bytes[count]
        csum += this_val
        csum = (csum & 0xffff) + (csum >> 16) # carry around
        count += 2
    csum = ~csum & 0xffff
    return csum

def build_icmp_packet(identifier, sequence, packet_size):
    """
    Build an ICMP Echo Request packet with a given identifier,
    sequence number, and payload size.

    :param identifier: ICMP packet identifier
    :param sequence: current sequence number
    :param packet_size: number of bytes to include in payload (exclude ICMP header)
    :return: A bytes object containing the entire ICMP packet
    """
    header = struct.pack('!BBHHH', 8, 0, 0, identifier, sequence) # Start with a dummy checksum of 0
    # Create payload.
    data = b'Q' * packet_size  # or any arbitrary data
     # Compute checksum over the header + data
    packet_chksum = checksum(header + data)
    # Pack with real checksum in network-byte order
    header = struct.pack('!BBHHH', 8, 0, socket.htons(packet_chksum), identifier, sequence)
    # Final packet = header + payload
    return header + data

def send_icmp_request(sock, dest_addr, identifier, sequence, packet_size):
    """
    Send an ICMP Echo Request through the provided raw socket.

    :param sock: The raw socket created for ICMP communication.
    :param dest_addr: The IP address of the destination.
    :param identifier: The ICMP identifier.
    :param sequence: The sequence number for request.
    :param packet_size: Number of data bytes to include in the ICMP payload.
    :return: The time when the packet was sent.
    """
    packet = build_icmp_packet(identifier, sequence, packet_size) # Build the packet
    sock.sendto(packet, (dest_addr, 0)) # Send to the destination on ICMP protocol (port=0 is typical for raw)
    return time.time()  # record time sent

def receive_icmp_reply(sock, identifier, timeout):
    """
    Listen for an ICMP Echo Reply that matches the given identifier.
    Returns None if times out.

    :param sock: The raw socket to listen on.
    :param identifier: Our ICMP identifier to match for replies.
    :param timeout: How long to wait for reply.
    :return: if successful, else (None, 0).
    """
    # Use select for the timeout
    start_select = time.time()
    while True:
        # Remaining time left for this listen
        remaining_time = timeout - (time.time() - start_select)
        if remaining_time <= 0:
            return None, 0
        
        # Use select to wait until socket is readable or the timeout expires
        ready = select.select([sock], [], [], remaining_time)
        if ready[0] == []:
            return None, 0  # timeout
        time_received = time.time()
        packet, addr = sock.recvfrom(1024)
        
        # The IP header is typically 20 bytes. The ICMP header starts at byte 20.
        icmp_header = packet[20:28]
        icmp_type, icmp_code, icmp_chksum, icmp_id, icmp_seq = struct.unpack('!BBHHH', icmp_header)

        # Check if this is the reply to our request
        if icmp_id == identifier:
            # Return the source address and the time we received the reply
            return addr, time_received
        


def main():
    """
    Main function that orchestrates the flow
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

    # Print some initial info like
    print(f"PING {args.destination} ({dest_ip}) {args.size}({args.size+8}) bytes of data.")

    # Create the raw socket
    try:
        sock = create_socket()
    except Exception as e:
        print(e)
        sys.exit(1)

    # Use the process ID as the ICMP packet identifier
    pid = os.getpid() & 0xFFFF

    # Stats
    packets_sent = 0
    packets_received = 0
    rtt_list = []

    # Keep track of the time we started pinging
    start_time = time.time()

    # If we have a count then we loop up to that
    # Else keep going until timeout
    sequence = 1  # ICMP sequence number start

    try:
        while True:
            # If overall timeout is specified, if so check if we exceeded it
            if args.timeout is not None:
                elapsed = time.time() - start_time
                if elapsed > args.timeout:
                    break  # we hit the overall timeout

            # Send one ICMP Echo Request
            send_time = send_icmp_request(sock, dest_ip, pid, sequence, args.size)
            packets_sent += 1

            # Wait for a reply. I decided to give it 2 seconds.
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

            # If user specified count -c, stop once we sent that many
            if args.count is not None and packets_sent >= args.count:
                break

            # Wait the interval
            if args.timeout is not None:
                # If next send would exceed overall timeout, break out
                if (time.time() - start_time) + args.interval > args.timeout:
                    break

            # Sleep specified interval before sending the next packet
            time.sleep(args.interval)

    except KeyboardInterrupt:
        # If Ctrl+C isp ressed, break from the loop
        print("\nKeyboard interrupt received, stopping now.")
    finally:
        # Print statistics
        print()
        print(f"--- {args.destination} ping statistics ---")
        print(f"{packets_sent} packets transmitted, {packets_received} received, "
              f"{(packets_sent - packets_received) / packets_sent * 100:.0f}% packet loss")

        # RTT stats
        if rtt_list:
            min_rtt = min(rtt_list)
            max_rtt = max(rtt_list)
            avg_rtt = sum(rtt_list) / len(rtt_list)
            mdev = (sum([(x - avg_rtt)**2 for x in rtt_list]) / len(rtt_list))**0.5
            print(f"rtt min/avg/max/mdev = {min_rtt:.3f}/{avg_rtt:.3f}/{max_rtt:.3f}/{mdev:.3f} ms")


if __name__ == '__main__':
    main()