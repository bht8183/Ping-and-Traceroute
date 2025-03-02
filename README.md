# Ping and Traceroute

This repository contains two Python tools:
1. **my_ping.py** – A simplified clone of the `ping` utility using raw sockets.
2. **my_traceroute.py** – A simplified clone of the `traceroute` utility using raw sockets (ICMP/UDP).

---

## 1. Overview

These programs allow you to:
- Send ICMP ECHO_REQUEST packets to test network connectivity (`my_ping.py`).
- Discover the route packets take to reach a destination (`my_traceroute.py`).

Both programs were developed in Python 3, using raw sockets. Root or Administrator privileges are generally required to run raw socket programs.

---

## 2. Repository Contents

- **my_ping.py**: Main script for the ping functionality.
- **my_traceroute.py**: Main script for the traceroute functionality.
- **requirements.txt**: Python dependencies.
- **report.pdf**: Screenshots and report showcasing usage and results.
- **code_documentation.pdf**: Auto-generated PDF documentation from Sphinx
- **revisions.txt**: Contains the `git log` output showing commit history.

---

## 3. Installation and Setup

1. **Clone** the repository or download and extract the ZIP file.
2. **Install dependencies**:
   pip install -r requirements.txt

3. my_ping

python my_ping.py <destination> [options]
Options:

-c, --count <number>: Number of ECHO_REQUEST packets to send (e.g., -c 4).
-i, --interval <seconds>: Interval between sending each packet (default 1).
-s, --size <bytes>: Number of data bytes to be sent (default 56).
-t, --timeout <seconds>: Timeout in seconds before the program exits.

3. my_traceroute

python my_traceroute.py <destination> [options]
Options:

-n: Numeric output only, no reverse DNS lookups.
-q, --nqueries <number>: Number of probes per TTL (default 3).
-S: Print a summary of unanswered probes for each hop.
