#!/usr/bin/env python3

from scapy.all import *

# set default PCAP file to "pcap_files/pings.pcap"
PCAP_FILE = "pcap_files/pings.pcap"

# set default to read all packets in file
COUNT = -1

packets = rdpcap(PCAP_FILE, COUNT)

for p in packets:
    print(p.summary())

