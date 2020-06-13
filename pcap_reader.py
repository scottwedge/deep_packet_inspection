#!/usr/bin/env python3
"""Script that reads packets of selected type from selected pcap file
   then displays the packets
"""

# import statements
from scapy.all import *


def list_pcap_files():
    """Return a list of all files of type .pcap
    """

def select_pcap_file():
    """Select one of the listed files
       Default to DEFAULT_FILE
    """


def list_packet_types():
    """Return list of packet types in the pcap file
    """

def select_packet_type():
    """Return one of the listed packet types
       If invalid entry, default to DEFAULT_TYPE
    """


# set default PCAP file to "pcap_files/pings.pcap"
PCAP_FILE = "pcap_files/pings.pcap"

# set default to read all packets in file
COUNT = -1

packets = rdpcap(PCAP_FILE, COUNT)

for p in packets:
    print(p.summary())
