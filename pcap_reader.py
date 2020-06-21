#!/usr/bin/env python3
"""Script that reads packets of selected type from selected pcap file
   then displays the packets
"""

# import statements
from scapy.all import *
import os


def list_pcap_files():
    """Return a list of all files of type .pcap
    """
    pcap_list = []
    for root, dirs, files in os.walk("./pcap_files"):
        for file in files:
            if file.endswith(".pcap"):
                pcap_list.append(file)
    return pcap_list

def display_pcap_files(list):
    """Display the files in the list
    """
    length = len(list)
    print("There are ", length," files to choose from in: ", list)

    l = 0
    while l < length:
        print(l+1,":", list[l])
        l = l + 1

    return length

def select_pcap_file(length):
    """Select one of the listed files
       Default to DEFAULT_FILE
    """
    choice = 0

    while choice not in range(1, length+1):
        choice = input("Enter a number from list above to select the file: ")
        choice = int(choice)
    # need to add range and type checking        

    print("Selected:", choice)
    return choice


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

list = list_pcap_files()

length = display_pcap_files(list)

select_pcap_file(length)
