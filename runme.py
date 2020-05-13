#!/usr/bin/env python3

from scapy.all import *
#from scapy.utils import PcapWriter
from random import randint, choice
import os

# User modifiable variables
num_loops = 10
source_pcap_dir = 'pcaps'
source_pcap_filename = 'DCS_for_PoVf.pcap'
dest_pcap_dir = '.'
dest_pcap_filename = 'DCS_for_PoV_v4.pcap'
source_subnet = '100.100.1.'
dest_subnet = '100.100.2.'

# create packet list
packets = []

# List of known/supported MAC OUIs
oui_list = [
'00:18:85',
'00:40:8c',
'AC:CC:8E',
'00:01:31',
'00:04:63',
'00:10:17',
'00:1B:86',
'00:1C:44',
'00:07:5F',
'4C:11:BF',
'90:02:A9',
'00:09:18',
'44:19:B6',
'C0:56:E3',
'00:01:4A',
'00:13:A9',
'00:1A:80',
'00:1D:BA',
'00:24:BE',
'08:00:46',
'30:F9:ED',
'3C:07:71',
'54:42:49',
'54:53:ED',
'78:84:3C',
'D8:D4:3C',
'F0:BF:97',
'FC:F1:52',
'00:0a:95',
'00:1A:E3',
'00:21:B7',
'00:50:56',
'48:60:BC',
'48:47:6E',
'70:01:B5',
'88:1D:FC',
'90:8D:78',
'A0:F2:17',
'B4:96:91',
]


def main():
    source_pcap_file = os.path.join(source_pcap_dir, source_pcap_filename)
    dest_pcap_file = os.path.join(dest_pcap_dir, dest_pcap_filename)
    i = 0
    while i < num_loops:
        # Build a list of source info for our packets
        source_packet_info = []
        for ip in range(1,255):
            full_ip = f"{source_subnet}{ip}"
            full_mac = f"{choice(oui_list)}:" \
                       f"{choice('0123456789abcdef')}{choice('0123456789abcdef')}:" \
                       f"{choice('0123456789abcdef')}{choice('0123456789abcdef')}:" \
                       f"{choice('0123456789abcdef')}{choice('0123456789abcdef')}"
            source_packet_info.append({ 'ip': full_ip, 'mac': full_mac})

        # Build a list of dest info for our packets
        dest_packet_info = []
        for ip in range(1,255):
            full_ip = f"{dest_subnet}{ip}"
            full_mac = f"{choice(oui_list)}:" \
                       f"{choice('0123456789abcdef')}{choice('0123456789abcdef')}:" \
                       f"{choice('0123456789abcdef')}{choice('0123456789abcdef')}:" \
                       f"{choice('0123456789abcdef')}{choice('0123456789abcdef')}"
            dest_packet_info.append({ 'ip': full_ip, 'mac': full_mac})

        # custom action function
        def customAction(packet):
            if packet[IP].src != '0.0.0.0' and packet[IP].src != '255.255.255.255':
                src_info = choice(source_packet_info)
                packet[IP].src = src_info['ip']
                packet[Ether].src = src_info['mac']
            if packet[IP].dst != '0.0.0.0' and packet[IP].dst != '255.255.255.255':
                dst_info = choice(dest_packet_info)
                packet[IP].dst = dst_info['ip']
                packet[Ether].dst = dst_info['mac']

        for sniffed_packet in sniff(offline=source_pcap_file, prn=customAction):
            #print(sniffed_packet.summary())
            packets.append(sniffed_packet)

        i += 1

    wrpcap(dest_pcap_file, packets)


if __name__ == "__main__":
    main()
