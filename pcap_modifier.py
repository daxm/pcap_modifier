#!/usr/bin/env python3
"""From a source PCAP file modify the IP/MAC information to better suit your example network."""

from scapy.all import *

# from scapy.utils import PcapWriter
from random import choice, getrandbits
import os
from ipaddress import IPv4Network, IPv4Address
import typing
import argparse

# User modifiable variables
num_loops: int = 10
source_pcap_dir: str = "."
source_pcap_filename: str = "infile.pcap"
dest_pcap_dir: str = "pcap_modifier"
dest_pcap_filename: str = "outfile.pcap"
source_subnet: str = "100.100.111.0/24"
dest_subnet: str = "100.100.222.0/24"

parser = argparse.ArgumentParser()
parser.add_argument(
    "-m",
    "--multiplier",
    help="Number of times to loop through the pcap.",
    type=int,
    default=num_loops,
)
parser.add_argument(
    "-i",
    "--infile",
    help="Source pcap file.",
    default=os.path.join(source_pcap_dir, source_pcap_filename),
)
parser.add_argument(
    "-o",
    "--outfile",
    help="Destination file to write new pcap file.",
    default=os.path.join(dest_pcap_dir, dest_pcap_filename),
)
parser.add_argument(
    "-s",
    "--source",
    help="Source subnet X.X.X.X/X for PCAP alteration.",
    default=source_subnet,
)
parser.add_argument(
    "-d",
    "--destination",
    help="Destination subnet X.X.X.X/X for PCAP alteration.",
    default=dest_subnet,
)
parser.add_argument(
    "-v",
    "--verbose",
    help="Print output as packets are created.",
    action="store_true",
)
parser.parse_args()
args = parser.parse_args()

source_subnet = args.source
dest_subnet = args.destination
num_loops = args.multiplier
verbose = args.verbose

# List of known/supported MAC OUIs
oui_list: typing.List = [
    "00:18:85",
    "00:40:8c",
    "AC:CC:8E",
    "00:01:31",
    "00:04:63",
    "00:10:17",
    "00:1B:86",
    "00:1C:44",
    "00:07:5F",
    "4C:11:BF",
    "90:02:A9",
    "00:09:18",
    "44:19:B6",
    "C0:56:E3",
    "00:01:4A",
    "00:13:A9",
    "00:1A:80",
    "00:1D:BA",
    "00:24:BE",
    "08:00:46",
    "30:F9:ED",
    "3C:07:71",
    "54:42:49",
    "54:53:ED",
    "78:84:3C",
    "D8:D4:3C",
    "F0:BF:97",
    "FC:F1:52",
    "00:0a:95",
    "00:1A:E3",
    "00:21:B7",
    "00:50:56",
    "48:60:BC",
    "48:47:6E",
    "70:01:B5",
    "88:1D:FC",
    "90:8D:78",
    "A0:F2:17",
    "B4:96:91",
    "44:61:32",
]


def generate_ip(subnet: str = "192.168.1.0/24") -> str:
    """
    Generate an IP in provided subnet.
    :param subnet: Subnet where generated IP should source.
    :return: ip
    """
    sub_network = IPv4Network(subnet)
    bits = getrandbits(sub_network.max_prefixlen - sub_network.prefixlen)
    return str(IPv4Address(sub_network.network_address + bits))


def generate_mac(oui: str = "00:00:00") -> str:
    """
    Generate a MAC in with provided OUI.
    :param oui: OUI of generated MAC
    str:return: mac
    """
    return (
        f"{oui}:"
        f"{choice('0123456789abcdef')}{choice('0123456789abcdef')}:"
        f"{choice('0123456789abcdef')}{choice('0123456789abcdef')}:"
        f"{choice('0123456789abcdef')}{choice('0123456789abcdef')}"
    )


def modify_packet(this_packet) -> typing.NoReturn:
    """
    Modify scapy sniff "AKA customAction"
    :param this_packet: scapy Packet object
    :return: none
    """
    if "IP" in this_packet:
        if (
            this_packet[IP].src != "0.0.0.0"
            and this_packet[IP].src != "255.255.255.255"
        ):
            src_info = {
                "ip": generate_ip(source_subnet),
                "mac": generate_mac(choice(oui_list)),
            }
            this_packet[IP].src = src_info["ip"]
            this_packet[Ether].src = src_info["mac"]

        if (
            this_packet[IP].dst != "0.0.0.0"
            and this_packet[IP].dst != "255.255.255.255"
        ):
            dst_info = {
                "ip": generate_ip(dest_subnet),
                "mac": generate_mac(choice(oui_list)),
            }
            this_packet[IP].dst = dst_info["ip"]
            this_packet[Ether].dst = dst_info["mac"]
    else:
        if verbose:
            print("Not IPv4 packet.  Passing through unaltered.")


def main() -> typing.NoReturn:
    # create packet list
    packets = []
    # Run through the source pcap file num_loops times.  Generate "similar" traffic but with different ip/mac info.
    i = 0
    while i < num_loops:
        for sniffed_packet in sniff(offline=args.infile, prn=modify_packet):
            if args.verbose:
                print(sniffed_packet.summary())
            packets.append(sniffed_packet)
        i += 1
    if args.verbose:
        print(f"Writing new PCAP file to {args.outfile}.")
    wrpcap(args.outfile, packets)


if __name__ == "__main__":
    main()
