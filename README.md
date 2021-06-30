# pcap_modifier
This script will take a source pcap file and modify it to more closely match your example network's environment.
The idea is to take a "common" pcap file that might showcase a particular pattern of traffic (for things like profiling
traffic or devices).

# How to use
1. Install python packages via requirements.txt file.
1. Run runme.py either taking the defaults or passing variable changes via CLI.

The result will be a new pcap file with your modified parameters.
