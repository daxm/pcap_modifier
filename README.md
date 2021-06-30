# pcap_modifier
This script will take a source pcap file and modify it to more closely match your example network's environment.
The idea is to take a "common" pcap file that might showcase a particular pattern of traffic (for things like profiling
traffic or devices).

## How to use
1. Install python packages via requirements.txt file: `pip install -r requriements.txt`
1. Run pcap_modifier.py either taking the defaults or passing variable changes via CLI: `./pcap_modifier.py -h`

The result will be a new pcap file with your modified parameters.

##  Docker how to use
1.  Build docker container: `docker build .`
1.  asdf
1.  asdf
1.  asdf
