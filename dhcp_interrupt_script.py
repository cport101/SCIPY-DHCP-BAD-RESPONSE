#!/usr/bin/env python3

"""
MIT LICENSE

Copyright 2023  Charles Port

Permission is hereby granted, free of charge, to any person obtaining a copy of
this software and associated documentation files (the “Software”), to deal in
the Software without restriction, including without limitation the rights to
use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies
of the Software, and to permit persons to whom the Software is furnished to do
so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED “AS IS”, WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
"""

from scapy.all import *

####################
# VARS
####################
header_count = 0
ont_mac  = "cc:be:59:51:bc:00"
#ont_mac  = "7c:9f:07:49:d5:aa"
interface = "enp10s0"
global MY_MACADDR
global IP_GATEWAY
global ETH_INT
MY_MACADDR   = "52:54:00:4e:72:bd"
IP_GATEWAY  = "172.16.2.1"
ETH_INT    ="enp10s0"

####################
# FUNC. 0
####################
def sniffer(interface):
    """
    SNIFF
    Look for a mac address and then invoke invoke function II [send_icmp_unreachable]
    """
    #sniff(iface=interface,filter="dhcpDiscover", store=False, prn=process_packet)
    #sniff(iface=interface, filter='udp and (port 67 or port 68)', store=False, prn=send_icmp_unreachable)
    sniff(iface=interface, lfilter= lambda d: d.src == 'cc:be:59:51:bc:00', store=False, prn=send_icmp_unreachable)


####################
# FUNC. 1
####################
def icmp_code():
    """
    0   Net Unreachable [RFC792]
    1   Host Unreachable        [RFC792]
    2   Protocol Unreachalbe
    3   Port Unreachable        [RFC792]
    4   Fragmentation Needed and Don't Fragment was Set [RFC792]
    5   Source Route Failed     [RFC792]
    6   Destination Network Unknown     [RFC1122]
    7   Destination Host Unknown        [RFC1122]
    8   Source Host Isolated    [RFC1122]
    9   Communication with Destination Network is Administratively Prohibited   [RFC1122]
    10  Communication with Destination Host is Administratively Prohibited      [RFC1122]
    11  Destination Network Unreachable for Type of Service     [RFC1122]
    12  Destination Host Unreachable for Type of Service        [RFC1122]
    13  Communication Administratively Prohibited       [RFC1812]
    14  Host Precedence Violation       [RFC1812]
    15  Precedence cutoff in effect     [RFC1812]
    """
    global header_count
    ret = header_count % 15
    header_count += 1
    return ret


####################
# FUNC. 2
####################
def send_icmp_unreachable (packet):
    """SEND ICMP"""
    counter = 1
    RandomBool = True
    print("Ingress PDU\n")
    print(packet.show())
    print(packet[Ether].src)
    print(Ether().src)
    p = Ether(src=MY_MACADDR, dst=packet.src)/IP(src=IP_GATEWAY, dst=packet.getlayer(IP).src)
    # ICMP type=3 code=3 Port Unreachable
    icmp = ICMP()
    #icmp.type = 3
    #icmp.code = icmp_code()
    icmp.type = 11
    icmp.code = 0
    try:
        print("Outgoing icmp unreachable [udp]")
        # sendp(p/icmp/packet.getlayer (IP)/packet.getlayer (UDP), iface=ETH_INT)
        sendp(p/icmp/packet.getlayer (IP), iface=ETH_INT)
        p.show()
        icmp.show()
    except:
        print("outgoing icmp unreachable [tcp]")
        # sendp(p/icmp/packet.getlayer (IP)/packet.getlayer (TCP), iface=ETH_INT)
        sendp(p/icmp/packet.getlayer (IP), iface=ETH_INT)
        p.show()
        icmp.show()
    return

####################
# FUNC. 3 (MAIN)
####################
def main():
    """MAIN"""
    sniffer(interface)


if __name__ == '__main__':
    main()
