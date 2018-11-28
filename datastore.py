#!/usr/bin/env python2
import sys
import struct

from scapy.all import sniff, sendp, hexdump, get_if_list, get_if_hwaddr, bind_layers, split_layers
from scapy.all import Packet
from scapy.all import IP, UDP, Raw, Ether
from scapy.fields import *

from headers import *


def handle_pkt(pkt):
    hexdump(pkt)
    pkt.show2()
    sys.stdout.flush()


def main():
    iface = get_if()
    print "sniffing on %s" % iface
    sys.stdout.flush()
    sniff(filter="dst host {}".format(DATASTORE_IP), iface=iface, prn=handle_pkt)


if __name__ == '__main__':
    main()
