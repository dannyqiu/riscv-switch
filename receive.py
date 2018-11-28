#!/usr/bin/env python2
import sys
import struct

from scapy.all import sniff, hexdump
from scapy.fields import *

from headers import *


def handle_pkt(pkt):
    hexdump(pkt)
    pkt.show2()
    sys.stdout.flush()


def main():
    iface = get_if()
    print("sniffing on {}".format(iface))
    sys.stdout.flush()
    sniff(filter="src host {}".format(LOAD_BALANCER_IP), iface=iface, prn=handle_pkt)


if __name__ == '__main__':
    main()
