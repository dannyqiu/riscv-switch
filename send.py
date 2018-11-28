#!/usr/bin/env python2
import sys
import socket

from scapy.all import sendp, send, get_if_list, get_if_hwaddr, bind_layers
from scapy.all import Packet, Raw
from scapy.all import Ether, IP, UDP
from scapy.fields import *
import readline

from headers import *


def main():
    iface = get_if()

    pkt = Ether(src=get_if_hwaddr(iface), dst=LOAD_BALANCER_MAC)
    pkt = pkt / IP(proto=PROTO_RAW_PROGRAM, dst=LOAD_BALANCER_IP)
    # Increase default recursion depth so scapy can handle longer programs
    sys.setrecursionlimit(10000)
    pkt = make_program(pkt, [
        AddI(dst=3, src=0, imm=42),
        Add(dst=0, src=0, target=0),
        # Sub(dst=0, src=0, target=0),
        # SubI(dst=0, src=0, imm=42),
        # Mul(dst=0, src=0, target=0),
        # MulI(dst=0, src=0, imm=42),
        # Div(dst=0, src=0, target=0),
        # DivI(dst=0, src=0, imm=42),
    ])
    hexdump(pkt)
    pkt.show2()
    sendp(pkt, iface=iface, verbose=False)


if __name__ == '__main__':
    main()
