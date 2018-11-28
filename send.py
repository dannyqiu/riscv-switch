#!/usr/bin/env python2
import sys
import socket

from scapy.all import sendp, hexdump, get_if_hwaddr
from scapy.all import Ether, IP
from scapy.fields import *

from headers import *


def main():
    iface = get_if()

    pkt = Ether(src=get_if_hwaddr(iface), dst=LOAD_BALANCER_MAC)
    pkt = pkt / IP(proto=PROTO_RAW_PROGRAM, dst=LOAD_BALANCER_IP)
    # Increase default recursion depth so scapy can handle longer programs
    sys.setrecursionlimit(10000)
    pkt = make_program(pkt, [
        AddI(dst=1, src=0, imm=42),      # r1 = 42
        AddI(dst=2, src=0, imm=31),      # r2 = 31
        Add(dst=3, src=1, target=1),     # r3 = 84
        Sub(dst=4, src=3, target=1),     # r4 = 42
        And(dst=5, src=1, target=2),     # r5 = 10
        Or(dst=6, src=1, target=2),      # r6 = 63
        Xor(dst=7, src=1, target=2),     # r7 = 53
        AndI(dst=8, src=1, imm=8),       # r8 = 8
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
