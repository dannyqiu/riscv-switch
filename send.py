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
        AddI(dst=3, src=0, imm=-1),      # r3 = -1 (4294967295)
        Add(dst=4, src=1, target=1),     # r4 = 84
        Sub(dst=5, src=1, target=2),     # r5 = 11
        And(dst=6, src=1, target=2),     # r6 = 10
        Or(dst=7, src=1, target=2),      # r7 = 63
        Xor(dst=8, src=1, target=2),     # r8 = 53
        AndI(dst=9, src=1, imm=8),       # r9 = 8
        Slt(dst=10, src=3, target=2),    # r10 = 1
        Sltu(dst=11, src=2, target=3),   # r11 = 1
        Sra(dst=12, src=3, target=1),    # r12 = -1 (4294967295)
        Srl(dst=13, src=3, target=1),    # r13 = 4194303
        Sll(dst=14, src=1, target=1),    # r14 = 43008
        Mul(dst=15, src=1, target=2),    # r15 = 1302
        OrI(dst=16, src=1, imm=31),      # r16 = 63
        XorI(dst=17, src=1, imm=31),     # r17 = 53
        SltI(dst=18, src=3, imm=100),    # r18 = 1
        SltIu(dst=19, src=2, imm=-100),  # r19 = 1
        SraI(dst=20, src=3, imm=10),     # r20 = -1 (4294967295)
        SrlI(dst=21, src=3, imm=14),     # r21 = 262143
        SllI(dst=22, src=1, imm=5),      # r22 = 1344
        Lui(dst=23, imm=0xabcde),        # r23 = 2882396160
        Auipc(dst=24, imm=0xabcde),      # r23 = 2882396252
    ])
    hexdump(pkt)
    pkt.show2()
    sendp(pkt, iface=iface, verbose=False)


if __name__ == '__main__':
    main()
