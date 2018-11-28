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

    pkt = Ether(src=get_if_hwaddr(iface), dst=DATASTORE_MAC)
    pkt = pkt / IP(proto=PROTO_STORE_REQUEST, dst=DATASTORE_IP)
    pkt /= StoreRequestMetadata(address=0, value=1337, execution_node=0)
    pkt /= ProgramExecutionMetadata()
    pkt /= ProgramMetadata(max_steps=1000)
    pkt /= Registers()
    pkt /= AddI(dst=3, src=0, imm=42)
    pkt /= Add(dst=0, src=0, target=0)
    pkt /= EndOfProgram()
    # Increase default recursion depth so scapy can handle longer programs
    sys.setrecursionlimit(10000)
    hexdump(pkt)
    pkt.show2()
    sendp(pkt, iface=iface, verbose=False)


if __name__ == '__main__':
    main()
