#!/usr/bin/env python2
import sys
import socket

from scapy.all import sendp, send, get_if_list, get_if_hwaddr, bind_layers
from scapy.all import Packet, Raw
from scapy.all import Ether, IP, UDP
from scapy.fields import *
import readline

from headers import *


iface = get_if()


def load_request(mem_namespace, address, register, execution_node):
    pkt = Ether(src=get_if_hwaddr(iface), dst=DATASTORE_MAC)
    pkt = pkt / IP(proto=PROTO_LOAD_REQUEST, dst=DATASTORE_IP)
    pkt /= LoadRequestMetadata(address=address, register=register, execution_node=execution_node)
    pkt /= ProgramExecutionMetadata(mem_namespace=mem_namespace)
    pkt /= ProgramMetadata(max_steps=1000)
    pkt /= Registers()
    pkt /= EndOfProgram()
    return pkt


def store_request(mem_namespace, address, value, execution_node):
    pkt = Ether(src=get_if_hwaddr(iface), dst=DATASTORE_MAC)
    pkt = pkt / IP(proto=PROTO_STORE_REQUEST, dst=DATASTORE_IP)
    pkt /= StoreRequestMetadata(address=address, value=value, execution_node=execution_node)
    pkt /= ProgramExecutionMetadata(mem_namespace=mem_namespace)
    pkt /= ProgramMetadata(max_steps=1000)
    pkt /= Registers()
    pkt /= EndOfProgram()
    return pkt


def main():
    pkt = store_request(0xdeadbeef, 4, 1337, 0)
    hexdump(pkt)
    pkt.show2()
    sendp(pkt, iface=iface, verbose=False)
    pkt = load_request(0xdeadbeef, 4, 5, 0)
    hexdump(pkt)
    pkt.show2()
    sendp(pkt, iface=iface, verbose=False)


if __name__ == '__main__':
    main()
