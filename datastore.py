#!/usr/bin/env python2
import sys
import struct
from collections import defaultdict

from scapy.all import sniff, sendp, hexdump, get_if_list, get_if_hwaddr, bind_layers, split_layers
from scapy.all import Packet
from scapy.all import IP, UDP, Raw, Ether
from scapy.fields import *

from headers import *


iface = get_if()
memory = defaultdict(lambda: defaultdict(int))


def send_reply(pkt):
    pkt[IP].dst = pkt[IP].src
    pkt[IP].src = DATASTORE_IP
    pkt[Ether].dst = pkt[Ether].src
    pkt[Ether].src = DATASTORE_MAC
    sendp(pkt, iface=iface, verbose=False)


def handle_pkt(pkt):
    pkt.show2()
    proto = pkt[IP].proto
    if proto == PROTO_STORE_REQUEST:
        # Apply store request
        mem_namespace = pkt[ProgramExecutionMetadata].mem_namespace
        store_request_metadata = pkt[StoreRequestMetadata]
        memory[mem_namespace][store_request_metadata.address] = store_request_metadata.value
        print("Store: mem[{}][{}] <- {}".format(mem_namespace, store_request_metadata.address,
                                               store_request_metadata.value))
        send_reply(pkt)
    elif proto == PROTO_LOAD_REQUEST:
        # Apply load request
        mem_namespace = pkt[ProgramExecutionMetadata].mem_namespace
        load_request_metadata = pkt[LoadRequestMetadata]
        value = memory[mem_namespace][load_request_metadata.address]
        print("Load: mem[{}][{}] -> {}".format(mem_namespace, load_request_metadata.address, value))
        # Replace load request header with load response header
        program_packet = pkt[ProgramExecutionMetadata]
        pkt[IP].remove_payload()
        pkt /= LoadResponseMetadata(value=value, register=load_request_metadata.register,
                                    execution_node=load_request_metadata.execution_node) / program_packet
        pkt[IP].proto = PROTO_LOAD_RESPONSE
        send_reply(pkt)
    else:
        print("Received packet with unexpected protocol: {}".format(proto))
    sys.stdout.flush()


def main():
    print("sniffing on {}".format(iface))
    sys.stdout.flush()
    sniff(filter="dst host {}".format(DATASTORE_IP), iface=iface, prn=handle_pkt)


if __name__ == '__main__':
    main()
