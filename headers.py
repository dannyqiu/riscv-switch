#!/usr/bin/env python2
from scapy.all import get_if_list, bind_layers
from scapy.all import Packet, Raw
from scapy.all import IP
from scapy.fields import *


PROTO_RAW_PROGRAM = 0x8F
MAX_PROGRAM_LENGTH = 300

LOAD_BALANCER_IP = '255.255.255.255'
LOAD_BALANCER_MAC = 'ff:ff:ff:ff:ff:ff'

def get_if():
    ifs = get_if_list()
    iface = [i for i in get_if_list() if "eth0" in i]
    if not iface:
        print("Cannot find eth0 interface")
        exit(1)
    return iface[0]


class ProtoWrapper(Packet):
    name = 'ProtoWrapper'
    fields_desc = [
        BitField('max_steps', 0, 32),
    ]


class Registers(Packet):
    name = 'Registers'
    fields_desc = [
        IntField('r0', 0),
        IntField('r1', 0),
        IntField('r2', 0),
        IntField('r3', 0),
        IntField('r4', 0),
        IntField('r5', 0),
        IntField('r6', 0),
        IntField('r7', 0),
        IntField('r8', 0),
        IntField('r9', 0),
        IntField('r10', 0),
        IntField('r11', 0),
        IntField('r12', 0),
        IntField('r13', 0),
        IntField('r14', 0),
        IntField('r15', 0),
        IntField('r16', 0),
        IntField('r17', 0),
        IntField('r18', 0),
        IntField('r19', 0),
        IntField('r20', 0),
        IntField('r21', 0),
        IntField('r22', 0),
        IntField('r23', 0),
        IntField('r24', 0),
        IntField('r25', 0),
        IntField('r26', 0),
        IntField('r27', 0),
        IntField('r28', 0),
        IntField('r29', 0),
        IntField('r30', 0),
        IntField('r31', 0),
    ]


class Instruction(Packet):
    name = 'Instruction'
    fields_desc = [
        BitField('funct7', 0, 7),
        BitField('part1', 0, 5),
        BitField('part2', 0, 5),
        BitField('funct3', 0, 3),
        BitField('part3', 0, 5),
        BitField('opcode', 0, 7),
    ]


bind_layers(IP, ProtoWrapper)
bind_layers(ProtoWrapper, Registers)
bind_layers(Registers, Instruction)
bind_layers(Instruction, Instruction)
