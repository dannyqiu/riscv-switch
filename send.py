#!/usr/bin/env python3
import sys
import socket

from scapy.all import sendp, send, get_if_list, get_if_hwaddr, bind_layers
from scapy.all import Packet, Raw
from scapy.all import Ether, IP, UDP
from scapy.fields import *
import readline


PROTO_PROGRAM = 0x00
PROTOCOL_PORT = 4321
MAX_PROGRAM_LENGTH = 350


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
        IPField('src', '127.0.0.1'),
        BitField('mem_namespace', 0, 32),
        BitField('type', PROTO_PROGRAM, 8),
        BitField('steps', 0, 12),
        BitField('max_steps', 0, 12),
    ]


class Instruction(Packet):
    name = 'Instruction'
    fields_desc = [
        BitField('bos', 0, 1),
        BitField('opcode', 0, 7),
        BitField('dst', 0, 4),
        BitField('src', 0, 4),
        BitField('target', 0, 4),
        BitField('imm', 0, 12),
    ]


bind_layers(UDP, ProtoWrapper, dport=PROTOCOL_PORT)
bind_layers(ProtoWrapper, Instruction, type=PROTO_PROGRAM)
bind_layers(Instruction, Instruction, )


def AddI(dst=0, src=0, imm=0, **kwargs):
    return Instruction(opcode=0b0000000, dst=dst, src=src, target=(imm >> 12), imm=(0x0FFF & imm), **kwargs)


def Add(dst=0, src=0, target=0, **kwargs):
    return Instruction(opcode=0b1000000, dst=dst, src=src, target=target, **kwargs)


def SubI(dst=0, src=0, imm=0, **kwargs):
    return Instruction(opcode=0b0000001, dst=dst, src=src, target=(imm >> 12), imm=(0x0FFF & imm), **kwargs)


def Sub(dst=0, src=0, target=0, **kwargs):
    return Instruction(opcode=0b1000001, dst=dst, src=src, target=target, **kwargs)


def MulI(dst=0, src=0, imm=0, **kwargs):
    return Instruction(opcode=0b0000010, dst=dst, src=src, target=(imm >> 12), imm=(0x0FFF & imm), **kwargs)


def Mul(dst=0, src=0, target=0, **kwargs):
    return Instruction(opcode=0b1000010, dst=dst, src=src, target=target, **kwargs)


def DivI(dst=0, src=0, imm=0, **kwargs):
    return Instruction(opcode=0b0000011, dst=dst, src=src, target=(imm >> 12), imm=(0x0FFF & imm), **kwargs)


def Div(dst=0, src=0, target=0, **kwargs):
    return Instruction(opcode=0b1000011, dst=dst, src=src, target=target, **kwargs)


def SllI(dst=0, src=0, imm=0, **kwargs):
    return Instruction(opcode=0b0000100, dst=dst, src=src, imm=(0b11111 & imm), **kwargs)


def Sll(dst=0, src=0, target=0, **kwargs):
    return Instruction(opcode=0b1000100, dst=dst, src=src, target=target, **kwargs)


def SrlI(dst=0, src=0, imm=0, **kwargs):
    return Instruction(opcode=0b0000110, dst=dst, src=src, imm=(0b11111 & imm), **kwargs)


def Srl(dst=0, src=0, target=0, **kwargs):
    return Instruction(opcode=0b1000110, dst=dst, src=src, target=target, **kwargs)


def SraI(dst=0, src=0, imm=0, **kwargs):
    return Instruction(opcode=0b0000111, dst=dst, src=src, imm=(0b11111 & imm), **kwargs)


def Sra(dst=0, src=0, target=0, **kwargs):
    return Instruction(opcode=0b1000111, dst=dst, src=src, target=target, **kwargs)


def AndI(dst=0, src=0, imm=0, **kwargs):
    return Instruction(opcode=0b0001000, dst=dst, src=src, target=(imm >> 12), imm=(0x0FFF & imm), **kwargs)


def And(dst=0, src=0, target=0, **kwargs):
    return Instruction(opcode=0b1001000, dst=dst, src=src, target=target, **kwargs)


def OrI(dst=0, src=0, imm=0, **kwargs):
    return Instruction(opcode=0b0001001, dst=dst, src=src, target=(imm >> 12), imm=(0x0FFF & imm), **kwargs)


def Or(dst=0, src=0, target=0, **kwargs):
    return Instruction(opcode=0b1001001, dst=dst, src=src, target=target, **kwargs)


def XorI(dst=0, src=0, imm=0, **kwargs):
    return Instruction(opcode=0b0001010, dst=dst, src=src, target=(imm >> 12), imm=(0x0FFF & imm), **kwargs)


def Xor(dst=0, src=0, target=0, **kwargs):
    return Instruction(opcode=0b1001010, dst=dst, src=src, target=target, **kwargs)


def MovI(dst=0, src=0, imm=0, **kwargs):
    return Instruction(opcode=0b0001100, dst=dst, src=src, target=(imm >> 12), imm=(0x0FFF & imm), **kwargs)


def Mov(dst=0, src=0, target=0, **kwargs):
    return Instruction(opcode=0b1001100, dst=dst, src=src, target=target, **kwargs)


def Movz(dst=0, src=0, target=0, **kwargs):
    return Instruction(opcode=0b1001101, dst=dst, src=src, target=target, **kwargs)


def Movn(dst=0, src=0, target=0, **kwargs):
    return Instruction(opcode=0b1001110, dst=dst, src=src, target=target, **kwargs)


def SwI(dst=0, src=0, imm=0, **kwargs):
    return Instruction(opcode=0b0010000, dst=dst, src=src, target=(imm >> 12), imm=(0x0FFF & imm), **kwargs)


def Sw(dst=0, src=0, target=0, **kwargs):
    return Instruction(opcode=0b1010000, dst=dst, src=src, target=target, **kwargs)


def Lw(dst=0, src=0, target=0, **kwargs):
    return Instruction(opcode=0b1011000, dst=dst, src=src, target=target, **kwargs)




def make_program(pkt, insns: [Instruction]):
    pkt /= ProtoWrapper(type=PROTO_PROGRAM, src=IP().src, max_steps=0xFFFF)
    assert len(insns) < MAX_PROGRAM_LENGTH
    for idx, insn in enumerate(insns):
        if idx == len(insns) - 1:
            insn.bos = 1
        else:
            insn.bos = 0
        pkt /= insn
    return pkt


def main():
    if len(sys.argv) < 2:
        print('usage: send.py <destination>')
        exit(1)

    iface = get_if()
    addr = socket.gethostbyname(sys.argv[1])

    pkt = Ether(src=get_if_hwaddr(iface), dst='ff:ff:ff:ff:ff:ff');
    pkt = pkt / IP(dst=addr)
    pkt = pkt / UDP(sport=1234, dport=PROTOCOL_PORT)
    # Increase default recursion depth so scapy can handle longer programs
    sys.setrecursionlimit(10000)
    pkt = make_program(pkt, [
        Add(dst=0, src=0, target=0),
        AddI(dst=0, src=0, imm=42),
        Sub(dst=0, src=0, target=0),
        SubI(dst=0, src=0, imm=42),
        Mul(dst=0, src=0, target=0),
        MulI(dst=0, src=0, imm=42),
        Div(dst=0, src=0, target=0),
        DivI(dst=0, src=0, imm=42),
    ])
    hexdump(pkt)
    pkt.show2()
    sendp(pkt, iface=iface, verbose=False)


if __name__ == '__main__':
    main()
