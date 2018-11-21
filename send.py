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
MAX_PROGRAM_LENGTH = 300


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
        BitField('opcode', 0, 6),
        BitField('dst', 0, 5),
        BitField('src', 0, 5),
        BitField('target', 0, 5),
        BitField('imm', 0, 11),
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


bind_layers(UDP, ProtoWrapper, dport=PROTOCOL_PORT)
bind_layers(ProtoWrapper, Registers, type=PROTO_PROGRAM)
bind_layers(Registers, Instruction)
bind_layers(Instruction, Instruction)


def AddI(dst=0, src=0, imm=0, **kwargs):
    return Instruction(opcode=0b000000, dst=dst, src=src, target=(imm >> 11), imm=(0b11111111111 & imm), **kwargs)


def Add(dst=0, src=0, target=0, **kwargs):
    return Instruction(opcode=0b100000, dst=dst, src=src, target=target, **kwargs)


def SubI(dst=0, src=0, imm=0, **kwargs):
    return Instruction(opcode=0b000001, dst=dst, src=src, target=(imm >> 11), imm=(0b11111111111 & imm), **kwargs)


def Sub(dst=0, src=0, target=0, **kwargs):
    return Instruction(opcode=0b100001, dst=dst, src=src, target=target, **kwargs)


def MulI(dst=0, src=0, imm=0, **kwargs):
    return Instruction(opcode=0b000010, dst=dst, src=src, target=(imm >> 11), imm=(0b11111111111 & imm), **kwargs)


def Mul(dst=0, src=0, target=0, **kwargs):
    return Instruction(opcode=0b100010, dst=dst, src=src, target=target, **kwargs)


def DivI(dst=0, src=0, imm=0, **kwargs):
    return Instruction(opcode=0b000011, dst=dst, src=src, target=(imm >> 11), imm=(0b11111111111 & imm), **kwargs)


def Div(dst=0, src=0, target=0, **kwargs):
    return Instruction(opcode=0b100011, dst=dst, src=src, target=target, **kwargs)


def SllI(dst=0, src=0, imm=0, **kwargs):
    return Instruction(opcode=0b000100, dst=dst, src=src, imm=(0b11111 & imm), **kwargs)


def Sll(dst=0, src=0, target=0, **kwargs):
    return Instruction(opcode=0b100100, dst=dst, src=src, target=target, **kwargs)


def SrlI(dst=0, src=0, imm=0, **kwargs):
    return Instruction(opcode=0b000110, dst=dst, src=src, imm=(0b11111 & imm), **kwargs)


def Srl(dst=0, src=0, target=0, **kwargs):
    return Instruction(opcode=0b100110, dst=dst, src=src, target=target, **kwargs)


def SraI(dst=0, src=0, imm=0, **kwargs):
    return Instruction(opcode=0b000111, dst=dst, src=src, imm=(0b11111 & imm), **kwargs)


def Sra(dst=0, src=0, target=0, **kwargs):
    return Instruction(opcode=0b100111, dst=dst, src=src, target=target, **kwargs)


def AndI(dst=0, src=0, imm=0, **kwargs):
    return Instruction(opcode=0b001000, dst=dst, src=src, target=(imm >> 11), imm=(0b11111111111 & imm), **kwargs)


def And(dst=0, src=0, target=0, **kwargs):
    return Instruction(opcode=0b101000, dst=dst, src=src, target=target, **kwargs)


def OrI(dst=0, src=0, imm=0, **kwargs):
    return Instruction(opcode=0b001001, dst=dst, src=src, target=(imm >> 11), imm=(0b11111111111 & imm), **kwargs)


def Or(dst=0, src=0, target=0, **kwargs):
    return Instruction(opcode=0b101001, dst=dst, src=src, target=target, **kwargs)


def XorI(dst=0, src=0, imm=0, **kwargs):
    return Instruction(opcode=0b001010, dst=dst, src=src, target=(imm >> 11), imm=(0b11111111111 & imm), **kwargs)


def Xor(dst=0, src=0, target=0, **kwargs):
    return Instruction(opcode=0b101010, dst=dst, src=src, target=target, **kwargs)


def MovI(dst=0, src=0, imm=0, **kwargs):
    return Instruction(opcode=0b001100, dst=dst, src=src, target=(imm >> 11), imm=(0b11111111111 & imm), **kwargs)


def Mov(dst=0, src=0, target=0, **kwargs):
    return Instruction(opcode=0b101100, dst=dst, src=src, target=target, **kwargs)


def Movz(dst=0, src=0, target=0, **kwargs):
    return Instruction(opcode=0b101101, dst=dst, src=src, target=target, **kwargs)


def Movn(dst=0, src=0, target=0, **kwargs):
    return Instruction(opcode=0b101110, dst=dst, src=src, target=target, **kwargs)


def SwI(dst=0, src=0, imm=0, **kwargs):
    return Instruction(opcode=0b010000, dst=dst, src=src, target=(imm >> 11), imm=(0b11111111111 & imm), **kwargs)


def Sw(dst=0, src=0, target=0, **kwargs):
    return Instruction(opcode=0b110000, dst=dst, src=src, target=target, **kwargs)


def Lw(dst=0, src=0, target=0, **kwargs):
    return Instruction(opcode=0b110001, dst=dst, src=src, target=target, **kwargs)


def Beq(dst=0, src=0, imm=0, **kwargs):
    return Instruction(opcode=0b011000, dst=dst, src=src, imm=(0b11111111111 & imm), **kwargs)


def Bne(dst=0, src=0, imm=0, **kwargs):
    return Instruction(opcode=0b011001, dst=dst, src=src, imm=(0b11111111111 & imm), **kwargs)


def Bgez(src=0, imm=0, **kwargs):
    return Instruction(opcode=0b011010, src=src, imm=(0b11111111111 & imm), **kwargs)


def Blez(src=0, imm=0, **kwargs):
    return Instruction(opcode=0b011011, src=src, imm=(0b11111111111 & imm), **kwargs)


def Bgtz(src=0, imm=0, **kwargs):
    return Instruction(opcode=0b011100, src=src, imm=(0b11111111111 & imm), **kwargs)


def Bltz(src=0, imm=0, **kwargs):
    return Instruction(opcode=0b011101, src=src, imm=(0b11111111111 & imm), **kwargs)


def EndOfProgram(src=0, imm=0, **kwargs):
    return Instruction(opcode=-1, dst=-1, src=-1, target=-1, imm=-1, **kwargs)


def make_program(pkt, insns: [Instruction]):
    pkt /= ProtoWrapper(type=PROTO_PROGRAM, src=IP().src, max_steps=0xFFFF)
    pkt /= Registers()
    assert len(insns) < MAX_PROGRAM_LENGTH
    for insn in insns:
        pkt /= insn
    pkt /= EndOfProgram()
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
