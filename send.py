#!/usr/bin/env python2
import sys
import socket

from scapy.all import sendp, send, get_if_list, get_if_hwaddr, bind_layers
from scapy.all import Packet, Raw
from scapy.all import Ether, IP, UDP
from scapy.fields import *
import readline

from headers import *


PROTO_RAW_PROGRAM = 0x8F
MAX_PROGRAM_LENGTH = 300

LOAD_BALANCER_IP = '255.255.255.255'
LOAD_BALANCER_MAC = 'ff:ff:ff:ff:ff:ff'


def AddI(dst=0, src=0, imm=0, **kwargs):
    return Instruction(funct7=(imm >> 5), part1=((1 << 5 - 1) & imm), part2=src, funct3=0b000, part3=dst, opcode=0b0010011, **kwargs)


def Add(dst=0, src=0, target=0, **kwargs):
    return Instruction(funct7=0b0000000, part1=target, part2=src, funct3=0b000, part3=dst, opcode=0b0110011, **kwargs)


# def SubI(dst=0, src=0, imm=0, **kwargs):
#     return Instruction(opcode=0b000001, dst=dst, src=src, target=(imm >> 11), imm=(0b11111111111 & imm), **kwargs)


# def Sub(dst=0, src=0, target=0, **kwargs):
#     return Instruction(opcode=0b100001, dst=dst, src=src, target=target, **kwargs)


# def MulI(dst=0, src=0, imm=0, **kwargs):
#     return Instruction(opcode=0b000010, dst=dst, src=src, target=(imm >> 11), imm=(0b11111111111 & imm), **kwargs)


# def Mul(dst=0, src=0, target=0, **kwargs):
#     return Instruction(opcode=0b100010, dst=dst, src=src, target=target, **kwargs)


# def DivI(dst=0, src=0, imm=0, **kwargs):
#     return Instruction(opcode=0b000011, dst=dst, src=src, target=(imm >> 11), imm=(0b11111111111 & imm), **kwargs)


# def Div(dst=0, src=0, target=0, **kwargs):
#     return Instruction(opcode=0b100011, dst=dst, src=src, target=target, **kwargs)


# def SllI(dst=0, src=0, imm=0, **kwargs):
#     return Instruction(opcode=0b000100, dst=dst, src=src, target=imm, **kwargs)


# def Sll(dst=0, src=0, target=0, **kwargs):
#     return Instruction(opcode=0b100100, dst=dst, src=src, target=target, **kwargs)


# def SrlI(dst=0, src=0, imm=0, **kwargs):
#     return Instruction(opcode=0b000110, dst=dst, src=src, target=imm, **kwargs)


# def Srl(dst=0, src=0, target=0, **kwargs):
#     return Instruction(opcode=0b100110, dst=dst, src=src, target=target, **kwargs)


# def SraI(dst=0, src=0, imm=0, **kwargs):
#     return Instruction(opcode=0b000111, dst=dst, src=src, target=imm, **kwargs)


# def Sra(dst=0, src=0, target=0, **kwargs):
#     return Instruction(opcode=0b100111, dst=dst, src=src, target=target, **kwargs)


# def AndI(dst=0, src=0, imm=0, **kwargs):
#     return Instruction(opcode=0b001000, dst=dst, src=src, target=(imm >> 11), imm=(0b11111111111 & imm), **kwargs)


# def And(dst=0, src=0, target=0, **kwargs):
#     return Instruction(opcode=0b101000, dst=dst, src=src, target=target, **kwargs)


# def OrI(dst=0, src=0, imm=0, **kwargs):
#     return Instruction(opcode=0b001001, dst=dst, src=src, target=(imm >> 11), imm=(0b11111111111 & imm), **kwargs)


# def Or(dst=0, src=0, target=0, **kwargs):
#     return Instruction(opcode=0b101001, dst=dst, src=src, target=target, **kwargs)


# def XorI(dst=0, src=0, imm=0, **kwargs):
#     return Instruction(opcode=0b001010, dst=dst, src=src, target=(imm >> 11), imm=(0b11111111111 & imm), **kwargs)


# def Xor(dst=0, src=0, target=0, **kwargs):
#     return Instruction(opcode=0b101010, dst=dst, src=src, target=target, **kwargs)


# def MovI(dst=0, src=0, imm=0, **kwargs):
#     return Instruction(opcode=0b001100, dst=dst, src=src, target=(imm >> 11), imm=(0b11111111111 & imm), **kwargs)


# def Mov(dst=0, src=0, target=0, **kwargs):
#     return Instruction(opcode=0b101100, dst=dst, src=src, target=target, **kwargs)


# def Movz(dst=0, src=0, target=0, **kwargs):
#     return Instruction(opcode=0b101101, dst=dst, src=src, target=target, **kwargs)


# def Movn(dst=0, src=0, target=0, **kwargs):
#     return Instruction(opcode=0b101110, dst=dst, src=src, target=target, **kwargs)


# def SwI(dst=0, src=0, imm=0, **kwargs):
#     return Instruction(opcode=0b010000, dst=dst, src=src, target=(imm >> 11), imm=(0b11111111111 & imm), **kwargs)


# def Sw(dst=0, src=0, target=0, **kwargs):
#     return Instruction(opcode=0b110000, dst=dst, src=src, target=target, **kwargs)


# def Lw(dst=0, src=0, target=0, **kwargs):
#     return Instruction(opcode=0b110001, dst=dst, src=src, target=target, **kwargs)


# def Beq(src=0, target=0, imm=0, **kwargs):
#     return Instruction(opcode=0b011000, src=src, target=target, imm=(0b11111111111 & imm), **kwargs)


# def Bne(src=0, target=0, imm=0, **kwargs):
#     return Instruction(opcode=0b011001, src=src, target=target, imm=(0b11111111111 & imm), **kwargs)


# def Bgez(src=0, imm=0, **kwargs):
#     return Instruction(opcode=0b011010, src=src, imm=(0b11111111111 & imm), **kwargs)


# def Blez(src=0, imm=0, **kwargs):
#     return Instruction(opcode=0b011011, src=src, imm=(0b11111111111 & imm), **kwargs)


# def Bgtz(src=0, imm=0, **kwargs):
#     return Instruction(opcode=0b011100, src=src, imm=(0b11111111111 & imm), **kwargs)


# def Bltz(src=0, imm=0, **kwargs):
#     return Instruction(opcode=0b011101, src=src, imm=(0b11111111111 & imm), **kwargs)


def EndOfProgram(**kwargs):
    return Instruction(funct7=-1, part1=-1, part2=-1, funct3=-1, part3=-1, opcode=-1, **kwargs)


def make_program(pkt, insns):
    pkt /= ProtoWrapper(max_steps=1000)
    pkt /= Registers()
    assert len(insns) < MAX_PROGRAM_LENGTH
    for insn in insns:
        pkt /= insn
    pkt /= EndOfProgram()
    return pkt


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
