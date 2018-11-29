#!/usr/bin/env python2
from __future__ import print_function

from scapy.all import get_if_list, bind_layers
from scapy.all import Packet, Raw
from scapy.all import IP
from scapy.fields import *


PROTO_RAW_PROGRAM = 0x8F
PROTO_PROGRAM = 0x90
PROTO_STORE_REQUEST = 0x91
PROTO_LOAD_REQUEST = 0x92
PROTO_LOAD_RESPONSE = 0x93

MAX_PROGRAM_LENGTH = 300

LOAD_BALANCER_IP = '10.255.255.0'
LOAD_BALANCER_MAC = '00:00:ff:00:00:00'
DATASTORE_IP = '10.255.255.1'
DATASTORE_MAC = '00:00:ff:00:00:01'

def get_if():
    ifs = get_if_list()
    iface = [i for i in get_if_list() if "eth0" in i]
    if not iface:
        print("Cannot find eth0 interface")
        exit(1)
    return iface[0]


class ProgramMetadata(Packet):
    name = 'ProgramMetadata'
    fields_desc = [
        BitField('max_steps', 0, 32),
    ]


class ProgramExecutionMetadata(Packet):
    name = 'ProgramExecutionMetadata'
    fields_desc = [
        BitField('src_port', 0, 9),
        BitField('reserved', 0, 7),
        BitField('src_mac', 0, 48),
        BitField('src_ipv4', 0, 32),
        BitField('pc', 0, 32),
        BitField('steps', 0, 32),
        BitField('mem_namespace', 0, 32),
    ]


class StoreRequestMetadata(Packet):
    name = 'StoreRequestMetadata'
    fields_desc = [
        BitField('address', 0, 32),
        BitField('value', 0, 32),
        BitField('execution_node', 0, 32),
    ]


class LoadRequestMetadata(Packet):
    name = 'LoadRequestMetadata'
    fields_desc = [
        BitField('address', 0, 32),
        BitField('register', 0, 5),
        BitField('reserved', 0, 3),
        BitField('execution_node', 0, 32),
    ]


class LoadResponseMetadata(Packet):
    name = 'LoadResponseMetadata'
    fields_desc = [
        BitField('value', 0, 32),
        BitField('register', 0, 5),
        BitField('reserved', 0, 3),
        BitField('execution_node', 0, 32),
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


def AddI(dst=0, src=0, imm=0, **kwargs):
    return Instruction(funct7=(imm >> 5), part1=(((1 << 5) - 1) & imm), part2=src, funct3=0b000, part3=dst, opcode=0b0010011, **kwargs)


def Add(dst=0, src=0, target=0, **kwargs):
    return Instruction(funct7=0b0000000, part1=target, part2=src, funct3=0b000, part3=dst, opcode=0b0110011, **kwargs)


def Sub(dst=0, src=0, target=0, **kwargs):
    return Instruction(funct7=0b0100000, part1=target, part2=src, funct3=0b000, part3=dst, opcode=0b0110011, **kwargs)


# def MulI(dst=0, src=0, imm=0, **kwargs):
#     return Instruction(opcode=0b000010, dst=dst, src=src, target=(imm >> 11), imm=(0b11111111111 & imm), **kwargs)


def Mul(dst=0, src=0, target=0, **kwargs):
    return Instruction(funct7=0b0000001, part1=target, part2=src, funct3=0b000, part3=dst, opcode=0b0110011, **kwargs)


def SllI(dst=0, src=0, imm=0, **kwargs):
    return Instruction(funct7=0b0000000, part1=(((1 << 5) - 1) & imm), part2=src, funct3=0b001, part3=dst, opcode=0b0010011, **kwargs)


def Sll(dst=0, src=0, target=0, **kwargs):
    return Instruction(funct7=0b0000000, part1=target, part2=src, funct3=0b001, part3=dst, opcode=0b0110011, **kwargs)


def SrlI(dst=0, src=0, imm=0, **kwargs):
    return Instruction(funct7=0b0000000, part1=(((1 << 5) - 1) & imm), part2=src, funct3=0b101, part3=dst, opcode=0b0010011, **kwargs)


def Srl(dst=0, src=0, target=0, **kwargs):
    return Instruction(funct7=0b0000000, part1=target, part2=src, funct3=0b101, part3=dst, opcode=0b0110011, **kwargs)


def SraI(dst=0, src=0, imm=0, **kwargs):
    return Instruction(funct7=0b0100000, part1=(((1 << 5) - 1) & imm), part2=src, funct3=0b101, part3=dst, opcode=0b0010011, **kwargs)


def Sra(dst=0, src=0, target=0, **kwargs):
    return Instruction(funct7=0b0100000, part1=target, part2=src, funct3=0b101, part3=dst, opcode=0b0110011, **kwargs)


def AndI(dst=0, src=0, imm=0, **kwargs):
    return Instruction(funct7=(imm >> 5), part1=(((1 << 5) - 1) & imm), part2=src, funct3=0b111, part3=dst, opcode=0b0010011, **kwargs)


def And(dst=0, src=0, target=0, **kwargs):
    return Instruction(funct7=0b0000000, part1=target, part2=src, funct3=0b111, part3=dst, opcode=0b0110011, **kwargs)


def OrI(dst=0, src=0, imm=0, **kwargs):
    return Instruction(funct7=(imm >> 5), part1=(((1 << 5) - 1) & imm), part2=src, funct3=0b110, part3=dst, opcode=0b0010011, **kwargs)


def Or(dst=0, src=0, target=0, **kwargs):
    return Instruction(funct7=0b0000000, part1=target, part2=src, funct3=0b110, part3=dst, opcode=0b0110011, **kwargs)


def XorI(dst=0, src=0, imm=0, **kwargs):
    return Instruction(funct7=(imm >> 5), part1=(((1 << 5) - 1) & imm), part2=src, funct3=0b100, part3=dst, opcode=0b0010011, **kwargs)


def Xor(dst=0, src=0, target=0, **kwargs):
    return Instruction(funct7=0b0000000, part1=target, part2=src, funct3=0b100, part3=dst, opcode=0b0110011, **kwargs)


# def MovI(dst=0, src=0, imm=0, **kwargs):
#     return Instruction(opcode=0b001100, dst=dst, src=src, target=(imm >> 11), imm=(0b11111111111 & imm), **kwargs)


# def Mov(dst=0, src=0, target=0, **kwargs):
#     return Instruction(opcode=0b101100, dst=dst, src=src, target=target, **kwargs)


# def Movz(dst=0, src=0, target=0, **kwargs):
#     return Instruction(opcode=0b101101, dst=dst, src=src, target=target, **kwargs)


# def Movn(dst=0, src=0, target=0, **kwargs):
#     return Instruction(opcode=0b101110, dst=dst, src=src, target=target, **kwargs)


def SltI(dst=0, src=0, imm=0, **kwargs):
    return Instruction(funct7=(imm >> 5), part1=(((1 << 5) - 1) & imm), part2=src, funct3=0b010, part3=dst, opcode=0b0010011, **kwargs)


def Slt(dst=0, src=0, target=0, **kwargs):
    return Instruction(funct7=0b0000000, part1=target, part2=src, funct3=0b010, part3=dst, opcode=0b0110011, **kwargs)


def SltIu(dst=0, src=0, imm=0, **kwargs):
    return Instruction(funct7=(imm >> 5), part1=(((1 << 5) - 1) & imm), part2=src, funct3=0b011, part3=dst, opcode=0b0010011, **kwargs)


def Sltu(dst=0, src=0, target=0, **kwargs):
    return Instruction(funct7=0b0000000, part1=target, part2=src, funct3=0b011, part3=dst, opcode=0b0110011, **kwargs)


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
    pkt /= ProgramMetadata(max_steps=1000)
    pkt /= Registers()
    assert len(insns) < MAX_PROGRAM_LENGTH
    for insn in insns:
        pkt /= insn
    pkt /= EndOfProgram()
    return pkt


bind_layers(IP, ProgramMetadata, proto=PROTO_RAW_PROGRAM)
bind_layers(IP, ProgramExecutionMetadata, proto=PROTO_PROGRAM)
bind_layers(IP, StoreRequestMetadata, proto=PROTO_STORE_REQUEST)
bind_layers(IP, LoadRequestMetadata, proto=PROTO_LOAD_REQUEST)
bind_layers(IP, LoadResponseMetadata, proto=PROTO_LOAD_RESPONSE)
bind_layers(StoreRequestMetadata, ProgramExecutionMetadata)
bind_layers(LoadRequestMetadata, ProgramExecutionMetadata)
bind_layers(LoadResponseMetadata, ProgramExecutionMetadata)
bind_layers(ProgramExecutionMetadata, ProgramMetadata)
bind_layers(ProgramMetadata, Registers)
bind_layers(Registers, Instruction)
bind_layers(Instruction, Instruction)
