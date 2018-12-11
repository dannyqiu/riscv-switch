#!/usr/bin/env python2
from headers import *
from send import send_program


def main():
    send_program([
        AddI(dst=10, src=0, imm=8),    # compute the 8th fibonacci number

        AddI(dst=30, src=0, imm=4),
        Mul(dst=31, src=30, target=10),
        Lw(dst=6, src=31, imm=0),
        Beq(src=6, target=0, imm=8),
        Jal(dst=0, imm=48),

        AddI(dst=5, src=0, imm=0),
        AddI(dst=6, src=0, imm=0),
        AddI(dst=7, src=0, imm=1),

        Bge(src=5, target=10, imm=32),
        Add(dst=28, src=6, target=7),
        AddI(dst=6, src=7, imm=0),
        AddI(dst=7, src=28, imm=0),
        AddI(dst=5, src=5, imm=1),
        Mul(dst=31, src=30, target=5),
        Sw(dst=31, src=6, imm=0),
        Jal(dst=0, imm=-28),

        AddI(dst=10, src=6, imm=0),
    ])


if __name__ == '__main__':
    main()
