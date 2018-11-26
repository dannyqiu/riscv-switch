/* -*- P4_16 -*- */
#include <core.p4>
#include <v1model.p4>
#include "headers.p4"

/*************************************************************************
*********************** P A R S E R  ***********************************
*************************************************************************/

parser ProgramParser(packet_in packet,
                     out headers hdr,
                     inout metadata meta) {

    bit<32> registers_to_parse;
    bit<32> insns_to_current;

    state start {
        packet.extract(hdr.program_metadata);
        registers_to_parse = NUM_REGISTERS;
        insns_to_current = hdr.program_metadata.pc;
        transition parse_registers;
    }

    state parse_registers {
        registers_to_parse = registers_to_parse - 1;
        packet.extract(hdr.registers.next);
        transition select(registers_to_parse) {
            0: parse_insns;
            default: parse_registers;
        }
    }

    state parse_insns {
        transition select(packet.lookahead<bit<32>>()) {
            0xffffffff: parse_end_program;
            default: check_current_insn;
        }
    }

    state check_current_insn {
        transition select(insns_to_current) {
            0: set_current_insn;
            default: parse_insn;
        }
    }

    state parse_insn {
        packet.extract(hdr.insns.next);
        insns_to_current = insns_to_current - 1;
        transition parse_insns;
    }

    // save current PC instruction during parsing, since we cannot access arrays
    // with non-constant values in the other stages
    state set_current_insn {
        meta.current_insn.funct7 = packet.lookahead<bit<32>>()[31:25];
        meta.current_insn.part1 = packet.lookahead<bit<32>>()[24:20];
        meta.current_insn.part2 = packet.lookahead<bit<32>>()[19:15];
        meta.current_insn.funct3 = packet.lookahead<bit<32>>()[14:12];
        meta.current_insn.part3 = packet.lookahead<bit<32>>()[11:7];
        meta.current_insn.opcode = packet.lookahead<bit<32>>()[6:0];
        meta.current_insn.setValid();
        transition parse_insn;
    }

    state parse_end_program {
        packet.extract(hdr.end_program);
        transition accept;
    }

}

parser MyParser(packet_in packet,
                out headers hdr,
                inout metadata meta,
                inout standard_metadata_t standard_metadata) {

    ProgramParser() program_parser;

    state start {
        transition parse_ethernet;
    }

    state parse_ethernet {
        packet.extract(hdr.ethernet);
        transition select(hdr.ethernet.etherType) {
            TYPE_IPV4: parse_ipv4;
            default: accept;
        }
    }

    state parse_ipv4 {
        packet.extract(hdr.ipv4);
        transition select(hdr.ipv4.protocol) {
            PROTO_TCP: parse_tcp;
            PROTO_UDP: parse_udp;
            PROTO_PROGRAM: parse_program;
            default: accept;
        }
    }

    state parse_tcp {
        packet.extract(hdr.tcp);
        transition accept;
    }

    state parse_udp {
        packet.extract(hdr.udp);
        transition accept;
    }

    state parse_program {
        program_parser.apply(packet, hdr, meta);
        transition accept;
    }

}

/*************************************************************************
************   C H E C K S U M    V E R I F I C A T I O N   *************
*************************************************************************/

control MyVerifyChecksum(inout headers hdr, inout metadata meta) {
    apply {  }
}


/*************************************************************************
**************  I N G R E S S   P R O C E S S I N G   *******************
*************************************************************************/

control MyIngress(inout headers hdr,
                  inout metadata meta,
                  inout standard_metadata_t standard_metadata) {

    action drop() {
        mark_to_drop();
    }

    action ipv4_forward(bit<48> dstAddr, bit<9> port) {
        standard_metadata.egress_spec = port;
        hdr.ethernet.srcAddr = hdr.ethernet.dstAddr;
        hdr.ethernet.dstAddr = dstAddr;
        hdr.ipv4.ttl = hdr.ipv4.ttl - 1;
    }

    table ipv4_lpm {
        key = {
            hdr.ipv4.dstAddr: lpm;
        }
        actions = {
            ipv4_forward;
            NoAction();
            drop;
        }
        size = 1024;
        default_action = NoAction();
    }

    action bless_rtype(in insn_unknown_t unknown, out insn_rtype_t rtype) {
        rtype.funct7 = unknown.funct7;
        rtype.rs2 = unknown.part1;
        rtype.rs1 = unknown.part2;
        rtype.funct3 = unknown.funct3;
        rtype.rd = unknown.part3;
        rtype.opcode = unknown.opcode;
    }

    action bless_itype(in insn_unknown_t unknown, out insn_itype_t itype) {
        itype.imm = unknown.funct7 ++ unknown.part1;
        itype.rs1 = unknown.part2;
        itype.funct3 = unknown.funct3;
        itype.rd = unknown.part3;
        itype.opcode = unknown.opcode;
    }

    action bless_stype(in insn_unknown_t unknown, out insn_stype_t stype) {
        stype.imm_upper = unknown.funct7;
        stype.rs2 = unknown.part1;
        stype.rs1 = unknown.part2;
        stype.funct3 = unknown.funct3;
        stype.imm_lower = unknown.part3;
        stype.opcode = unknown.opcode;
    }

    action bless_utype(in insn_unknown_t unknown, out insn_utype_t utype) {
        utype.imm = unknown.funct7 ++ unknown.part1 ++ unknown.part2 ++ unknown.funct3;
        utype.rd = unknown.part3;
        utype.opcode = unknown.opcode;
    }

    action handle_rtype() {
        exit;
    }

    action handle_itype() {
        exit;
    }

    action handle_stype() {
        exit;
    }

    action handle_utype() {
        exit;
    }

    action get_register(in bit<5> r, out bit<32> value) {
        if (r == 0) {
            value = hdr.registers[0].value;
        }
        else if (r == 1) {
            value = hdr.registers[1].value;
        }
        else if (r == 2) {
            value = hdr.registers[2].value;
        }
        else if (r == 3) {
            value = hdr.registers[3].value;
        }
        else if (r == 4) {
            value = hdr.registers[4].value;
        }
        else if (r == 5) {
            value = hdr.registers[5].value;
        }
        else if (r == 6) {
            value = hdr.registers[6].value;
        }
        else if (r == 7) {
            value = hdr.registers[7].value;
        }
        else if (r == 8) {
            value = hdr.registers[8].value;
        }
        else if (r == 9) {
            value = hdr.registers[9].value;
        }
        else if (r == 10) {
            value = hdr.registers[10].value;
        }
        else if (r == 11) {
            value = hdr.registers[11].value;
        }
        else if (r == 12) {
            value = hdr.registers[12].value;
        }
        else if (r == 13) {
            value = hdr.registers[13].value;
        }
        else if (r == 14) {
            value = hdr.registers[14].value;
        }
        else if (r == 15) {
            value = hdr.registers[15].value;
        }
        else if (r == 16) {
            value = hdr.registers[16].value;
        }
        else if (r == 17) {
            value = hdr.registers[17].value;
        }
        else if (r == 18) {
            value = hdr.registers[18].value;
        }
        else if (r == 19) {
            value = hdr.registers[19].value;
        }
        else if (r == 20) {
            value = hdr.registers[20].value;
        }
        else if (r == 21) {
            value = hdr.registers[21].value;
        }
        else if (r == 22) {
            value = hdr.registers[22].value;
        }
        else if (r == 23) {
            value = hdr.registers[23].value;
        }
        else if (r == 24) {
            value = hdr.registers[24].value;
        }
        else if (r == 25) {
            value = hdr.registers[25].value;
        }
        else if (r == 26) {
            value = hdr.registers[26].value;
        }
        else if (r == 27) {
            value = hdr.registers[27].value;
        }
        else if (r == 28) {
            value = hdr.registers[28].value;
        }
        else if (r == 29) {
            value = hdr.registers[29].value;
        }
        else if (r == 30) {
            value = hdr.registers[30].value;
        }
        else if (r == 31) {
            value = hdr.registers[31].value;
        }
        else {
            value = 0;
        }
    }

    action set_register(in bit<5> r, in bit<32> value) {
        if (r == 0) {
            hdr.registers[0].value = value;
        }
        else if (r == 1) {
            hdr.registers[1].value = value;
        }
        else if (r == 2) {
            hdr.registers[2].value = value;
        }
        else if (r == 3) {
            hdr.registers[3].value = value;
        }
        else if (r == 4) {
            hdr.registers[4].value = value;
        }
        else if (r == 5) {
            hdr.registers[5].value = value;
        }
        else if (r == 6) {
            hdr.registers[6].value = value;
        }
        else if (r == 7) {
            hdr.registers[7].value = value;
        }
        else if (r == 8) {
            hdr.registers[8].value = value;
        }
        else if (r == 9) {
            hdr.registers[9].value = value;
        }
        else if (r == 10) {
            hdr.registers[10].value = value;
        }
        else if (r == 11) {
            hdr.registers[11].value = value;
        }
        else if (r == 12) {
            hdr.registers[12].value = value;
        }
        else if (r == 13) {
            hdr.registers[13].value = value;
        }
        else if (r == 14) {
            hdr.registers[14].value = value;
        }
        else if (r == 15) {
            hdr.registers[15].value = value;
        }
        else if (r == 16) {
            hdr.registers[16].value = value;
        }
        else if (r == 17) {
            hdr.registers[17].value = value;
        }
        else if (r == 18) {
            hdr.registers[18].value = value;
        }
        else if (r == 19) {
            hdr.registers[19].value = value;
        }
        else if (r == 20) {
            hdr.registers[20].value = value;
        }
        else if (r == 21) {
            hdr.registers[21].value = value;
        }
        else if (r == 22) {
            hdr.registers[22].value = value;
        }
        else if (r == 23) {
            hdr.registers[23].value = value;
        }
        else if (r == 24) {
            hdr.registers[24].value = value;
        }
        else if (r == 25) {
            hdr.registers[25].value = value;
        }
        else if (r == 26) {
            hdr.registers[26].value = value;
        }
        else if (r == 27) {
            hdr.registers[27].value = value;
        }
        else if (r == 28) {
            hdr.registers[28].value = value;
        }
        else if (r == 29) {
            hdr.registers[29].value = value;
        }
        else if (r == 30) {
            hdr.registers[30].value = value;
        }
        else if (r == 31) {
            hdr.registers[31].value = value;
        }
    }

    action insn_add() {
        insn_rtype_t add;
        bless_rtype(meta.current_insn, add);
        bit<32> r1;
        bit<32> r2;
        get_register(add.rs1, r1);
        get_register(add.rs2, r2);
        set_register(add.rd, r1 + r2);
    }

    action insn_addi() {
        insn_itype_t addi;
        bless_itype(meta.current_insn, addi);
        bit<32> r1;
        get_register(addi.rs1, r1);
        set_register(addi.rd, r1 + (bit<32>) addi.imm);
    }

    table insn_opcode_exact {
        key = {
            meta.current_insn.funct7: ternary;
            meta.current_insn.funct3: ternary;
            meta.current_insn.opcode: exact;
        }
        actions = {
            insn_add;
            insn_addi;
            handle_rtype;
            handle_itype;
            handle_stype;
            handle_utype;
            NoAction();
        }
        default_action = NoAction();
        const entries = {
            (0b0000000, 0b000, 0b0110011) : insn_add();
            // (0b0100000, 0b000, 0b0110011) : insn_sub();
            // (0b0000000, 0b111, 0b0110011) : insn_and();
            // (0b0000000, 0b110, 0b0110011) : insn_or();
            // (0b0000000, 0b100, 0b0110011) : insn_xor();
            // (0b0000000, 0b010, 0b0110011) : insn_slt();
            // (0b0000000, 0b011, 0b0110011) : insn_sltu();
            // (0b0100000, 0b101, 0b0110011) : insn_sra();
            // (0b0000000, 0b101, 0b0110011) : insn_srl();
            // (0b0000000, 0b001, 0b0110011) : insn_sll();
            // (0b0000001, 0b000, 0b0110011) : insn_mul();

            (_, _, 0b0110011) : handle_rtype(); // generic rtype

            (_, 0b000, 0b0010011) : insn_addi();

            (_, _, 0b0000011) : handle_itype(); // LW
            (_, _, 0b1100111) : handle_itype(); // JR / JALR
            (_, _, 0b0010011) : handle_itype(); // generic itype

            (_, _, 0b0100011) : handle_stype(); // SW
            (_, _, 0b1100011) : handle_stype(); // generic branch

            (_, _, 0b0010111) : handle_utype(); // AUIPC
            (_, _, 0b0110111) : handle_utype(); // LUI
            (_, _, 0b1101111) : handle_utype(); // JAL
        }
    }

    apply {
        if (meta.current_insn.isValid()) {
            insn_opcode_exact.apply();
        }
        else if (hdr.ipv4.isValid()) {
            ipv4_lpm.apply();
        }
        else {
            drop();
        }
    }
}

/*************************************************************************
****************  E G R E S S   P R O C E S S I N G   *******************
*************************************************************************/

control MyEgress(inout headers hdr,
                 inout metadata meta,
                 inout standard_metadata_t standard_metadata) {
    apply { }
}

/*************************************************************************
*************   C H E C K S U M    C O M P U T A T I O N   **************
*************************************************************************/

control MyComputeChecksum(inout headers  hdr, inout metadata meta) {
     apply { }
}

/*************************************************************************
***********************  D E P A R S E R  *******************************
*************************************************************************/

control MyDeparser(packet_out packet, in headers hdr) {
    apply {
        packet.emit(hdr.ethernet);
        packet.emit(hdr.ipv4);
        packet.emit(hdr.tcp);
        packet.emit(hdr.udp);
        packet.emit(hdr.program_metadata);
        packet.emit(hdr.registers);
        packet.emit(hdr.insns);
        packet.emit(hdr.end_program);
    }
}

/*************************************************************************
***********************  S W I T C H  *******************************
*************************************************************************/

V1Switch(
MyParser(),
MyVerifyChecksum(),
MyIngress(),
MyEgress(),
MyComputeChecksum(),
MyDeparser()
) main;
