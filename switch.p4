/* -*- P4_16 -*- */
#include <core.p4>
#include <v1model.p4>
#include "headers.p4"

#define GET_REG_PRIMARY(r, n, v) if (r == n) { v = hdr.registers[n].value; }
#define GET_REG_OTHERWISE(r, n, v) else if (r == n) { v = hdr.registers[n].value; }
#define SET_REG_PRIMARY(r, n, v) if (r == n) { hdr.registers[n].value = v; }
#define SET_REG_OTHERWISE(r, n, v) else if (r == n) { hdr.registers[n].value = v; }

// Role IDs
#define ROLE_LOAD_BALANCER 0
#define ROLE_EXECUTION_UNIT 1
#define ROLE_DATASTORE 2

/*************************************************************************
*********************** P A R S E R  ***********************************
*************************************************************************/

parser ProgramParser(packet_in packet,
                     inout headers hdr,
                     inout metadata meta,
                     inout standard_metadata_t standard_metadata) {

    bit<32> registers_to_parse;
    bit<32> insns_to_current;

    state start {
        insns_to_current = 0;
        registers_to_parse = NUM_REGISTERS;
        transition select(hdr.ipv4.protocol) {
            PROTO_RAW_PROGRAM: parse_metadata;
            PROTO_PROGRAM: parse_execution_metadata;
            PROTO_STORE_REQUEST: parse_store_request_metadata;
            PROTO_LOAD_REQUEST: parse_load_request_metadata;
            PROTO_LOAD_RESPONSE: parse_load_response_metadata;
        }
    }

    state parse_store_request_metadata {
        packet.extract(hdr.store_request_metadata);
        transition parse_execution_metadata;
    }

    state parse_load_request_metadata {
        packet.extract(hdr.load_request_metadata);
        transition parse_execution_metadata;
    }

    state parse_load_response_metadata {
        packet.extract(hdr.load_response_metadata);
        transition parse_execution_metadata;
    }

    state parse_execution_metadata {
        packet.extract(hdr.program_execution_metadata);
        insns_to_current = hdr.program_execution_metadata.pc >> 2;
        transition parse_metadata;
    }

    state parse_metadata {
        packet.extract(hdr.program_metadata);
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

    // save current PC instruction during parsing, since we cannot access arrays
    // with non-constant values in the other stages
    state set_current_insn {
        meta.current_insn.setValid();
        meta.current_insn.funct7 = packet.lookahead<bit<32>>()[31:25];
        meta.current_insn.part1 = packet.lookahead<bit<32>>()[24:20];
        meta.current_insn.part2 = packet.lookahead<bit<32>>()[19:15];
        meta.current_insn.funct3 = packet.lookahead<bit<32>>()[14:12];
        meta.current_insn.part3 = packet.lookahead<bit<32>>()[11:7];
        meta.current_insn.opcode = packet.lookahead<bit<32>>()[6:0];
        transition parse_insn;
    }

    state parse_insn {
        packet.extract(hdr.insns.next);
        insns_to_current = insns_to_current - 1;
        transition parse_insns;
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
            PROTO_RAW_PROGRAM: parse_program;
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
        program_parser.apply(packet, hdr, meta, standard_metadata);
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

    bit<32> switch_id = 0;
    bit<2> switch_role = ROLE_EXECUTION_UNIT;
    bit<32> num_execution_units = 0;
    bit<32> num_hosts = 0;
    bit<32> target_execution_node_idx = 0;
    bit<32> target_execution_node_id = 0;

    register<bit<32>>(NUM_REGISTERS) registers;

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

    /******************** BEGIN: PARSING INSTRUCTION FORMAT ********************/

    action bless_rtype(in insn_unknown_t unknown, out insn_rtype_t rtype) {
        rtype.setValid();
        rtype.funct7 = unknown.funct7;
        rtype.rs2 = unknown.part1;
        rtype.rs1 = unknown.part2;
        rtype.funct3 = unknown.funct3;
        rtype.rd = unknown.part3;
        rtype.opcode = unknown.opcode;
    }

    action bless_itype(in insn_unknown_t unknown, out insn_itype_t itype) {
        itype.setValid();
        itype.imm = unknown.funct7 ++ unknown.part1;
        itype.rs1 = unknown.part2;
        itype.funct3 = unknown.funct3;
        itype.rd = unknown.part3;
        itype.opcode = unknown.opcode;
    }

    action bless_stype(in insn_unknown_t unknown, out insn_stype_t stype) {
        stype.setValid();
        stype.imm_upper = unknown.funct7;
        stype.rs2 = unknown.part1;
        stype.rs1 = unknown.part2;
        stype.funct3 = unknown.funct3;
        stype.imm_lower = unknown.part3;
        stype.opcode = unknown.opcode;
    }

    action bless_utype(in insn_unknown_t unknown, out insn_utype_t utype) {
        utype.setValid();
        utype.imm = unknown.funct7 ++ unknown.part1 ++ unknown.part2 ++ unknown.funct3;
        utype.rd = unknown.part3;
        utype.opcode = unknown.opcode;
    }

    /******************** END: PARSING INSTRUCTION FORMAT ********************/

    /******************** BEGIN: PARSING IMMEDIATE FORMAT ********************/

    action bless_i_imm(in insn_itype_t itype, out bit<32> imm) {
        imm = 20w0 ++ itype.imm;
        if ((imm & 0x00000800) > 0) {
            imm = imm | 0xfffff000;
        }
    }

    action bless_s_imm(in insn_stype_t stype, out bit<32> imm) {
        imm = 20w0 ++ (stype.imm_upper ++ stype.imm_lower);
        if ((imm & 0x00000800) > 0) {
            imm = imm | 0xfffff000;
        }
    }

    action bless_b_imm(in insn_stype_t stype, out bit<32> imm) {
        imm = 19w0 ++ stype.imm_upper[6:6] ++ stype.imm_lower[0:0] ++ stype.imm_upper[5:0] ++ stype.imm_lower[4:1] ++ 1w0;
        if ((imm & 0x00001000) > 0) {
            imm = imm | 0xffffe000;
        }
    }

    action bless_u_imm(in insn_itype_t itype, out bit<32> imm) {
        imm = itype.imm ++ itype.rs1 ++ itype.funct3 ++ 12w0;
    }

    action bless_j_imm(in insn_utype_t utype, out bit<32> imm) {
        imm = 11w0 ++ imm[19:19] ++ imm[7:0] ++ imm[8:8] ++ imm[18:9] ++ 1w0;
        if ((imm & 0x00100000) > 0) {
            imm = imm | 0xffe00000;
        }
    }

    /******************** END: PARSING IMMEDIATE FORMAT ********************/

    /******************** BEGIN: CACHING REGISTER HEADER ********************/

    action get_register(in bit<5> r, out bit<32> value) {
        registers.read(value, (bit<32>) r);
    }

    action set_register(in bit<5> r, in bit<32> value) {
        registers.write((bit<32>) r, value);
    }

    /* Read all register values from header into registers primitive. This is
     * required because we cannot normally access the register header stack with
     * a non-constant index. The alternative would be to have an action with
     * many if-else cases, but that would be inlined in every instruction
     * action, causing the size of the program to expand greatly. */
    action read_all_registers() {
        registers.write(0, 0);
        registers.write(1, hdr.registers[1].value);
        registers.write(2, hdr.registers[2].value);
        registers.write(3, hdr.registers[3].value);
        registers.write(4, hdr.registers[4].value);
        registers.write(5, hdr.registers[5].value);
        registers.write(6, hdr.registers[6].value);
        registers.write(7, hdr.registers[7].value);
        registers.write(8, hdr.registers[8].value);
        registers.write(9, hdr.registers[9].value);
        registers.write(10, hdr.registers[10].value);
        registers.write(11, hdr.registers[11].value);
        registers.write(12, hdr.registers[12].value);
        registers.write(13, hdr.registers[13].value);
        registers.write(14, hdr.registers[14].value);
        registers.write(15, hdr.registers[15].value);
        registers.write(16, hdr.registers[16].value);
        registers.write(17, hdr.registers[17].value);
        registers.write(18, hdr.registers[18].value);
        registers.write(19, hdr.registers[19].value);
        registers.write(20, hdr.registers[20].value);
        registers.write(21, hdr.registers[21].value);
        registers.write(22, hdr.registers[22].value);
        registers.write(23, hdr.registers[23].value);
        registers.write(24, hdr.registers[24].value);
        registers.write(25, hdr.registers[25].value);
        registers.write(26, hdr.registers[26].value);
        registers.write(27, hdr.registers[27].value);
        registers.write(28, hdr.registers[28].value);
        registers.write(29, hdr.registers[29].value);
        registers.write(30, hdr.registers[30].value);
        registers.write(31, hdr.registers[31].value);
    }

    action write_all_registers() {
        hdr.registers[0].value = 0;
        registers.read(hdr.registers[1].value, 1);
        registers.read(hdr.registers[2].value, 2);
        registers.read(hdr.registers[3].value, 3);
        registers.read(hdr.registers[4].value, 4);
        registers.read(hdr.registers[5].value, 5);
        registers.read(hdr.registers[6].value, 6);
        registers.read(hdr.registers[7].value, 7);
        registers.read(hdr.registers[8].value, 8);
        registers.read(hdr.registers[9].value, 9);
        registers.read(hdr.registers[10].value, 10);
        registers.read(hdr.registers[11].value, 11);
        registers.read(hdr.registers[12].value, 12);
        registers.read(hdr.registers[13].value, 13);
        registers.read(hdr.registers[14].value, 14);
        registers.read(hdr.registers[15].value, 15);
        registers.read(hdr.registers[16].value, 16);
        registers.read(hdr.registers[17].value, 17);
        registers.read(hdr.registers[18].value, 18);
        registers.read(hdr.registers[19].value, 19);
        registers.read(hdr.registers[20].value, 20);
        registers.read(hdr.registers[21].value, 21);
        registers.read(hdr.registers[22].value, 22);
        registers.read(hdr.registers[23].value, 23);
        registers.read(hdr.registers[24].value, 24);
        registers.read(hdr.registers[25].value, 25);
        registers.read(hdr.registers[26].value, 26);
        registers.read(hdr.registers[27].value, 27);
        registers.read(hdr.registers[28].value, 28);
        registers.read(hdr.registers[29].value, 29);
        registers.read(hdr.registers[30].value, 30);
        registers.read(hdr.registers[31].value, 31);
    }

    /******************** END: CACHING REGISTER HEADER ********************/

    /******************** BEGIN: INSTRUCTION HANDLING ********************/

    action advance_pc() {
        hdr.program_execution_metadata.pc = hdr.program_execution_metadata.pc + 4;
    }

    action insn_add() {
        insn_rtype_t add;
        bless_rtype(meta.current_insn, add);
        bit<32> r1;
        bit<32> r2;
        get_register(add.rs1, r1);
        get_register(add.rs2, r2);
        set_register(add.rd, r1 + r2);
        advance_pc();
    }

    action insn_addi() {
        insn_itype_t addi;
        bless_itype(meta.current_insn, addi);
        bit<32> r1;
        bit<32> imm;
        get_register(addi.rs1, r1);
        bless_i_imm(addi, imm);
        set_register(addi.rd, r1 + imm);
        advance_pc();
    }

    action insn_and() {
        insn_rtype_t and;
        bless_rtype(meta.current_insn, and);
        bit<32> r1;
        bit<32> r2;
        get_register(and.rs1, r1);
        get_register(and.rs2, r2);
        set_register(and.rd, r1 & r2);
        advance_pc();
    }

    action insn_andi() {
        insn_itype_t addi;
        bless_itype(meta.current_insn, addi);
        bit<32> r1;
        bit<32> imm;
        get_register(addi.rs1, r1);
        bless_i_imm(addi, imm);
        set_register(addi.rd, r1 & imm);
        advance_pc();
    }

    action insn_or() {
        insn_rtype_t or;
        bless_rtype(meta.current_insn, or);
        bit<32> r1;
        bit<32> r2;
        get_register(or.rs1, r1);
        get_register(or.rs2, r2);
        set_register(or.rd, r1 | r2);
        advance_pc();
    }

    action insn_sub() {
        insn_rtype_t sub;
        bless_rtype(meta.current_insn, sub);
        bit<32> r1;
        bit<32> r2;
        get_register(sub.rs1, r1);
        get_register(sub.rs2, r2);
        set_register(sub.rd, r1 - r2);
        advance_pc();
    }

    action insn_xor() {
        insn_rtype_t xor;
        bless_rtype(meta.current_insn, xor);
        bit<32> r1;
        bit<32> r2;
        get_register(xor.rs1, r1);
        get_register(xor.rs2, r2);
        set_register(xor.rd, r1 ^ r2);
        advance_pc();
    }

    table insn_opcode {
        key = {
            meta.current_insn.funct7: ternary;
            meta.current_insn.funct3: ternary;
            meta.current_insn.opcode: exact;
        }
        actions = {
            insn_add;
            insn_addi;
            insn_and;
            insn_andi;
            insn_or;
            insn_sub;
            insn_xor;
            advance_pc;
        }
        default_action = advance_pc();
        const entries = {
            (0b0000000, 0b000, 0b0110011) : insn_add();
            (0b0100000, 0b000, 0b0110011) : insn_sub();
            (0b0000000, 0b111, 0b0110011) : insn_and();
            (0b0000000, 0b110, 0b0110011) : insn_or();
            (0b0000000, 0b100, 0b0110011) : insn_xor();
            // (0b0000000, 0b010, 0b0110011) : insn_slt();
            // (0b0000000, 0b011, 0b0110011) : insn_sltu();
            // (0b0100000, 0b101, 0b0110011) : insn_sra();
            // (0b0000000, 0b101, 0b0110011) : insn_srl();
            // (0b0000000, 0b001, 0b0110011) : insn_sll();
            // (0b0000001, 0b000, 0b0110011) : insn_mul();

            // (_, _, 0b0110011) : handle_rtype(); // generic rtype

            (_, 0b000, 0b0010011) : insn_addi();
            (_, 0b111, 0b0010011) : insn_andi();

            // (_, _, 0b0000011) : handle_itype(); // LW
            // (_, _, 0b1100111) : handle_itype(); // JR / JALR
            // (_, _, 0b0010011) : handle_itype(); // generic itype

            // (_, _, 0b0100011) : handle_stype(); // SW
            // (_, _, 0b1100011) : handle_stype(); // generic branch

            // (_, _, 0b0010111) : handle_utype(); // AUIPC
            // (_, _, 0b0110111) : handle_utype(); // LUI
            // (_, _, 0b1101111) : handle_utype(); // JAL
        }
    }

    /******************** END: INSTRUCTION HANDLING ********************/

    /******************** BEGIN: SWITCH CONFIGURATION ********************/

    action configure_switch(bit<32> id, bit<2> role, bit<32> n_execution_units, bit<32> n_hosts) {
        switch_id = id;
        switch_role = role;
        num_execution_units = n_execution_units;
        num_hosts = n_hosts;
    }

    table configuration {
        key = { }
        actions = {
            configure_switch;
            drop;
        }
        default_action = drop();
    }

    action forward_to_execution_node(bit<9> port) {
        standard_metadata.egress_spec = port;
    }

    table load_balance_map {
        key = {
            target_execution_node_idx: exact;
        }
        actions = {
            forward_to_execution_node;
            drop;
        }
        default_action = drop();
    }

    table datastore_response_map {
        key = {
            target_execution_node_id: exact;
        }
        actions = {
            forward_to_execution_node;
            drop;
        }
        default_action = drop();
    }

    /******************** END: SWITCH CONFIGURATION ********************/

    table debug {
        key = {
            switch_id: exact;
            switch_role: exact;
            num_execution_units: exact;
            num_hosts: exact;
            hdr.program_execution_metadata.pc: exact;
        }
        actions = {
            NoAction();
        }
        default_action = NoAction();
    }

    apply {
        configuration.apply();
        debug.apply();
        if (switch_role == ROLE_LOAD_BALANCER && hdr.program_metadata.isValid()) {
            if (!hdr.program_execution_metadata.isValid()) {
                // Add execution metadata header and perform load-balancing
                hdr.ipv4.protocol = PROTO_PROGRAM;
                hdr.program_execution_metadata.setValid();
                hdr.program_execution_metadata.src_port = standard_metadata.ingress_port;
                hdr.program_execution_metadata.src_mac = hdr.ethernet.srcAddr;
                hdr.program_execution_metadata.src_ipv4 = hdr.ipv4.srcAddr;
                hdr.program_execution_metadata.pc = 0;
                hdr.program_execution_metadata.steps = 0;
                hdr.program_execution_metadata.mem_namespace = hdr.ipv4.srcAddr;
                hash(target_execution_node_idx, HashAlgorithm.crc16, (bit<1>) 0,
                    {
                        hdr.ethernet.srcAddr,
                        hdr.ipv4.hdrChecksum,
                        hdr.program_metadata.max_steps
                    }, num_execution_units);
                load_balance_map.apply();
            }
            else {
                // Forward executed program back to host
                standard_metadata.egress_spec = hdr.program_execution_metadata.src_port;
                hdr.ethernet.srcAddr = LOAD_BALANCER_MAC;
                hdr.ethernet.dstAddr = hdr.program_execution_metadata.src_mac;
                hdr.ipv4.srcAddr = LOAD_BALANCER_IP;
                hdr.ipv4.dstAddr = hdr.program_execution_metadata.src_ipv4;
                // Strip execution metadata
                hdr.program_execution_metadata.setInvalid();
                hdr.ipv4.protocol = PROTO_RAW_PROGRAM;
            }
        }
        else if (switch_role == ROLE_EXECUTION_UNIT) {
            if (meta.current_insn.isValid()) {
                read_all_registers();
                // Apply load response if applicable
                if (hdr.load_response_metadata.isValid()) {
                    set_register(hdr.load_response_metadata.register, hdr.load_response_metadata.value);
                    hdr.load_response_metadata.setInvalid();
                }
                insn_opcode.apply();
                hdr.program_execution_metadata.steps = hdr.program_execution_metadata.steps + 1;
                // Forward to self if execution is not complete
                if (hdr.program_execution_metadata.steps < hdr.program_metadata.max_steps) {
                    standard_metadata.egress_spec = standard_metadata.ingress_port;
                    recirculate({meta, standard_metadata});
                }
                // Forward back to load balancer when execution steps are exhausted
                else {
                    standard_metadata.egress_spec = LOAD_BALANCER_PORT;
                }
                write_all_registers();
            }
            // Forward back to load balancer if no more instructions to execute
            else {
                standard_metadata.egress_spec = LOAD_BALANCER_PORT;
            }
        }
        else if (switch_role == ROLE_DATASTORE) {
            if (standard_metadata.ingress_port == DATASTORE_HOST_PORT) {
                // Forward back to the source execution unit
                // If not load response, then strip load/store request header before forwarding back
                if (hdr.load_response_metadata.isValid()) {
                    target_execution_node_id = hdr.load_response_metadata.execution_node;
                }
                else if (hdr.load_request_metadata.isValid()) {
                    target_execution_node_id = hdr.load_request_metadata.execution_node;
                    hdr.load_request_metadata.setInvalid();
                }
                else if (hdr.store_request_metadata.isValid()) {
                    target_execution_node_id = hdr.store_request_metadata.execution_node;
                    hdr.store_request_metadata.setInvalid();
                }
                else {
                    drop();
                }
                datastore_response_map.apply();
            }
            else {
                // Forward to data store host
                standard_metadata.egress_spec = DATASTORE_HOST_PORT;
                hdr.ethernet.srcAddr = hdr.program_execution_metadata.src_mac;
                hdr.ethernet.dstAddr = DATASTORE_MAC;
                hdr.ipv4.srcAddr = hdr.program_execution_metadata.src_ipv4;
                hdr.ipv4.dstAddr = DATASTORE_IP;
            }
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
        packet.emit(hdr.program_execution_metadata);
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
