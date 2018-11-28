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
        value = 0;
        GET_REG_PRIMARY(r, 0, value)
        GET_REG_OTHERWISE(r, 1, value)
        GET_REG_OTHERWISE(r, 2, value)
        GET_REG_OTHERWISE(r, 3, value)
        GET_REG_OTHERWISE(r, 4, value)
        GET_REG_OTHERWISE(r, 5, value)
        GET_REG_OTHERWISE(r, 6, value)
        GET_REG_OTHERWISE(r, 7, value)
        GET_REG_OTHERWISE(r, 8, value)
        GET_REG_OTHERWISE(r, 9, value)
        GET_REG_OTHERWISE(r, 10, value)
        GET_REG_OTHERWISE(r, 11, value)
        GET_REG_OTHERWISE(r, 12, value)
        GET_REG_OTHERWISE(r, 13, value)
        GET_REG_OTHERWISE(r, 14, value)
        GET_REG_OTHERWISE(r, 15, value)
        GET_REG_OTHERWISE(r, 16, value)
        GET_REG_OTHERWISE(r, 17, value)
        GET_REG_OTHERWISE(r, 18, value)
        GET_REG_OTHERWISE(r, 19, value)
        GET_REG_OTHERWISE(r, 20, value)
        GET_REG_OTHERWISE(r, 21, value)
        GET_REG_OTHERWISE(r, 22, value)
        GET_REG_OTHERWISE(r, 23, value)
        GET_REG_OTHERWISE(r, 24, value)
        GET_REG_OTHERWISE(r, 25, value)
        GET_REG_OTHERWISE(r, 26, value)
        GET_REG_OTHERWISE(r, 27, value)
        GET_REG_OTHERWISE(r, 28, value)
        GET_REG_OTHERWISE(r, 29, value)
        GET_REG_OTHERWISE(r, 30, value)
        GET_REG_OTHERWISE(r, 31, value)
    }

    action set_register(in bit<5> r, in bit<32> value) {
        // Zero-register must always contain zero
        SET_REG_PRIMARY(r, 0, 0)
        SET_REG_OTHERWISE(r, 1, value)
        SET_REG_OTHERWISE(r, 2, value)
        SET_REG_OTHERWISE(r, 3, value)
        SET_REG_OTHERWISE(r, 4, value)
        SET_REG_OTHERWISE(r, 5, value)
        SET_REG_OTHERWISE(r, 6, value)
        SET_REG_OTHERWISE(r, 7, value)
        SET_REG_OTHERWISE(r, 8, value)
        SET_REG_OTHERWISE(r, 9, value)
        SET_REG_OTHERWISE(r, 10, value)
        SET_REG_OTHERWISE(r, 11, value)
        SET_REG_OTHERWISE(r, 12, value)
        SET_REG_OTHERWISE(r, 13, value)
        SET_REG_OTHERWISE(r, 14, value)
        SET_REG_OTHERWISE(r, 15, value)
        SET_REG_OTHERWISE(r, 16, value)
        SET_REG_OTHERWISE(r, 17, value)
        SET_REG_OTHERWISE(r, 18, value)
        SET_REG_OTHERWISE(r, 19, value)
        SET_REG_OTHERWISE(r, 20, value)
        SET_REG_OTHERWISE(r, 21, value)
        SET_REG_OTHERWISE(r, 22, value)
        SET_REG_OTHERWISE(r, 23, value)
        SET_REG_OTHERWISE(r, 24, value)
        SET_REG_OTHERWISE(r, 25, value)
        SET_REG_OTHERWISE(r, 26, value)
        SET_REG_OTHERWISE(r, 27, value)
        SET_REG_OTHERWISE(r, 28, value)
        SET_REG_OTHERWISE(r, 29, value)
        SET_REG_OTHERWISE(r, 30, value)
        SET_REG_OTHERWISE(r, 31, value)
    }

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
        get_register(addi.rs1, r1);
        set_register(addi.rd, r1 + (bit<32>) addi.imm);
        advance_pc();
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
            advance_pc();
        }
        default_action = advance_pc();
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

    action configure_switch(bit<32> id, bit<2> role, bit<32> n_execution_units, bit<32> n_hosts) {
        switch_id = id;
        switch_role = role;
        num_execution_units = n_execution_units;
        num_hosts = n_hosts;
    }

    table configuration {
        key = {
        }
        actions = {
            configure_switch();
            drop;
        }
        size = 1024;
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
            forward_to_execution_node();
            drop;
        }
        size = 1024;
        default_action = drop();
    }

    table datastore_response_map {
        key = {
            target_execution_node_id: exact;
        }
        actions = {
            forward_to_execution_node();
            drop;
        }
        size = 1024;
        default_action = drop();
    }

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
        size = 1024;
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
                // Apply load response if applicable
                if (hdr.load_response_metadata.isValid()) {
                    set_register(hdr.load_response_metadata.register, hdr.load_response_metadata.value);
                    hdr.load_response_metadata.setInvalid();
                }
                insn_opcode_exact.apply();
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
