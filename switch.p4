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
            32w0: accept;
            default: parse_insn;
        }
    }

    state parse_insn {
        packet.extract(hdr.insns.next);
        insns_to_current = insns_to_current - 1;
        transition select(insns_to_current) {
            0xffffffff: set_current_insn;
            default: parse_insns;
        }
    }

    // save current PC instruction during parsing, since we cannot access arrays
    // with non-constant values in the other stages
    state set_current_insn {
        meta.current_insn = hdr.insns.last;
        meta.current_insn.setValid();
        transition parse_insns;
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

    action handle_rtype() {

    }

    action handle_itype() {

    }

    action handle_stype() {

    }

    action handle_utype() {

    }

    table insn_opcode_exact {
        key = {
            meta.current_insn.opcode: exact;
        }
        actions = {
            handle_rtype;
            handle_itype;
            handle_stype;
            handle_utype;
            NoAction();
        }
        size = 1024;
        default_action = NoAction();
    }

    apply {
        if (hdr.ipv4.isValid()) {
            ipv4_lpm.apply();
        }
        else if (meta.current_insn.isValid()) {
            insn_opcode_exact.apply();
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
