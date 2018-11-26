#include "assembly.p4"

/*************************************************************************
*********************** H E A D E R S  ***********************************
*************************************************************************/

const bit<16> TYPE_IPV4 = 0x800;
const bit<8>  PROTO_TCP = 0x6;
const bit<8>  PROTO_UDP = 0x11;

header ethernet_t {
    bit<48>   dstAddr;
    bit<48>   srcAddr;
    bit<16>   etherType;
}

header ipv4_t {
    bit<4>    version;
    bit<4>    ihl;
    bit<8>    diffserv;
    bit<16>   totalLen;
    bit<16>   identification;
    bit<3>    flags;
    bit<13>   fragOffset;
    bit<8>    ttl;
    bit<8>    protocol;
    bit<16>   hdrChecksum;
    bit<32>   srcAddr;
    bit<32>   dstAddr;
}

header tcp_t {
    bit<16>   srcPort;
    bit<16>   dstPort;
    bit<32>   seqNo;
    bit<32>   ackNo;
    bit<4>    dataOffset;
    bit<3>    reserved;
    bit<9>    flags;
    bit<16>   windowSize;
    bit<16>   tcpChecksum;
}

header udp_t {
    bit<16>   srcPort;
    bit<16>   dstPort;
    bit<16>   len;
    bit<16>   checksum;
}

struct metadata {
    insn_unknown_t   current_insn;
}

struct headers {
    ethernet_t   ethernet;
    ipv4_t       ipv4;
    tcp_t        tcp;
    udp_t        udp;

    program_metadata_t          program_metadata;
    register_t[NUM_REGISTERS]   registers;
    insn_unknown_t[MAX_INSNS]   insns;
}
