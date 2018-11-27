const bit<8>  PROTO_RAW_PROGRAM = 0x8F;
const bit<8>  PROTO_PROGRAM = 0x90;

const bit<32> NUM_REGISTERS = 32;
const bit<32> MAX_INSNS = 300;

// Load balancer is connected to all execution units via port 1
const bit<9>  LOAD_BALANCER_PORT = 1;
// Data store is connected to all execution units via port 2
const bit<9>  DATASTORE_PORT = 2;
const bit<48> LOAD_BALANCER_MAC = 0xFFFFFFFFFFFF;
const bit<32> LOAD_BALANCER_IP = 0xFFFFFFFF;

/*******************************************************************************
*********************** M E T A D A T A ****************************************
*******************************************************************************/

header register_t {
    bit<32>   value;
}

header program_metadata_t {
    bit<32>   max_steps;
}

header program_execution_metadata_t {
    // Ingress port to the load balancer from the source host
    bit<9>    src_port;
    // Padding to make header word-aligned
    bit<3>    reserved;
    // MAC address of the source host
    bit<48>   src_mac;
    // IPv4 address of the source host
    bit<32>   src_ipv4;
    bit<32>   pc;
    bit<32>   steps;
    bit<32>   mem_namespace;
}

/*******************************************************************************
*********************** A S S E M B L Y ****************************************
*******************************************************************************/

const bit<8> ADD  = 0b00000000;
const bit<8> ADDI = 0b10000000;
const bit<8> SUB  = 0b00000001;
const bit<8> SUBI = 0b10000001;
const bit<8> MUL  = 0b00000010;
const bit<8> MULI = 0b10000010;
const bit<8> DIV  = 0b00000011;
const bit<8> DIVI = 0b10000011;

header insn_unknown_t {
    bit<7>  funct7;
    bit<5>  part1;
    bit<5>  part2;
    bit<3>  funct3;
    bit<5>  part3;
    bit<7>  opcode;
}

header insn_rtype_t {
    bit<7>  funct7;
    bit<5>  rs2;
    bit<5>  rs1;
    bit<3>  funct3;
    bit<5>  rd;
    bit<7>  opcode;
}

header insn_itype_t {
    bit<12> imm;
    bit<5>  rs1;
    bit<3>  funct3;
    bit<5>  rd;
    bit<7>  opcode;
}

header insn_stype_t {
    bit<7>  imm_upper;
    bit<5>  rs2;
    bit<5>  rs1;
    bit<3>  funct3;
    bit<5>  imm_lower;
    bit<7>  opcode;
}

header insn_utype_t {
    bit<20> imm;
    bit<5>  rd;
    bit<7>  opcode;
}

// header_union is not fully supported in P4lang
// Specifically, we cannot create a header_union stack in a struct
header_union insn_t {
    insn_rtype_t   rtype;
    insn_itype_t   itype;
    insn_stype_t   stype;
    insn_utype_t   utype;
    insn_unknown_t unknown;
}
