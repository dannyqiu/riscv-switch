const bit<8>  PROTO_PROGRAM = 0x0;

const bit<32> NUM_REGISTERS = 32;
const bit<32> MAX_INSNS = 350;

/*******************************************************************************
*********************** M E T A D A T A ****************************************
*******************************************************************************/

header register_t {
    bit<32>   value;
}

header program_metadata_t {
    bit<16>   src;
    bit<32>   pc;
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

header insn_t {
    bit<1>   bos;
    bit<8>   opcode;
    bit<5>   dst;
    bit<5>   src;
    bit<5>   target;
    bit<11>  imm;
}
