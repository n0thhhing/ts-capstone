export interface cs_mos65xx_op {
  type: MOS65XX; // operand type
  reg?: MOS65XX; // register value for REG operand
  imm?: number; // immediate value for IMM operand
  mem?: number; // address for MEM operand
}

export enum MOS65XX {
  // MOS65XX registers and special registers
  REG_INVALID = 0,
  REG_ACC = 1, // accumulator
  REG_X = 2, // X index register
  REG_Y = 3, // Y index register
  REG_P = 4, // status register
  REG_SP = 5, // stack pointer register
  REG_DP = 6, // direct page register
  REG_B = 7, // data bank register
  REG_K = 8, // program bank register
  REG_ENDING = 9, // mark the end of the list of registers

  // MOS65XX Addressing Modes
  AM_NONE = 0, // No address mode.
  AM_IMP = 1, // implied addressing (no addressing mode)
  AM_ACC = 2, // accumulator addressing
  AM_IMM = 3, // 8/16 Bit immediate value
  AM_REL = 4, // relative addressing used by branches
  AM_INT = 5, // interrupt addressing
  AM_BLOCK = 6, // memory block addressing
  AM_ZP = 7, // zeropage addressing
  AM_ZP_X = 8, // indexed zeropage addressing by the X index register
  AM_ZP_Y = 8, // indexed zeropage addressing by the Y index register
  AM_ZP_REL = 10, // zero page address, branch relative address
  AM_ZP_IND = 11, // indirect zeropage addressing
  AM_ZP_X_IND = 12, // indexed zeropage indirect addressing by the X index register
  AM_ZP_IND_Y = 13, // indirect zeropage indexed addressing by the Y index register
  AM_ZP_IND_LONG = 14, // zeropage indirect long addressing
  AM_ZP_IND_LONG_Y = 15, // zeropage indirect long addressing indexed by Y register
  AM_ABS = 16, // absolute addressing
  AM_ABS_X = 17, // indexed absolute addressing by the X index register
  AM_ABS_Y = 18, // indexed absolute addressing by the Y index register
  AM_ABS_IND = 19, // absolute indirect addressing
  AM_ABS_X_IND = 20, // indexed absolute indirect addressing by the X index register
  AM_ABS_IND_LONG = 21, // absolute indirect long addressing
  AM_ABS_LONG = 22, // absolute long address mode
  AM_ABS_LONG_X = 23, // absolute long address mode, indexed by X register
  AM_SR = 24, // stack relative addressing
  AM_SR_IND_Y = 25, // indirect stack relative addressing indexed by the Y index register

  // MOS65XX instruction
  INS_INVALID = 0,
  INS_ADC = 1,
  INS_AND = 2,
  INS_ASL = 3,
  INS_BBR = 4,
  INS_BBS = 5,
  INS_BCC = 6,
  INS_BCS = 7,
  INS_BEQ = 8,
  INS_BIT = 9,
  INS_BMI = 10,
  INS_BNE = 11,
  INS_BPL = 12,
  INS_BRA = 13,
  INS_BRK = 14,
  INS_BRL = 15,
  INS_BVC = 16,
  INS_BVS = 17,
  INS_CLC = 18,
  INS_CLD = 19,
  INS_CLI = 20,
  INS_CLV = 21,
  INS_CMP = 22,
  INS_COP = 23,
  INS_CPX = 24,
  INS_CPY = 25,
  INS_DEC = 26,
  INS_DEX = 27,
  INS_DEY = 28,
  INS_EOR = 29,
  INS_INC = 30,
  INS_INX = 31,
  INS_INY = 32,
  INS_JML = 33,
  INS_JMP = 34,
  INS_JSL = 35,
  INS_JSR = 36,
  INS_LDA = 37,
  INS_LDX = 38,
  INS_LDY = 39,
  INS_LSR = 40,
  INS_MVN = 41,
  INS_MVP = 42,
  INS_NOP = 43,
  INS_ORA = 44,
  INS_PEA = 45,
  INS_PEI = 46,
  INS_PER = 47,
  INS_PHA = 48,
  INS_PHB = 49,
  INS_PHD = 50,
  INS_PHK = 51,
  INS_PHP = 52,
  INS_PHX = 53,
  INS_PHY = 54,
  INS_PLA = 55,
  INS_PLB = 56,
  INS_PLD = 57,
  INS_PLP = 58,
  INS_PLX = 59,
  INS_PLY = 60,
  INS_REP = 61,
  INS_RMB = 62,
  INS_ROL = 63,
  INS_ROR = 64,
  INS_RTI = 65,
  INS_RTL = 66,
  INS_RTS = 67,
  INS_SBC = 68,
  INS_SEC = 69,
  INS_SED = 70,
  INS_SEI = 71,
  INS_SEP = 72,
  INS_SMB = 73,
  INS_STA = 74,
  INS_STP = 75,
  INS_STX = 76,
  INS_STY = 77,
  INS_STZ = 78,
  INS_TAX = 79,
  INS_TAY = 80,
  INS_TCD = 81,
  INS_TCS = 82,
  INS_TDC = 83,
  INS_TRB = 84,
  INS_TSB = 85,
  INS_TSC = 86,
  INS_TSX = 87,
  INS_TXA = 88,
  INS_TXS = 89,
  INS_TXY = 90,
  INS_TYA = 91,
  INS_TYX = 92,
  INS_WAI = 93,
  INS_WDM = 94,
  INS_XBA = 95,
  INS_XCE = 96,
  INS_ENDING = 97, // mark the end of the list of instructions

  // Group of MOS65XX instructions
  GRP_INVALID = 0, ///< cs.GRP_INVALID
  GRP_JUMP = 1, // cs.GRP_JUMP
  GRP_CALL = 2, // cs.GRP_RET
  GRP_RET = 3, // cs.GRP_RET
  GRP_INT = 4, // cs.GRP_INT
  GRP_IRET = 5, // cs.GRP_IRET
  GRP_BRANCH_RELATIVE = 6, // cs.GRP_BRANCH_RELATIVE
  GRP_ENDING = 7, // mark the end of the list of groups

  // Operand type for instruction's operands
  OP_INVALID = 0, // cs.OP_INVALID (Uninitialized).
  OP_REG = 1, // cs.OP_REG (Register operand).
  OP_IMM = 2, // cs.OP_IMM (Immediate operand).
  OP_MEM = 3, // cs.OP_MEM (Memory operand).
}

export class cs_mos65xx {
  public am: MOS65XX;
  public modifies_flags: boolean;
  public op_count: number; // Number of operands of this instruction, or 0 when instruction has no operand.
  public operands: cs_mos65xx_op[]; // operands for this instruction.

  constructor(arch_info_ptr: number, Memory: any) {
    this.operands = [];
    this.am = Memory.read(arch_info_ptr + 0, 'i32');
    this.modifies_flags = Memory.read(arch_info_ptr + 4, 'bool');
    this.op_count = Memory.read(arch_info_ptr + 5, 'ubyte');
    for (let i = 0; i < this.op_count; i++) {
      const op: cs_mos65xx_op = {} as cs_mos65xx_op;
      const op_ptr: number = arch_info_ptr + 8 + i * 8;
      op.type = Memory.read(op_ptr, 'i32');
      switch (op.type) {
        case MOS65XX.OP_REG:
          op.reg = Memory.read(op_ptr + 4, 'i32');
          break;
        case MOS65XX.OP_IMM:
          op.imm = Memory.read(op_ptr + 4, 'i32');
          break;
        case MOS65XX.OP_MEM:
          op.mem = Memory.read(op_ptr + 4, 'i32');
          break;
      }
      this.operands[i] = op;
    }
    return this;
  }
}
