export interface cs_sh_op {
  type: SH;
  imm?: number; // immediate value for IMM operand
  reg?: SH; // register value for REG operand
  mem?: {
    // data when operand is targeting memory
    address: SH; // memory address
    reg: SH; // base register
    disp: number; // displacement
  };
}

export enum SH {
  // SH registers and special registers
  REG_INVALID = 0,

  REG_R0,
  REG_R1,
  REG_R2,
  REG_R3,
  REG_R4,
  REG_R5,
  REG_R6,
  REG_R7,

  REG_R8,
  REG_R9,
  REG_R10,
  REG_R11,
  REG_R12,
  REG_R13,
  REG_R14,
  REG_R15,

  REG_R0_BANK,
  REG_R1_BANK,
  REG_R2_BANK,
  REG_R3_BANK,
  REG_R4_BANK,
  REG_R5_BANK,
  REG_R6_BANK,
  REG_R7_BANK,

  REG_FR0,
  REG_FR1,
  REG_FR2,
  REG_FR3,
  REG_FR4,
  REG_FR5,
  REG_FR6,
  REG_FR7,
  REG_FR8,
  REG_FR9,
  REG_FR10,
  REG_FR11,
  REG_FR12,
  REG_FR13,
  REG_FR14,
  REG_FR15,

  REG_DR0,
  REG_DR2,
  REG_DR4,
  REG_DR6,
  REG_DR8,
  REG_DR10,
  REG_DR12,
  REG_DR14,

  REG_XD0,
  REG_XD2,
  REG_XD4,
  REG_XD6,
  REG_XD8,
  REG_XD10,
  REG_XD12,
  REG_XD14,

  REG_XF0,
  REG_XF1,
  REG_XF2,
  REG_XF3,
  REG_XF4,
  REG_XF5,
  REG_XF6,
  REG_XF7,
  REG_XF8,
  REG_XF9,
  REG_XF10,
  REG_XF11,
  REG_XF12,
  REG_XF13,
  REG_XF14,
  REG_XF15,

  REG_FV0,
  REG_FV4,
  REG_FV8,
  REG_FV12,

  REG_XMATRX,

  REG_PC,
  REG_PR,
  REG_MACH,
  REG_MACL,

  REG_SR,
  REG_GBR,
  REG_SSR,
  REG_SPC,
  REG_SGR,
  REG_DBR,
  REG_VBR,
  REG_TBR,
  REG_RS,
  REG_RE,
  REG_MOD,

  REG_FPUL,
  REG_FPSCR,

  REG_DSP_X0,
  REG_DSP_X1,
  REG_DSP_Y0,
  REG_DSP_Y1,
  REG_DSP_A0,
  REG_DSP_A1,
  REG_DSP_A0G,
  REG_DSP_A1G,
  REG_DSP_M0,
  REG_DSP_M1,
  REG_DSP_DSR,

  REG_DSP_RSV0,
  REG_DSP_RSV1,
  REG_DSP_RSV2,
  REG_DSP_RSV3,
  REG_DSP_RSV4,
  REG_DSP_RSV5,
  REG_DSP_RSV6,
  REG_DSP_RSV7,
  REG_DSP_RSV8,
  REG_DSP_RSV9,
  REG_DSP_RSVA,
  REG_DSP_RSVB,
  REG_DSP_RSVC,
  REG_DSP_RSVD,
  REG_DSP_RSVE,
  REG_DSP_RSVF,

  REG_ENDING, // mark the end of the list of registers

  OP_INVALID = 0, // = cs.OP_INVALID (Uninitialized).
  OP_REG = 1, // = cs.OP_REG (Register operand).
  OP_IMM = 2, // = cs.OP_IMM (Immediate operand).
  OP_MEM = 3, // = cs.OP_MEM (Memory operand).

  OP_MEM_INVALID = 0, // Invalid
  OP_MEM_REG_IND = 1, // Register indirect
  OP_MEM_REG_POST = 2, // Register post increment
  OP_MEM_REG_PRE = 3, // Register pre decrement
  OP_MEM_REG_DISP = 4, // displacement
  OP_MEM_REG_R0 = 5, // R0 indexed
  OP_MEM_GBR_DISP = 6, // GBR based displacement
  OP_MEM_GBR_R0 = 7, // GBR based R0 indexed
  OP_MEM_PCR = 8, // PC relative
  OP_MEM_TBR_DISP = 9, // TBR based displaysment

  // SH-DSP instructions define
  INS_DSP_INVALID = 0,
  INS_DSP_DOUBLE = 1,
  INS_DSP_SINGLE = 2,
  INS_DSP_PARALLEL = 3,

  OP_DSP_INVALID = 0,
  OP_DSP_REG_PRE = 1,
  OP_DSP_REG_IND = 2,
  OP_DSP_REG_POST = 3,
  OP_DSP_REG_INDEX = 4,
  OP_DSP_REG = 5,
  OP_DSP_IMM = 6,

  DSP_CC_INVALID = 0,
  DSP_CC_NONE = 1,
  DSP_CC_DCT = 2,
  DSP_CC_DCF = 3,

  INS_DSP_NOP = 1,
  INS_DSP_MOV = 2,
  INS_DSP_PSHL = 3,
  INS_DSP_PSHA = 4,
  INS_DSP_PMLS = 5,
  INS_DSP_PCLR_PMLS = 6,
  INS_DSP_PSB_PMLS = 7,
  INS_DSP_PADD_PMLS = 8,
  INS_DSP_PSBC = 9,
  INS_DSP_PADDC = 10,
  INS_DSP_PCMP = 11,
  INS_DSP_PABS = 12,
  INS_DSP_PRND = 13,
  INS_DSP_PSB = 14,
  INS_DSP_PSBr = 15,
  INS_DSP_PADD = 16,
  INS_DSP_PAND = 17,
  INS_DSP_PXOR = 18,
  INS_DSP_POR = 19,
  INS_DSP_PDEC = 20,
  INS_DSP_PINC = 21,
  INS_DSP_PCLR = 22,
  INS_DSP_PDMSB = 23,
  INS_DSP_PNEG = 24,
  INS_DSP_PCOPY = 25,
  INS_DSP_PSTS = 26,
  INS_DSP_PLDS = 27,
  INS_DSP_PSWAP = 28,
  INS_DSP_PWAD = 29,
  INS_DSP_PWSB = 30,

  // SH instruction
  INS_INVALID = 0,
  INS_ADD_r = 1,
  INS_ADD = 2,
  INS_ADDC = 3,
  INS_ADDV = 4,
  INS_AND = 5,
  INS_BAND = 6,
  INS_BANDNOT = 7,
  INS_BCLR = 8,
  INS_BF = 9,
  INS_BF_S = 10,
  INS_BLD = 11,
  INS_BLDNOT = 12,
  INS_BOR = 13,
  INS_BORNOT = 14,
  INS_BRA = 15,
  INS_BRAF = 16,
  INS_BSET = 17,
  INS_BSR = 18,
  INS_BSRF = 19,
  INS_BST = 20,
  INS_BT = 21,
  INS_BT_S = 22,
  INS_BXOR = 23,
  INS_CLIPS = 24,
  INS_CLIP = 25,
  INS_CLRDMXY = 26,
  INS_CLRMAC = 27,
  INS_CLRS = 28,
  INS_CLRT = 29,
  INS_CMP_EQ = 30,
  INS_CMP_GE = 31,
  INS_CMP_GT = 32,
  INS_CMP_HI = 33,
  INS_CMP_HS = 34,
  INS_CMP_PL = 35,
  INS_CMP_PZ = 36,
  INS_CMP_STR = 37,
  INS_DIV0S = 38,
  INS_DIV0 = 39,
  INS_DIV1 = 40,
  INS_DIVS = 41,
  INS_DIV = 42,
  INS_DMLS_L = 43,
  INS_DML_L = 44,
  INS_DT = 45,
  INS_EXTS_B = 46,
  INS_EXTS_W = 47,
  INS_EXT_B = 48,
  INS_EXT_W = 49,
  INS_FABS = 50,
  INS_FADD = 51,
  INS_FCMP_EQ = 52,
  INS_FCMP_GT = 53,
  INS_FCNVDS = 54,
  INS_FCNVSD = 55,
  INS_FDIV = 56,
  INS_FIPR = 57,
  INS_FLDI0 = 58,
  INS_FLDI1 = 59,
  INS_FLDS = 60,
  INS_FLOAT = 61,
  INS_FMAC = 62,
  INS_FMOV = 63,
  INS_FML = 64,
  INS_FNEG = 65,
  INS_FPCHG = 66,
  INS_FRCHG = 67,
  INS_FSCA = 68,
  INS_FSCHG = 69,
  INS_FSQRT = 70,
  INS_FSRRA = 71,
  INS_FSTS = 72,
  INS_FSB = 73,
  INS_FTRC = 74,
  INS_FTRV = 75,
  INS_ICBI = 76,
  INS_JMP = 77,
  INS_JSR = 78,
  INS_JSR_N = 79,
  INS_LDBANK = 80,
  INS_LDC = 81,
  INS_LDRC = 82,
  INS_LDRE = 83,
  INS_LDRS = 84,
  INS_LDS = 85,
  INS_LDTLB = 86,
  INS_MAC_L = 87,
  INS_MAC_W = 88,
  INS_MOV = 89,
  INS_MOVA = 90,
  INS_MOVCA = 91,
  INS_MOVCO = 92,
  INS_MOVI20 = 93,
  INS_MOVI20S = 94,
  INS_MOVLI = 95,
  INS_MOVML = 96,
  INS_MOVM = 97,
  INS_MOVRT = 98,
  INS_MOVT = 99,
  INS_ML_L = 100,
  INS_MLR = 101,
  INS_MLS_W = 102,
  INS_ML_W = 103,
  INS_NEG = 104,
  INS_NEGC = 105,
  INS_NOP = 106,
  INS_NOT = 107,
  INS_NOTT = 108,
  INS_OCBI = 109,
  INS_OCBP = 110,
  INS_OCBWB = 111,
  INS_OR = 112,
  INS_PREF = 113,
  INS_PREFI = 114,
  INS_RESBANK = 115,
  INS_ROTCL = 116,
  INS_ROTCR = 117,
  INS_ROTL = 118,
  INS_ROTR = 119,
  INS_RTE = 120,
  INS_RTS = 121,
  INS_RTS_N = 122,
  INS_RTV_N = 123,
  INS_SETDMX = 124,
  INS_SETDMY = 125,
  INS_SETRC = 126,
  INS_SETS = 127,
  INS_SETT = 128,
  INS_SHAD = 129,
  INS_SHAL = 130,
  INS_SHAR = 131,
  INS_SHLD = 132,
  INS_SHLL = 133,
  INS_SHLL16 = 134,
  INS_SHLL2 = 135,
  INS_SHLL8 = 136,
  INS_SHLR = 137,
  INS_SHLR16 = 138,
  INS_SHLR2 = 139,
  INS_SHLR8 = 140,
  INS_SLEEP = 141,
  INS_STBANK = 142,
  INS_STC = 143,
  INS_STS = 144,
  INS_SB = 145,
  INS_SBC = 146,
  INS_SBV = 147,
  INS_SWAP_B = 148,
  INS_SWAP_W = 149,
  INS_SYNCO = 150,
  INS_TAS = 151,
  INS_TRAPA = 152,
  INS_TST = 153,
  INS_XOR = 154,
  INS_XTRCT = 155,
  INS_DSP = 156,
  INS_ENDING = 157, // mark the end of the list of instructions

  GRP_INVALID = 0, // cs.GRP_INVALID
  GRP_JMP = 1, // = cs.GRP_JMP
  GRP_CALL = 2, // = cs.GRP_CALL
  GRP_INT = 3, // = cs.GRP_INT
  GRP_RET = 4, // = cs.GRP_RET
  GRP_IRET = 5, // = cs.GRP_IRET
  GRP_PRIVILEGE = 6, // = cs.GRP_PRIVILEGE
  GRP_BRANCH_RELATIVE = 7, // = cs.GRP_BRANCH_RELATIVE
  GRP_SH1 = 8,
  GRP_SH2 = 9,
  GRP_SH2E = 10,
  GRP_SH2DSP = 11,
  GRP_SH2A = 12,
  GRP_SH2AFP = 13,
  GRP_SH3 = 14,
  GRP_SH3DSP = 15,
  GRP_SH4 = 16,
  GRP_SH4A = 17,
  GRP_ENDING = 18, // mark the end of the list of groups
}

export class cs_sh {
  public insn: SH;
  public size: number;
  public op_count: number;
  public operands: cs_sh_op[];

  constructor(arch_info_ptr: number, Memory: any) {
    this.operands = [];
    this.insn = Memory.read(arch_info_ptr + 0, 'u32');
    this.size = Memory.read(arch_info_ptr + 4, 'ubyte');
    this.op_count = Memory.read(arch_info_ptr + 5, 'ubyte');
    for (let i = 0; i < this.op_count; i++) {
      const op: cs_sh_op = {} as cs_sh_op;
      const op_ptr: number = arch_info_ptr + 8 + i * 58;
      op.type = Memory.read(op_ptr + 0, 'i32');
      switch (op.type) {
        case SH.OP_IMM:
          op.imm = Memory.read(op_ptr + 8, 'i64');
          break;
        case SH.OP_REG:
          op.reg = Memory.read(op_ptr + 8, 'i32');
          break;
        case SH.OP_MEM:
          op.mem = {
            address: Memory.read(op_ptr + 8, 'i32'),
            reg: Memory.read(op_ptr + 12, 'i32'),
            disp: Memory.read(op_ptr + 16, 'i32'),
          };
          break;
      }
      this.operands[i] = op;
    }
    return this;
  }
}
