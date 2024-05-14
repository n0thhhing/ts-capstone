export interface cs_tms320c64x_op {
  type: TMS320C64X; // operand type
  reg?: TMS320C64X; // register value for REG operand or first register for REGPAIR operand
  imm?: number; // immediate value for IMM operand
  mem?: {
    // base/disp value for MEM operand
    base: number; // base register
    disp: number; // displacement/offset value
    unit: number; // unit of base and offset register
    scaled: number; // offset scaled
    disptype: number; // displacement type
    direction: number; // direction
    modify: number; // modification
  };
}

export enum TMS320C64X {
  OP_INVALID = 0, // cs.OP_INVALID (Uninitialized).
  OP_REG = 1, // cs.OP_REG (Register operand).
  OP_IMM = 2, // cs.OP_IMM (Immediate operand).
  OP_MEM = 3, // cs.OP_MEM (Memory operand).
  OP_REGPAIR = 64, // Register pair for double word ops

  MEM_DISP_INVALID = 0,
  MEM_DISP_CONSTANT = 1,
  MEM_DISP_REGISTER = 2,

  MEM_DIR_INVALID = 0,
  MEM_DIR_FW = 1,
  MEM_DIR_BW = 2,

  MEM_MOD_INVALID = 0,
  MEM_MOD_NO = 1,
  MEM_MOD_PRE = 2,
  MEM_MOD_POST = 3,

  REG_INVALID = 0,
  REG_AMR = 1,
  REG_CSR = 2,
  REG_DIER = 3,
  REG_DNUM = 4,
  REG_ECR = 5,
  REG_GFPGFR = 6,
  REG_GPLYA = 7,
  REG_GPLYB = 8,
  REG_ICR = 9,
  REG_IER = 10,
  REG_IERR = 11,
  REG_ILC = 12,
  REG_IRP = 13,
  REG_ISR = 14,
  REG_ISTP = 15,
  REG_ITSR = 16,
  REG_NRP = 17,
  REG_NTSR = 18,
  REG_REP = 19,
  REG_RILC = 20,
  REG_SSR = 21,
  REG_TSCH = 22,
  REG_TSCL = 23,
  REG_TSR = 24,
  REG_A0 = 25,
  REG_A1 = 26,
  REG_A2 = 27,
  REG_A3 = 28,
  REG_A4 = 29,
  REG_A5 = 30,
  REG_A6 = 31,
  REG_A7 = 32,
  REG_A8 = 33,
  REG_A9 = 34,
  REG_A10 = 35,
  REG_A11 = 36,
  REG_A12 = 37,
  REG_A13 = 38,
  REG_A14 = 39,
  REG_A15 = 40,
  REG_A16 = 41,
  REG_A17 = 42,
  REG_A18 = 43,
  REG_A19 = 44,
  REG_A20 = 45,
  REG_A21 = 46,
  REG_A22 = 47,
  REG_A23 = 48,
  REG_A24 = 49,
  REG_A25 = 50,
  REG_A26 = 51,
  REG_A27 = 52,
  REG_A28 = 53,
  REG_A29 = 54,
  REG_A30 = 55,
  REG_A31 = 56,
  REG_B0 = 57,
  REG_B1 = 58,
  REG_B2 = 59,
  REG_B3 = 60,
  REG_B4 = 61,
  REG_B5 = 62,
  REG_B6 = 63,
  REG_B7 = 64,
  REG_B8 = 65,
  REG_B9 = 66,
  REG_B10 = 67,
  REG_B11 = 68,
  REG_B12 = 69,
  REG_B13 = 70,
  REG_B14 = 71,
  REG_B15 = 72,
  REG_B16 = 73,
  REG_B17 = 74,
  REG_B18 = 75,
  REG_B19 = 76,
  REG_B20 = 77,
  REG_B21 = 78,
  REG_B22 = 79,
  REG_B23 = 80,
  REG_B24 = 81,
  REG_B25 = 82,
  REG_B26 = 83,
  REG_B27 = 84,
  REG_B28 = 85,
  REG_B29 = 86,
  REG_B30 = 87,
  REG_B31 = 88,
  REG_PCE1 = 89,
  REG_ENDING = 90, // mark the end of the list of registers

  // Alias registers
  REG_EFR = TMS320C64X.REG_ECR,
  REG_IFR = TMS320C64X.REG_ISR,

  INS_INVALID = 0,
  INS_ABS = 1,
  INS_ABS2 = 2,
  INS_ADD = 3,
  INS_ADD2 = 4,
  INS_ADD4 = 5,
  INS_ADDAB = 6,
  INS_ADDAD = 7,
  INS_ADDAH = 8,
  INS_ADDAW = 9,
  INS_ADDK = 10,
  INS_ADDKPC = 11,
  INS_ADDU = 12,
  INS_AND = 13,
  INS_ANDN = 14,
  INS_AVG2 = 15,
  INS_AVGU4 = 16,
  INS_B = 17,
  INS_BDEC = 18,
  INS_BITC4 = 19,
  INS_BNOP = 20,
  INS_BPOS = 21,
  INS_CLR = 22,
  INS_CMPEQ = 23,
  INS_CMPEQ2 = 24,
  INS_CMPEQ4 = 25,
  INS_CMPGT = 26,
  INS_CMPGT2 = 27,
  INS_CMPGTU4 = 28,
  INS_CMPLT = 29,
  INS_CMPLTU = 30,
  INS_DEAL = 31,
  INS_DOTP2 = 32,
  INS_DOTPN2 = 33,
  INS_DOTPNRSU2 = 34,
  INS_DOTPRSU2 = 35,
  INS_DOTPSU4 = 36,
  INS_DOTPU4 = 37,
  INS_EXT = 38,
  INS_EXTU = 39,
  INS_GMPGTU = 40,
  INS_GMPY4 = 41,
  INS_LDB = 42,
  INS_LDBU = 43,
  INS_LDDW = 44,
  INS_LDH = 45,
  INS_LDHU = 46,
  INS_LDNDW = 47,
  INS_LDNW = 48,
  INS_LDW = 49,
  INS_LMBD = 50,
  INS_MAX2 = 51,
  INS_MAXU4 = 52,
  INS_MIN2 = 53,
  INS_MINU4 = 54,
  INS_MPY = 55,
  INS_MPY2 = 56,
  INS_MPYH = 57,
  INS_MPYHI = 58,
  INS_MPYHIR = 59,
  INS_MPYHL = 60,
  INS_MPYHLU = 61,
  INS_MPYHSLU = 62,
  INS_MPYHSU = 63,
  INS_MPYHU = 64,
  INS_MPYHULS = 65,
  INS_MPYHUS = 66,
  INS_MPYLH = 67,
  INS_MPYLHU = 68,
  INS_MPYLI = 69,
  INS_MPYLIR = 70,
  INS_MPYLSHU = 71,
  INS_MPYLUHS = 72,
  INS_MPYSU = 73,
  INS_MPYSU4 = 74,
  INS_MPYU = 75,
  INS_MPYU4 = 76,
  INS_MPYUS = 77,
  INS_MVC = 78,
  INS_MVD = 79,
  INS_MVK = 80,
  INS_MVKL = 81,
  INS_MVKLH = 82,
  INS_NOP = 83,
  INS_NORM = 84,
  INS_OR = 85,
  INS_PACK2 = 86,
  INS_PACKH2 = 87,
  INS_PACKH4 = 88,
  INS_PACKHL2 = 89,
  INS_PACKL4 = 90,
  INS_PACKLH2 = 91,
  INS_ROTL = 92,
  INS_SADD = 93,
  INS_SADD2 = 94,
  INS_SADDU4 = 95,
  INS_SADDUS2 = 96,
  INS_SAT = 97,
  INS_SET = 98,
  INS_SHFL = 99,
  INS_SHL = 100,
  INS_SHLMB = 101,
  INS_SHR = 102,
  INS_SHR2 = 103,
  INS_SHRMB = 104,
  INS_SHRU = 105,
  INS_SHRU2 = 106,
  INS_SMPY = 107,
  INS_SMPY2 = 108,
  INS_SMPYH = 109,
  INS_SMPYHL = 110,
  INS_SMPYLH = 111,
  INS_SPACK2 = 112,
  INS_SPACKU4 = 113,
  INS_SSHL = 114,
  INS_SSHVL = 115,
  INS_SSHVR = 116,
  INS_SSUB = 117,
  INS_STB = 118,
  INS_STDW = 119,
  INS_STH = 120,
  INS_STNDW = 121,
  INS_STNW = 122,
  INS_STW = 123,
  INS_SUB = 124,
  INS_SUB2 = 125,
  INS_SUB4 = 126,
  INS_SUBAB = 127,
  INS_SUBABS4 = 128,
  INS_SUBAH = 129,
  INS_SUBAW = 130,
  INS_SUBC = 131,
  INS_SUBU = 132,
  INS_SWAP4 = 133,
  INS_UNPKHU4 = 134,
  INS_UNPKLU4 = 135,
  INS_XOR = 136,
  INS_XPND2 = 137,
  INS_XPND4 = 138,
  INS_IDLE = 139,
  INS_MV = 140,
  INS_NEG = 141,
  INS_NOT = 142,
  INS_SWAP2 = 143,
  INS_ZERO = 144,
  INS_ENDING = 145, // mark the end of the list of instructions

  GRP_INVALID = 0, // cs.GRP_INVALID
  GRP_JUMP = 1, // cs.GRP_JUMP
  GRP_FUNIT_D = 128,
  GRP_FUNIT_L = 129,
  GRP_FUNIT_M = 130,
  GRP_FUNIT_S = 131,
  GRP_FUNIT_NO = 132,
  GRP_ENDING = 133, // mark the end of the list of groups

  FUNIT_INVALID = 0,
  FUNIT_D = 1,
  FUNIT_L = 2,
  FUNIT_M = 3,
  FUNIT_S = 4,
  FUNIT_NO = 5,
}

export class cs_tms320c64x {
  public op_count: number;
  public operands: cs_tms320c64x_op[]; // operands for this instruction.
  public condition: {
    reg: number;
    zero: number;
  };
  public funit: {
    unit: number;
    side: number;
    crosspath: number;
  };
  public parallel: number;
  constructor(arch_info_ptr: number, Memory: any) {
    this.operands = [];
    this.op_count = Memory.read(arch_info_ptr + 0, 'ubyte');
    this.condition = {
      reg: Memory.read(arch_info_ptr + 260, 'i32'),
      zero: Memory.read(arch_info_ptr + 264, 'i32'),
    };
    this.funit = {
      unit: Memory.read(arch_info_ptr + 268, 'u32'),
      side: Memory.read(arch_info_ptr + 272, 'u32'),
      crosspath: Memory.read(arch_info_ptr + 276, 'u32'),
    };
    this.parallel = Memory.read(arch_info_ptr + 280, 'u32');
    for (let i = 0; i < this.op_count; i++) {
      const op: cs_tms320c64x_op = {} as cs_tms320c64x_op;
      const op_ptr: number = arch_info_ptr + 4 + i * 32;
      op.type = Memory.read(op_ptr, 'i32');
      switch (op.type) {
        case TMS320C64X.OP_REG:
          op.reg = Memory.read(op_ptr + 4, 'u32');
          break;
        case TMS320C64X.OP_IMM:
          op.imm = Memory.read(op_ptr + 4, 'i32');
          break;
        case TMS320C64X.OP_MEM:
          op.mem = {
            base: Memory.read(op_ptr + 4, 'u32'),
            disp: Memory.read(op_ptr + 8, 'i32'),
            unit: Memory.read(op_ptr + 12, 'i32'),
            scaled: Memory.read(op_ptr + 16, 'i32'),
            disptype: Memory.read(op_ptr + 20, 'i32'),
            direction: Memory.read(op_ptr + 24, 'i32'),
            modify: Memory.read(op_ptr + 28, 'i32'),
          };
          break;
        case TMS320C64X.OP_REGPAIR:
          op.reg = Memory.read(op_ptr + 4, 'u32');
          break;
      }
      this.operands[i] = op;
    }
    return this;
  }
}
