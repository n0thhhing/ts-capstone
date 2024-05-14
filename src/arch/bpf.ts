export interface cs_bpf_op {
  type: BPF;
  reg?: BPF; // register value for REG operand
  imm?: number; // immediate value IMM operand
  off?: number; // offset value, used in jump & call
  mem: {
    // base/disp value for MEM operand
    base: number; // base register
    disp: number; // offset value
  };
  // cBPF only
  mmem?: number; // M[k] in cBPF
  msh?: number; // corresponds to cBPF's BPF_MSH mode
  ext?: number; // cBPF's extension (not eBPF)
  // How is this operand accessed? (READ, WRITE or READ|WRITE)
  // This field is combined of cs_ac_type.
  access: number;
}

export enum BPF {
  // Operand type for instruction's operands
  OP_INVALID = 0,
  OP_REG = 1,
  OP_IMM = 2,
  OP_OFF = 3,
  OP_MEM = 4,
  OP_MMEM = 5, // M[k] in cBPF
  OP_MSH = 6, // corresponds to cBPF's BPF_MSH mode
  OP_EXT = 7, // cBPF's extension (not eBPF)

  // BPF registers
  REG_INVALID = 0,

  // cBPF
  REG_A = 1,
  REG_X = 2,

  // eBPF
  REG_R0 = 3,
  REG_R1 = 4,
  REG_R2 = 5,
  REG_R3 = 6,
  REG_R4 = 7,
  REG_R5 = 8,
  REG_R6 = 9,
  REG_R7 = 10,
  REG_R8 = 11,
  REG_R9 = 12,
  REG_R10 = 13,
  REG_ENDING = 14,

  EXT_INVALID = 0,
  EXT_LEN = 1,

  // BPF instruction
  INS_INVALID = 0,

  // ALU
  INS_ADD = 1,
  INS_SUB = 2,
  INS_MUL = 3,
  INS_DIV = 4,
  INS_OR = 5,
  INS_AND = 6,
  INS_LSH = 7,
  INS_RSH = 8,
  INS_NEG = 9,
  INS_MOD = 10,
  INS_XOR = 11,
  INS_MOV = 12, // eBPF only
  INS_ARSH = 13, // eBPF only

  // ALU64, eBPF only
  INS_ADD64 = 14,
  INS_SUB64 = 15,
  INS_MUL64 = 16,
  INS_DIV64 = 17,
  INS_OR64 = 18,
  INS_AND64 = 19,
  INS_LSH64 = 20,
  INS_RSH64 = 21,
  INS_NEG64 = 22,
  INS_MOD64 = 23,
  INS_XOR64 = 24,
  INS_MOV64 = 25,
  INS_ARSH64 = 26,

  // Byteswap, eBPF only
  INS_LE16 = 27,
  INS_LE32 = 28,
  INS_LE64 = 29,
  INS_BE16 = 30,
  INS_BE32 = 31,
  INS_BE64 = 32,

  // Load
  INS_LDW = 33, // eBPF only
  INS_LDH = 34,
  INS_LDB = 35,
  INS_LDDW = 36, // eBPF only: load 64-bit imm
  INS_LDXW = 37, // eBPF only
  INS_LDXH = 38, // eBPF only
  INS_LDXB = 39, // eBPF only
  INS_LDXDW = 40, // eBPF only

  // Store
  INS_STW = 41, // eBPF only
  INS_STH = 42, // eBPF only
  INS_STB = 43, // eBPF only
  INS_STDW = 44, // eBPF only
  INS_STXW = 45, // eBPF only
  INS_STXH = 46, // eBPF only
  INS_STXB = 47, // eBPF only
  INS_STXDW = 48, // eBPF only
  INS_XADDW = 49, // eBPF only
  INS_XADDDW = 50, // eBPF only

  // Jump
  INS_JMP = 51,
  INS_JEQ = 52,
  INS_JGT = 53,
  INS_JGE = 54,
  INS_JSET = 55,
  INS_JNE = 56, // eBPF only
  INS_JSGT = 57, // eBPF only
  INS_JSGE = 58, // eBPF only
  INS_CALL = 59, // eBPF only
  INS_CALLX = 60, // eBPF only
  INS_EXIT = 61, // eBPF only
  INS_JLT = 62, // eBPF only
  INS_JLE = 63, // eBPF only
  INS_JSLT = 64, // eBPF only
  INS_JSLE = 65, // eBPF only

  // Return, cBPF only
  INS_RET = 66,

  // Misc, cBPF only
  INS_TAX = 67,
  INS_TXA = 68,
  INS_ENDING = 69,

  // alias instructions
  INS_LD = BPF.INS_LDW,
  INS_LDX = BPF.INS_LDXW,
  INS_ST = BPF.INS_STW,
  INS_STX = BPF.INS_STXW,

  // Group of BPF instructions
  GRP_INVALID = 0, // cs.GRP_INVALID
  GRP_LOAD = 1,
  GRP_STORE = 2,
  GRP_ALU = 3,
  GRP_JUMP = 4,
  GRP_CALL = 5, // eBPF only
  GRP_RETURN = 6,
  GRP_MISC = 7, // cBPF only
  GRP_ENDING = 8,
}

export class cs_bpf {
  public op_count: number;
  public operands: cs_bpf_op[];

  constructor(arch_info_ptr: number, Memory: any) {
    this.operands = [];
    this.op_count = Memory.read(arch_info_ptr + 0, 'ubyte');
    for (let i = 0; i < this.op_count; i++) {
      const op: cs_bpf_op = {} as cs_bpf_op;
      const op_ptr: number = arch_info_ptr + 8 + i * 24;
      op.type = Memory.read(op_ptr + 0, 'i32');
      op.access = Memory.read(op_ptr + 16, 'u32');
      switch (op.type) {
        case BPF.OP_REG:
          op.reg = Memory.read(op_ptr + 8, 'ubyte');
          break;
        case BPF.OP_IMM:
          op.imm = Memory.read(op_ptr + 8, 'i64');
          break;
        case BPF.OP_OFF:
          op.off = Memory.read(op_ptr + 8, 'u32');
          break;
        case BPF.OP_MEM:
          op.mem = {
            base: Memory.read(op_ptr + 8, 'i32'),
            disp: Memory.read(op_ptr + 12, 'u32'),
          };
          break;
        case BPF.OP_MMEM:
          op.mmem = Memory.read(op_ptr + 8, 'u32');
          break;
        case BPF.OP_MSH:
          op.msh = Memory.read(op_ptr + 8, 'u32');
          break;
        case BPF.OP_EXT:
          op.ext = Memory.read(op_ptr + 8, 'u32');
          break;
      }
      this.operands[i] = op;
    }
    return this;
  }
}
