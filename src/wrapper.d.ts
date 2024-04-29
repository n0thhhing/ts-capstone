/// <reference types="node" />
import {
  type cs_arm64_op,
  ARM64,
  cs_arm64,
  type cs_arm_op,
  ARM,
  cs_arm,
  type cs_bpf_op,
  BPF,
  cs_bpf,
  EVM,
  cs_evm,
  type cs_m680x_op,
  M680X,
  cs_m680x,
  type cs_m68k_op,
  M68K,
  cs_m68k,
  type cs_mips_op,
  MIPS,
  cs_mips,
  type cs_mos65xx_op,
  MOS65XX,
  cs_mos65xx,
  type cs_ppc_op,
  PPC,
  cs_ppc,
  type cs_riscv_op,
  RISCV,
  cs_riscv,
  type cs_sh_op,
  SH,
  cs_sh,
  type cs_sparc_op,
  SPARC,
  cs_sparc,
  type cs_tms320c64x_op,
  TMS320C64X,
  cs_tms320c64x,
  type cs_tricore_op,
  TRICORE,
  cs_tricore,
  type cs_wasm_op,
  WASM,
  cs_wasm,
  type cs_x86_op,
  X86,
  cs_x86,
  type cs_xcore_op,
  XCORE,
  cs_xcore,
} from './arch';
declare const Wrapper: wasm_module;
type cs_err = number;
type cs_arch = number;
type cs_mode = number;
type cs_opt_type = number;
type cs_opt_value = number;
type cs_group_type = number;
type cs_op_type = number;
type cs_ac_type = number;
type cs_regs = Array<number>;
type csh = number;
type ptr = number;
type wasm_arg = 'number' | 'string' | 'array' | 'boolean' | 'pointer' | null;
type wasm_t = 'i8' | 'i16' | 'i32' | 'i64' | 'float' | 'double' | 'i8*' | '*';
interface wasm_module {
  HEAP8: Int8Array;
  HEAPU8: Uint8Array;
  HEAP16: Int16Array;
  HEAPU16: Uint16Array;
  HEAP32: Int32Array;
  HEAPU32: Uint32Array;
  HEAPF32: Float32Array;
  HEAPF64: Float64Array;
  _cs_free: (insn: ptr, count: number) => void;
  _cs_malloc: (handle: csh) => ptr;
  _malloc: (size: number) => ptr;
  _free: (pointer: ptr) => void;
  _cs_reg_write: (handle: csh, insn: ptr, reg_id: number) => number;
  _cs_reg_read: (handle: csh, insn: ptr, reg_id: number) => number;
  _cs_insn_group: (handle: csh, insn: ptr, group_id: number) => number;
  _cs_regs_access: (
    handle: csh,
    insn: ptr,
    regs_read: ptr,
    regs_read_count: ptr,
    regs_write: ptr,
    regs_write_count: ptr,
  ) => number;
  _cs_op_count: (handle: csh, insn: ptr, op_type: number) => number;
  _cs_op_index: (
    handle: csh,
    insn: ptr,
    op_type: number,
    position: number,
  ) => number;
  _cs_insn_offset: (insns: ptr, post: number) => number;
  _x86_rel_addr: (insn: ptr) => number;
  ccall: (
    ident: string, // name of C function
    returnType: wasm_arg, // return type
    argTypes: Array<wasm_arg>, // argument types
    args: Array<any>, // arguments
    opts?: {
      async: boolean;
    },
  ) => any;
  cwrap: (
    ident: string, // name of C function
    returnType: wasm_arg, // return type
    argTypes: Array<wasm_arg>,
  ) => any;
  addFunction: (func: Function, sig: string) => any;
  setValue: (ptr: number, value: any, type: wasm_t) => void;
  getValue: (ptr: number, type: wasm_t) => any;
  UTF8ToString: (ptr: number, maxBytesToRead?: number) => string;
  stringToNewUTF8: (str: string, outPtr: ptr, maxBytesToWrite: number) => any;
  writeArrayToMemory: (
    array: Array<number> | Uint8Array | Buffer,
    buffer: ptr,
  ) => void;
}
interface cs_insn {
  id: number;
  address: number;
  size: number;
  mnemonic: string;
  op_str: string;
  bytes: Array<number>;
  detail?: cs_detail;
}
interface cs_detail {
  regs_read: Array<number>;
  regs_read_count: number;
  regs_write: Array<number>;
  regs_write_count: number;
  groups: Array<number>;
  groups_count: number;
  writeback: boolean;
  x86?: any;
  arm?: any;
  arm64?: any;
  m68k?: any;
  mips?: any;
  ppc?: any;
  sparc?: any;
  sysz?: any;
  xcore?: any;
  tms320c64x?: any;
  m680x?: any;
  evm?: any;
  mos65xx?: any;
  wasm?: any;
  bpf?: any;
  riscv?: any;
  sh?: any;
  tricore?: any;
}
interface cs_opt_skipdata {
  mnemonic: string | null;
  callback: Function | null;
  user_data: object;
}
interface cs_opt_mnem {
  id: number;
  mnemonic: string | null;
}
declare namespace cs {
  const ERR_OK: cs_err;
  const ERR_MEM: cs_err;
  const ERR_ARCH: cs_err;
  const ERR_HANDLE: cs_err;
  const ERR_CSH: cs_err;
  const ERR_MODE: cs_err;
  const ERR_OPTION: cs_err;
  const ERR_DETAIL: cs_err;
  const ERR_MEMSETUP: cs_err;
  const ERR_VERSION: cs_err;
  const ERR_DIET: cs_err;
  const ERR_SKIPDATA: cs_err;
  const ERR_X86_ATT: cs_err;
  const ERR_X86_INTEL: cs_err;
  const ERR_X86_MASM: cs_err;
  const ARCH_ARM: cs_arch;
  const ARCH_ARM64: cs_arch;
  const ARCH_AARCH64: cs_arch;
  const ARCH_MIPS: cs_arch;
  const ARCH_X86: cs_arch;
  const ARCH_PPC: cs_arch;
  const ARCH_SPARC: cs_arch;
  const ARCH_SYSZ: cs_arch;
  const ARCH_XCORE: cs_arch;
  const ARCH_M68K: cs_arch;
  const ARCH_TMS320C64X: cs_arch;
  const ARCH_M680X: cs_arch;
  const ARCH_EVM: cs_arch;
  const ARCH_MOS65XX: cs_arch;
  const ARCH_WASM: cs_arch;
  const ARCH_BPF: cs_arch;
  const ARCH_RISCV: cs_arch;
  const ARCH_SH: cs_arch;
  const ARCH_TRICORE: cs_arch;
  const ARCH_MAX: cs_arch;
  const ARCH_ALL: cs_arch;
  const MODE_LITTLE_ENDIAN: cs_mode;
  const MODE_ARM: cs_mode;
  const MODE_16: cs_mode;
  const MODE_32: cs_mode;
  const MODE_64: cs_mode;
  const MODE_THUMB: cs_mode;
  const MODE_MCLASS: cs_mode;
  const MODE_V8: cs_mode;
  const MODE_MICRO: cs_mode;
  const MODE_MIPS3: cs_mode;
  const MODE_MIPS32R6: cs_mode;
  const MODE_MIPS2: cs_mode;
  const MODE_V9: cs_mode;
  const MODE_QPX: cs_mode;
  const MODE_SPE: cs_mode;
  const MODE_BOOKE: cs_mode;
  const MODE_PS: cs_mode;
  const MODE_M68K_000: cs_mode;
  const MODE_M68K_010: cs_mode;
  const MODE_M68K_020: cs_mode;
  const MODE_M68K_030: cs_mode;
  const MODE_M68K_040: cs_mode;
  const MODE_M68K_060: cs_mode;
  const MODE_BIG_ENDIAN: cs_mode;
  const MODE_MIPS32: cs_mode;
  const MODE_MIPS64: cs_mode;
  const MODE_M680X_6301: cs_mode;
  const MODE_M680X_6309: cs_mode;
  const MODE_M680X_6800: cs_mode;
  const MODE_M680X_6801: cs_mode;
  const MODE_M680X_6805: cs_mode;
  const MODE_M680X_6808: cs_mode;
  const MODE_M680X_6809: cs_mode;
  const MODE_M680X_6811: cs_mode;
  const MODE_M680X_CPU12: cs_mode;
  const MODE_M680X_HCS08: cs_mode;
  const MODE_BPF_CLASSIC: cs_mode;
  const MODE_BPF_EXTENDED: cs_mode;
  const MODE_RISCV32: cs_mode;
  const MODE_RISCV64: cs_mode;
  const MODE_RISCVC: cs_mode;
  const MODE_MOS65XX_6502: cs_mode;
  const MODE_MOS65XX_65C02: cs_mode;
  const MODE_MOS65XX_W65C02: cs_mode;
  const MODE_MOS65XX_65816: cs_mode;
  const MODE_MOS65XX_65816_LONG_M: cs_mode;
  const MODE_MOS65XX_65816_LONG_X: cs_mode;
  const MODE_MOS65XX_65816_LONG_MX: cs_mode;
  const MODE_SH2: cs_mode;
  const MODE_SH2A: cs_mode;
  const MODE_SH3: cs_mode;
  const MODE_SH4: cs_mode;
  const MODE_SH4A: cs_mode;
  const MODE_SHFPU: cs_mode;
  const MODE_SHDSP: cs_mode;
  const MODE_TRICORE_110: cs_mode;
  const MODE_TRICORE_120: cs_mode;
  const MODE_TRICORE_130: cs_mode;
  const MODE_TRICORE_131: cs_mode;
  const MODE_TRICORE_160: cs_mode;
  const MODE_TRICORE_161: cs_mode;
  const MODE_TRICORE_162: cs_mode;
  const OPT_INVALID: cs_opt_type;
  const OPT_SYNTAX: cs_opt_type;
  const OPT_DETAIL: cs_opt_type;
  const OPT_MODE: cs_opt_type;
  const OPT_MEM: cs_opt_type;
  const OPT_SKIPDATA: cs_opt_type;
  const OPT_SKIPDATA_SETUP: cs_opt_type;
  const OPT_MNEMONIC: cs_opt_type;
  const OPT_UNSIGNED: cs_opt_type;
  const OPT_NO_BRANCH_OFFSET: cs_opt_type;
  const OPT_OFF: cs_opt_value;
  const OPT_ON: cs_opt_value;
  const OPT_SYNTAX_DEFAULT: cs_opt_value;
  const OPT_SYNTAX_INTEL: cs_opt_value;
  const OPT_SYNTAX_ATT: cs_opt_value;
  const OPT_SYNTAX_NOREGNAME: cs_opt_value;
  const OPT_SYNTAX_MASM: cs_opt_value;
  const OPT_SYNTAX_MOTOROLA: cs_opt_value;
  const GRP_INVALID: cs_group_type;
  const GRP_JUMP: cs_group_type;
  const GRP_CALL: cs_group_type;
  const GRP_RET: cs_group_type;
  const GRP_INT: cs_group_type;
  const GRP_IRET: cs_group_type;
  const GRP_PRIVILEGE: cs_group_type;
  const GRP_BRANCH_RELATIVE: cs_group_type;
  const OP_INVALID: cs_op_type;
  const OP_REG: cs_op_type;
  const OP_IMM: cs_op_type;
  const OP_MEM: cs_op_type;
  const OP_FP: cs_op_type;
  const AC_INVALID: cs_ac_type;
  const AC_READ: cs_ac_type;
  const AC_WRITE: cs_ac_type;
  const SUPPORT_DIET: number;
  const SUPPORT_X86_REDUCE: number;
  const MNEMONIC_SIZE = 32;
  const INSN_SIZE = 240;
  const MAX_IMPL_W_REGS = 20;
  const MAX_IMPL_R_REGS = 20;
  const MAX_NUM_GROUPS = 8;
  function version(): string;
  function support(query: number): boolean;
  function strerror(code: number): string;
  function errno(handle: number): cs_err;
  class Capstone {
    private arch;
    private mode;
    private handle_ptr;
    private arch_info;
    constructor(arch: number, mode: number);
    private init;
    private deref;
    private ref;
    private get_detail;
    option(
      option: cs_opt_type,
      value: cs_opt_value | boolean | cs_opt_mnem | cs_opt_skipdata,
    ): void;
    private open;
    close(): void;
    disasm(
      buffer: Buffer | Array<number> | Uint8Array,
      addr: number,
      max_len?: number,
    ): cs_insn[];
    disasm_iter(data: {
      buffer: Buffer | Array<number> | Uint8Array;
      addr: number;
      insn: {} | cs_insn | null;
    }): boolean;
    regs_access(insn: cs_insn): {
      regs_read: cs_regs;
      regs_read_count: number;
      regs_write: cs_regs;
      regs_write_count: number;
    };
    op_count(insn: cs_insn, op_type: number): number;
    op_index(insn: cs_insn, op_type: number, position: number): number;
    insn_group(insn: cs_insn, group_id: number): boolean;
    reg_read(insn: cs_insn, reg_id: number): boolean;
    reg_write(insn: cs_insn, reg_id: number): boolean;
    group_name(group_id: number): string;
    reg_name(reg_id: number): string;
    insn_name(insn_id: number): string;
    INSN_OFFSET(insns: Array<cs_insn>, position: number): number;
    X86_REL_ADDR(insn: cs_insn): number;
  }
}
export default cs;
export {
  Wrapper,
  cs_opt_skipdata,
  cs_opt_mnem,
  cs_insn,
  cs_detail,
  cs_arch,
  cs_mode,
  cs_err,
  cs_opt_type,
  cs_opt_value,
  cs_group_type,
  cs_op_type,
  cs_ac_type,
  cs_regs,
  type cs_arm64_op,
  ARM64,
  cs_arm64,
  type cs_arm_op,
  ARM,
  cs_arm,
  type cs_bpf_op,
  BPF,
  cs_bpf,
  EVM,
  cs_evm,
  type cs_m680x_op,
  M680X,
  cs_m680x,
  type cs_m68k_op,
  M68K,
  cs_m68k,
  type cs_mips_op,
  MIPS,
  cs_mips,
  type cs_mos65xx_op,
  MOS65XX,
  cs_mos65xx,
  type cs_ppc_op,
  PPC,
  cs_ppc,
  type cs_riscv_op,
  RISCV,
  cs_riscv,
  type cs_sh_op,
  SH,
  cs_sh,
  type cs_sparc_op,
  SPARC,
  cs_sparc,
  type cs_tms320c64x_op,
  TMS320C64X,
  cs_tms320c64x,
  type cs_tricore_op,
  TRICORE,
  cs_tricore,
  type cs_wasm_op,
  WASM,
  cs_wasm,
  type cs_x86_op,
  X86,
  cs_x86,
  type cs_xcore_op,
  XCORE,
  cs_xcore,
};
