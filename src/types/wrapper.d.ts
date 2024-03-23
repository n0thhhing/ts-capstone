/// <reference types="node" />
declare const Wrapper: any;
interface cs_insn {
  id: number;
  address: number;
  size: number;
  mnemonic: string;
  op_str: string;
  bytes: number[];
}
type cs_err = number;
type cs_arch = number;
type cs_mode = number;
type cs_opt_type = number;
type cs_opt_value = number;
type cs_group_type = number;
type cs_op_type = number;
type cs_ac_type = number;
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
  const MODE_MIPSGP64: cs_mode;
  const MODE_V9: cs_mode;
  const MODE_QPX: cs_mode;
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
  const OPT_INVALID: cs_opt_type;
  const OPT_SYNTAX: cs_opt_type;
  const OPT_DETAIL: cs_opt_type;
  const OPT_MODE: cs_opt_type;
  const OPT_MEM: cs_opt_type;
  const OPT_SKIPDATA: cs_opt_type;
  const OPT_SKIPDATA_SETUP: cs_opt_type;
  const OPT_MNEMONIC: cs_opt_type;
  const OPT_UNSIGNED: cs_opt_type;
  const OPT_OFF: cs_opt_value;
  const OPT_ON: cs_opt_value;
  const OPT_SYNTAX_DEFAULT: cs_opt_value;
  const OPT_SYNTAX_INTEL: cs_opt_value;
  const OPT_SYNTAX_ATT: cs_opt_value;
  const OPT_SYNTAX_NOREGNAME: cs_opt_value;
  const OPT_SYNTAX_MASM: cs_opt_value;
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
  const CS_MNEMONIC_SIZE = 32;
  const CS_INSN_SIZE = 232;
  function version(): string;
  function support(query: number): boolean;
  function strerror(code: number): string;
  function errno(handle: number): cs_err;
  class Capstone {
    arch: cs_arch;
    mode: cs_mode;
    private handlePtr;
    constructor(arch: number, mode: number);
    private dereferenceInsn;
    option(
      option: cs_opt_type,
      value:
        | cs_opt_value
        | boolean
        | {
            id: number;
            name: string;
          },
    ): void;
    private open;
    close(): void;
    disasm(
      buffer: Buffer | number[] | Uint8Array,
      addr: number,
      maxLen?: number,
    ): cs_insn[];
    disasm_iter(data: {
      buffer: Buffer | number[] | Uint8Array;
      addr: number;
      insn: {} | cs_insn | null;
    }): boolean;
    reg_name(reg_id: number): string;
    insn_name(insn_id: number): string;
  }
}
export default cs;
export { Wrapper };
