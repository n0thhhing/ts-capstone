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
  cs_sysz,
} from './arch';
declare const Wrapper: wasm_module;
type cs_err = 0 | 1 | 2 | 3 | 4 | 5 | 6 | 7 | 8 | 9 | 10 | 11 | 12 | 13 | 14;
type cs_arch = number;
type cs_mode = number;
type cs_opt_type = number;
type cs_opt_value = number;
type cs_group_type = number;
type cs_op_type = number;
type cs_ac_type = number;
type cs_regs = number[];
type csh = number;
type cs_skipdata_cb_t = (
  code: number,
  code_size: number,
  offset: number,
  user_data: any,
) => number;
type pointer_t<T extends any> = number;
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
  _cs_free: (insn: pointer_t<cs_insn>, count: number) => void;
  _cs_malloc: (handle: csh) => pointer_t<cs_insn>;
  _malloc: (size: number) => pointer_t<any>;
  _free: (pointer: pointer_t<any>) => void;
  _cs_reg_write: (
    handle: csh,
    insn: pointer_t<cs_insn>,
    reg_id: number,
  ) => number;
  _cs_reg_read: (
    handle: csh,
    insn: pointer_t<cs_insn>,
    reg_id: number,
  ) => number;
  _cs_insn_group: (
    handle: csh,
    insn: pointer_t<cs_insn>,
    group_id: number,
  ) => number;
  _cs_regs_access: (
    handle: csh,
    insn: pointer_t<cs_insn>,
    regs_read: pointer_t<cs_regs>,
    regs_read_count: pointer_t<number>,
    regs_write: pointer_t<cs_regs>,
    regs_write_count: pointer_t<number>,
  ) => cs_err;
  _cs_op_count: (
    handle: csh,
    insn: pointer_t<cs_insn>,
    op_type: number,
  ) => number;
  _cs_op_index: (
    handle: csh,
    insn: pointer_t<cs_insn>,
    op_type: number,
    position: number,
  ) => number;
  _cs_insn_offset: (insns: pointer_t<cs_insn[]>, post: number) => number;
  _cs_detail_buffer: (insn: pointer_t<cs_insn>) => pointer_t<Uint8Array>;
  _cs_insn_buffer: (insn: pointer_t<cs_insn>) => pointer_t<Uint8Array>;
  _x86_rel_addr: (insn: pointer_t<cs_insn>) => number;
  ccall: (
    ident: string, // name of C function
    returnType: wasm_arg, // return type
    argTypes: wasm_arg[], // argument types
    args: any[], // arguments
    opts?: {
      async: boolean;
    },
  ) => any;
  setValue: (pointer: number, value: any, type: wasm_t) => void;
  getValue: (pointer: number, type: wasm_t) => any;
  UTF8ToString: (pointer: number, maxBytesToRead?: number) => string;
  addFunction: (func: Function, sig: string) => any;
  writeArrayToMemory: (
    array: number[] | Uint8Array | Buffer,
    buffer: pointer_t<number[] | Uint8Array | Buffer>,
  ) => void;
}
interface cs_insn {
  id: number;
  address: number;
  size: number;
  mnemonic: string;
  op_str: string;
  bytes: Uint8Array;
  detail?: cs_detail;
  buffer?: Uint8Array;
}
interface cs_detail {
  regs_read: cs_regs;
  regs_read_count: number;
  regs_write: cs_regs;
  regs_write_count: number;
  groups: number[];
  groups_count: number;
  writeback: boolean;
  buffer?: Uint8Array;
  x86?: cs_x86;
  arm?: cs_arm;
  arm64?: cs_arm64;
  m68k?: cs_m68k;
  mips?: cs_mips;
  ppc?: cs_ppc;
  sparc?: cs_sparc;
  sysz?: cs_sysz;
  xcore?: cs_xcore;
  tms320c64x?: cs_tms320c64x;
  m680x?: cs_m680x;
  evm?: cs_evm;
  mos65xx?: cs_mos65xx;
  wasm?: cs_wasm;
  bpf?: cs_bpf;
  riscv?: cs_riscv;
  sh?: cs_sh;
  tricore?: cs_tricore;
}
interface cs_opt_skipdata {
  mnemonic: string | null;
  callback: cs_skipdata_cb_t | null;
  user_data: object;
}
interface cs_opt_fmt {
  bytes: boolean;
  address: boolean;
  ASCII: boolean;
}
interface cs_opt_mnem {
  id: number;
  mnemonic: string | null;
}
declare namespace CS {
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
  const OPT_BUFFER: cs_opt_type;
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
  const DETAIL_SIZE = 1864;
  const MAX_IMPL_W_REGS = 20;
  const MAX_IMPL_R_REGS = 20;
  const MAX_NUM_GROUPS = 8;
  class CAPSTONE {
    private arch;
    private mode;
    private handle_ptr;
    private arch_info;
    private opt_buffer;
    /**
     * Create a new instance of the Capstone disassembly engine.
     *
     * @param {cs_arch} arch - The architecture type.
     * @param {cs_mode} mode - The mode type.
     */
    constructor(arch: cs_arch, mode: cs_mode);
    /**
     * Return the Capstone library version as a string.
     *
     * @public
     * @returns {string} The Capstone library version as a string in the format "major.minor".
     */
    version(): string;
    /**
     * Check if Capstone supports a specific query.
     *
     * @public
     * @param {number} query - The query ID to check.
     * @returns {boolean} A boolean indicating whether Capstone supports the given query.
     */
    support(query: number): boolean;
    /**
     * Get the error message string for a given error code.
     *
     * @public
     * @param {number} code - The error code.
     * @returns {string} The error message string corresponding to the given error code.
     */
    strerror(code: number): string;
    /**
     * Get the error code for the most recent Capstone error that occurred with the given handle.
     *
     * @public
     * @param {csh} handle - The handle for which to get the error code.
     * returns {cs_err} The error code for the most recent Capstone error.
     */
    errno(handle: csh): cs_err;
    private init;
    /**
     * Handler to parse the cs_opt_skipdata obj
     *
     * @private
     * @param {cs_opt_skipdata} skipdata - User-customized setup for SKIPDATA option
     * @returns {pointer_t<cs_opt_skipdata>} The pointer to the cs_opt_skipdata struct
     */
    private skipdata_cb;
    /**
     * Dereferences a pointer to a cs_insn strict to retrieve information about a disassembled instruction.
     *
     * @private
     * @param {pointer_t<cs_insn>} insn_ptr - The pointer to the disassembled instruction.
     * @returns {cs_insn} Information about the disassembled instruction.
     */
    private deref;
    /**
     * Converts an array of `cs_insn` objects into a pointer to an array of cs_insn structures.
     *
     * @private
     * @param {cs_insn[]} insns Array of `cs_insn` objects to be converted.
     * @returns {pointer_t<cs_insn[]>} Pointer to the array of cs_insn structures.
     */
    private ref;
    /**
     * Retrieves the detail information of a disassembled instruction from the cs_detail struct.
     *
     * @private
     * @param {pointer_t<cs_detail>} pointer - The pointer to the detail information.
     * @returns {cs_detail} The detail information of the disassembled instruction.
     */
    private get_detail;
    /**
     * Set an option for the Capstone disassembly engine.
     *
     * @public
     * @param {cs_opt_type} option - The option type to set.
     * @param {cs_opt_value | boolean | cs_opt_mnem | cs_opt_skipdata} value - The value to set for the option.
     * @returns {void}
     */
    option(
      option: cs_opt_type,
      value: cs_opt_value | boolean | cs_opt_mnem | cs_opt_skipdata,
    ): void;
    /**
     * Create the capstone instance handle
     *
     * @private
     * @returns {void}
     */
    private open;
    /**
     * Free the capstone instance handle and cleanup resources
     *
     * @public
     * @returns {void}
     */
    close(): void;
    /**
     * Disassemble binary data.
     *
     * @public
     * @param {Buffer | number[] | Uint8Array,} buffer - The binary data to disassemble, as a Buffer, array, or Uint8Array.
     * @param {number} addr - The starting address of the binary data.
     * @param {number} [max_len] - (Optional) The maximum number of instructions to disassemble.
     * @returns {cs_insn[]} An array of disassembled instructions.
     */
    disasm(
      buffer: Buffer | number[] | Uint8Array,
      addr: number,
      max_len?: number,
    ): cs_insn[];
    /**
     * Perform iterative disassembly on binary data.
     *
     * @public
     * @param {Object} data - An object containing the binary data to disassemble, the starting address, and the previous instruction.
     * @param {Buffer | number[] | Uint8Array} data.buffer - The binary data to disassemble, as a Buffer, array, or Uint8Array.
     * @param {number} data.address - the address of the current instruction
     * @param {{} | cs_insn | null} data.insn - the previous iterations instruct or {} on iteration 0
     * @returns {boolean} A boolean indicating whether another instruction was successfully disassembled.
     */
    disasm_iter(data: {
      buffer: Buffer | number[] | Uint8Array;
      addr: number;
      insn: {} | cs_insn | null;
    }): boolean;
    /**
     * Retrieve information about registers accessed by an instruction.
     *
     * @public
     * @param {cs_insn} insn - The instruction to analyze.
     * @returns {{regs_read: cs_regs, regs_read_count: number, regs_write: cs_regs, regs_write_count: number}} An object containing arrays of registers read and written by the instruction.
     */
    regs_access(insn: cs_insn): {
      regs_read: cs_regs;
      regs_read_count: number;
      regs_write: cs_regs;
      regs_write_count: number;
    };
    /**
     * Get the number of operands of a specific type for an instruction.
     *
     * @public
     * @param {cs_insn} insn - The instruction to analyze.
     * @param {number} op_type - The type of operand to count.
     * @returns {number} The number of operands of the specified type for the instruction.
     */
    op_count(insn: cs_insn, op_type: number): number;
    /**
     * Get the index of a specific operand of a specific type at a given position for an instruction.
     *
     * @public
     * @param {cs_insn} insn - The instruction to analyze.
     * @param {number} op_type - The type of operand to search for.
     * @param {number} position - The position of the operand to find (zero-based).
     * @returns {number} The index of the operand within the instruction's operand list, or -1 if not found.
     */
    op_index(insn: cs_insn, op_type: number, position: number): number;
    /**
     * Check if an instruction belongs to a specific group.
     *
     * @public
     * @param {cs_insn} insn - The instruction to check.
     * @param {number} group_id - The ID of the group to check against.
     * @returns {boolean} A boolean indicating whether the instruction belongs to the specified group.
     */
    insn_group(insn: cs_insn, group_id: number): boolean;
    /**
     * Retrieves the registers read by an instruction.
     *
     * @public
     * @param {cs_insn} insn - The instruction to analyze.
     * @param {number} reg_id - The register to look for.
     * @returns {boolean} A boolean indicating whether the instruction reads a specific register.
     */
    reg_read(insn: cs_insn, reg_id: number): boolean;
    /**
     * Retrieves the registers written to by an instruction.
     *
     * @public
     * @param {cs_insn} insn - The instruction to analyze.
     * @param {number} reg_id - The register to look for.
     * @returns {boolean} A boolean indicating whether the instruction writes to a specific register.
     */
    reg_write(insn: cs_insn, reg_id: number): boolean;
    /**
     * Retrieves the name of the instruction group to which an instruction belongs.
     *
     * @public
     * @param {number} insn - The instruction to analyze.
     * @returns {string} The name of the instruction group.
     */
    group_name(group_id: number): string;
    /**
     * Retrieves the name of a register referenced by an operand in an instruction.
     *
     * @public
     * @param {number} reg_id - The register to look for.
     * @returns {string} The name of the register referenced by the operand.
     */
    reg_name(reg_id: number): string;
    /**
     * Retrieves the name of the instruction mnemonic.
     *
     * @public
     * @param {number} insn_id - The instruction id to look for.
     * @returns {string} The mnemonic of the instruction.
     */
    insn_name(insn_id: number): string;
    /**
     * Retrieves the offset relative to the start of the buffer where the instruction resides.
     *
     * @public
     * @param {cs_insn[]} insns - The instructions to analyze.
     * @param {number} position - The index of the specific insn.
     * @returns {number} The offset of the instruction relative to the buffer.
     */
    INSN_OFFSET(insns: cs_insn[], position: number): number;
    /**
     * Retrieves the relative address for X86 instructions using RIP-relative addressing mode.
     *
     * @public
     * @param {cs_insn} insn - The instruction to analyze.
     * @returns {number} The relative address associated with the X86 instruction.
     */
    X86_REL_ADDR(insn: cs_insn): number;
    /**
     * Formats the given instructions to a printable string.
     *
     * @public
     * @param {cs_insn | cs_insn[]} instructions - The instruction or array of instructions to format.
     * @param {cs_opt_fmt} [options={ASCII: false, address: true, bytes: true}] - Formatting options.
     */
    fmt(instructions: cs_insn | cs_insn[], options?: cs_opt_fmt): string;
  }
}
export default CS;
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
