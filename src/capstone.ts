import Module from './libcapstone';
import { Memory } from './memory';

import {
  // ARM64 architecture
  type cs_arm64_op,
  ARM64,
  cs_arm64,
  // ARM architecture
  type cs_arm_op,
  ARM,
  cs_arm,
  // BPF architecture
  type cs_bpf_op,
  BPF,
  cs_bpf,
  // EVM architecture
  EVM,
  cs_evm,
  // M680X architecture
  type cs_m680x_op,
  M680X,
  cs_m680x,
  // M68K architecture
  type cs_m68k_op,
  M68K,
  cs_m68k,
  // MIPS architecture
  type cs_mips_op,
  MIPS,
  cs_mips,
  // MOS65XX architecture
  type cs_mos65xx_op,
  MOS65XX,
  cs_mos65xx,
  // PPC architecture
  type cs_ppc_op,
  PPC,
  cs_ppc,
  // RISCV architecture
  type cs_riscv_op,
  RISCV,
  cs_riscv,
  // SH architecture
  type cs_sh_op,
  SH,
  cs_sh,
  // SPARC architecture
  type cs_sparc_op,
  SPARC,
  cs_sparc,
  // TMS320C64X architecture
  type cs_tms320c64x_op,
  TMS320C64X,
  cs_tms320c64x,
  // TRICORE architecture
  type cs_tricore_op,
  TRICORE,
  cs_tricore,
  // WASM architecture
  type cs_wasm_op,
  WASM,
  cs_wasm,
  // X86 architecture
  type cs_x86_op,
  X86,
  cs_x86,
  // XCORE architecture
  type cs_xcore_op,
  XCORE,
  cs_xcore,
  // SYSZ architecture
  type cs_sysz_op,
  SYSZ,
  cs_sysz,
} from './arch';

const Wrapper: wasm_module = Module() as wasm_module;

type cs_err = 0 | 1 | 2 | 3 | 4 | 5 | 6 | 7 | 8 | 9 | 10 | 11 | 12 | 13 | 14; // All type of errors encountered by Capstone API. These are values returned by cs_errno()
type cs_arch = number; // Architecture type
type cs_mode = number; // Mode type
type cs_opt_type = number; // Runtime option for the disassembled engine
type cs_opt_value = number; // Runtime option value (associated with option type above)
type cs_group_type = number; // Common instruction groups - to be consistent across all architectures.
type cs_op_type = number; // Common instruction operand types - to be consistent across all architectures
type cs_ac_type = number; // Common instruction operand access types - to be consistent across all architectures. It is possible to combine access types, for example: CS_AC_READ | CS_AC_WRITE
type cs_regs = number[]; // Type of array to keep the list of registers
type csh = number; // Handle using with all API
type cs_skipdata_cb_t = (
  code: number,
  code_size: number,
  offset: number,
  user_data: any,
) => number; // User-defined callback function for SKIPDATA option
type pointer_t<T extends any> = number; // Points to a specific memory address
type wasm_arg = 'number' | 'string' | 'array' | 'boolean' | 'pointer' | null; // types of arguments for the C function.
type wasm_t = 'i8' | 'i16' | 'i32' | 'i64' | 'float' | 'double' | 'i8*' | '*'; // An LLVM IR type as a string

// Module object with attributes that Emscripten-generated code calls at various points in its execution.
interface wasm_module {
  HEAP8: Int8Array; // View for 8-bit signed memory.
  HEAPU8: Uint8Array; // View for 8-bit unsigned memory.
  HEAP16: Int16Array; // View for 16-bit signed memory.
  HEAPU16: Uint16Array; // View for 16-bit unsigned memory.
  HEAP32: Int32Array; // View for 32-bit signed memory.
  HEAPU32: Uint32Array; // View for 32-bit unsigned memory.
  HEAPF32: Float32Array; // View for 32-bit float memory.
  HEAPF64: Float64Array; // View for 8-bit float memory.
  _cs_free: (insn: pointer_t<cs_insn>, count: number) => void; // Free memory allocated by _cs_malloc() or disasm()
  _cs_malloc: (handle: csh) => pointer_t<cs_insn>; // Allocate memory for 1 instruction to be used by disasm_iter()
  _malloc: (size: number) => pointer_t<any>; // Allocates a block of memory on the heap, must be paired with free(), or heap memory will leak! (use Memory.malloc()).
  _free: (pointer: pointer_t<any>) => void; // Free allocated memory (use Memory.free()).
  _cs_reg_write: (
    handle: csh,
    insn: pointer_t<cs_insn>,
    reg_id: number,
  ) => number; // Check if a disassembled instruction IMPLICITLY modified a particular register.
  _cs_reg_read: (
    handle: csh,
    insn: pointer_t<cs_insn>,
    reg_id: number,
  ) => number; // Check if a disassembled instruction IMPLICITLY used a particular register.
  _cs_insn_group: (
    handle: csh,
    insn: pointer_t<cs_insn>,
    group_id: number,
  ) => number; // Check if a disassembled instruction belong to a particular group.
  _cs_regs_access: (
    handle: csh,
    insn: pointer_t<cs_insn>,
    regs_read: pointer_t<cs_regs>,
    regs_read_count: pointer_t<number>,
    regs_write: pointer_t<cs_regs>,
    regs_write_count: pointer_t<number>,
  ) => cs_err; // Retrieve all the registers accessed by an instruction, either explicitly or implicitly.
  _cs_op_count: (
    handle: csh,
    insn: pointer_t<cs_insn>,
    op_type: number,
  ) => number; // Count the number of operands of a given type.
  _cs_op_index: (
    handle: csh,
    insn: pointer_t<cs_insn>,
    op_type: number,
    position: number,
  ) => number; // Retrieve the position of operand of given type in <arch>.operands[] array.
  _cs_insn_offset: (insns: pointer_t<cs_insn[]>, post: number) => number; // Calculate the offset of a disassembled instruction in its buffer, given its position in its array of disassembled insn.
  _cs_detail_buffer: (insn: pointer_t<cs_insn>) => pointer_t<Uint8Array>; // Gets the raw buffer of the specified insns cs_detail.
  _cs_insn_buffer: (insn: pointer_t<cs_insn>) => pointer_t<Uint8Array>; // Gets the raw buffer of the cs_insn
  _x86_rel_addr: (insn: pointer_t<cs_insn>) => number; // Calculate relative address for X86-64, given cs_insn structure
  ccall: (
    ident: string, // name of C function
    returnType: wasm_arg, // return type
    argTypes: wasm_arg[], // argument types
    args: any[], // arguments
    opts?: {
      async: boolean; // If true, implies that the ccall will perform an async operation. This assumes you are build with asyncify support.
    },
  ) => any; // Call a compiled C function from JavaScript.
  setValue: (pointer: number, value: any, type: wasm_t) => void; // Sets a value at a specific memory address at run-time (use Memory.write()).
  getValue: (pointer: number, type: wasm_t) => any; // Gets a value at a specific memory address at run-time (use Memory.read()).
  UTF8ToString: (pointer: number, maxBytesToRead?: number) => string; // Given a pointer pointer_t to a null-terminated UTF8-encoded string in the Emscripten HEAP, returns a copy of that string as a JavaScript String object.
  addFunction: (func: Function, sig: string) => any; // You can use addFunction to return an integer value that represents a function pointer
  writeArrayToMemory: (
    array: number[] | Uint8Array | Buffer,
    buffer: pointer_t<number[] | Uint8Array | Buffer>,
  ) => void; // Writes an array to a specified address in the heap. Note that memory should to be allocated for the array before it is written.
}

// Detail information of disassembled instruction
interface cs_insn {
  id: number; // Instruction ID (basically a numeric ID for the instruction mnemonic) Find the instruction id in the 'ARCH_insn' enum in the header file of corresponding architecture, such as 'arm_insn' in arm.h for ARM, 'x86_insn' in x86.h for X86, etc... This information is available even when CS_OPT_DETAIL = CS_OPT_OFF NOTE: in Skipdata mode, "data" instruction has 0 for this id field.
  address: number; // Address (EIP) of this instruction This information is available even when CS_OPT_DETAIL = CS_OPT_OFF
  size: number; // Size of this instruction This information is available even when CS_OPT_DETAIL = CS_OPT_OFF
  mnemonic: string; // Ascii text of instruction mnemonic This information is available even when CS_OPT_DETAIL = CS_OPT_OFF
  op_str: string; // Ascii text of instruction operands This information is available even when CS_OPT_DETAIL = CS_OPT_OFF
  bytes: Uint8Array; // Machine bytes of this instruction, with number of bytes indicated by @size above This information is available even when CS_OPT_DETAIL = CS_OPT_OFF
  detail?: cs_detail; // cs_detail object
  buffer?: Uint8Array; // The raw detail buffer, this will only be present if CS.OPT_BUFFER is on.
}

// cs_detail object. NOTE: detail object is only valid when both requirements below are met: (1) CS_OP_DETAIL = CS_OPT_ON (2) Engine is not in Skipdata mode (CS_OP_SKIPDATA option set to CS_OPT_ON)
interface cs_detail {
  [index: string]: any;
  regs_read: cs_regs; // list of implicit registers read by this insn
  regs_read_count: number; // number of implicit registers read by this insn
  regs_write: cs_regs; // list of implicit registers modified by this insn
  regs_write_count: number; // number of implicit registers modified by this insn
  groups: number[]; // list of group this instruction belong to
  groups_count: number; // number of groups this insn belongs to
  writeback: boolean; // Instruction has writeback operands.
  buffer?: Uint8Array; // The raw detail buffer, this will only be present if CS.OPT_BUFFER is on.
  x86?: cs_x86; // X86 architecture, including 16-bit, 32-bit & 64-bit mode
  arm?: cs_arm; // ARM64 architecture (aka AArch64)
  arm64?: cs_arm64; // ARM architecture (including Thumb/Thumb2)
  m68k?: cs_m68k; // M68K architecture
  mips?: cs_mips; // MIPS architecture
  ppc?: cs_ppc; // PowerPC architecture
  sparc?: cs_sparc; // Sparc architecture
  sysz?: cs_sysz; // SystemZ architecture
  xcore?: cs_xcore; // XCore architecture
  tms320c64x?: cs_tms320c64x; // TMS320C64x architecture
  m680x?: cs_m680x; // M680X architecture
  evm?: cs_evm; // Ethereum architecture
  mos65xx?: cs_mos65xx; //MOS65XX architecture (including MOS6502)
  wasm?: cs_wasm; // Web Assembly architecture
  bpf?: cs_bpf; // Berkeley Packet Filter architecture (including eBPF)
  riscv?: cs_riscv; // RISCV architecture
  sh?: cs_sh; // SH architecture
  tricore?: cs_tricore; // TriCore architecture
  // alpha?: cs_alpha; // Alpha architecture
  // hppa?: cs_hppa; // HPPA architecture
}

// User-customized setup for SKIPDATA option
interface cs_opt_skipdata {
  mnemonic: string | null; // Capstone considers data to skip as special "instructions", User can specify the string for this instruction's "mnemonic" here (default = ".byte").
  callback: cs_skipdata_cb_t | null; // User-defined callback function to be called when Capstone hits data (default = null).
  user_data: object; // User-defined data to be passed to callback function.
}

// fmt() options
interface cs_opt_fmt {
  hex_comment?: boolean; // Specifies if the output should include decimal comments for hexadecimal imm
  colors?: boolean; // Specifies if the output should include coloring
  bytes?: boolean; // Specifies if the formatted string should have the instructions bytes.
  address?: boolean; // Specifies if the formatted string should include the instructions address.
  ASCII?: boolean; // Specifies if the formatted string should include the bytes ASCII representation.
}

// Customize mnemonic for instructions with alternative name.
// To reset existing customized instruction to its default mnemonic,
// call option(CS.OPT_MNEMONIC) again with the same id and null value
interface cs_opt_mnem {
  id: number; // ID of instruction to be customized obtained from the cs_insn object.
  mnemonic: string | null; // Customized instruction mnemonic(or null).
}

namespace CS {
  // Return codes
  export const ERR_OK: cs_err = 0; // No error: everything was fine
  export const ERR_MEM: cs_err = 1; // Out-Of-Memory error: cs_open(), cs_disasm(), cs_disasm_iter()
  export const ERR_ARCH: cs_err = 2; // Unsupported architecture: cs_open()
  export const ERR_HANDLE: cs_err = 3; // Invalid handle: cs_op_count(), cs_op_index()
  export const ERR_CSH: cs_err = 4; // Invalid csh argument: cs_close(), cs_errno(), cs_option()
  export const ERR_MODE: cs_err = 5; // Invalid/unsupported mode: cs_open()
  export const ERR_OPTION: cs_err = 6; // Invalid/unsupported option: cs_option()
  export const ERR_DETAIL: cs_err = 7; // Information is unavailable because detail option is OFF
  export const ERR_MEMSETUP: cs_err = 8; // Dynamic memory management uninitialized (see OPT_MEM)
  export const ERR_VERSION: cs_err = 9; // Unsupported version (bindings)
  export const ERR_DIET: cs_err = 10; // Access irrelevant data in "diet" engine
  export const ERR_SKIPDATA: cs_err = 11; // Access irrelevant data for "data" instruction in SKIPDATA mode
  export const ERR_X86_ATT: cs_err = 12; // X86 AT&T syntax is unsupported (opt-out at compile time)
  export const ERR_X86_INTEL: cs_err = 13; // X86 Intel syntax is unsupported (opt-out at compile time)
  export const ERR_X86_MASM: cs_err = 14; // X86 Intel syntax is unsupported (opt-out at compile time)

  // Architectures
  export const ARCH_ARM: cs_arch = 0; // ARM architecture (including Thumb, Thumb-2)
  export const ARCH_ARM64: cs_arch = 1; // ARM-64, also called AArch64
  export const ARCH_AARCH64: cs_arch = 1; // AArch-64, also called ARM-64
  export const ARCH_MIPS: cs_arch = 2; // Mips architecture
  export const ARCH_X86: cs_arch = 3; // X86 architecture (including x86 & x86-64)
  export const ARCH_PPC: cs_arch = 4; // PowerPC architecture
  export const ARCH_SPARC: cs_arch = 5; // Sparc architecture
  export const ARCH_SYSZ: cs_arch = 6; // SystemZ architecture
  export const ARCH_XCORE: cs_arch = 7; // XCore architecture
  export const ARCH_M68K: cs_arch = 8; // 68K architecture
  export const ARCH_TMS320C64X: cs_arch = 9; // TMS320C64x architecture
  export const ARCH_M680X: cs_arch = 10; // 680X architecture
  export const ARCH_EVM: cs_arch = 11; // Ethereum architecture
  export const ARCH_MOS65XX: cs_arch = 12; // MOS65XX architecture (including MOS6502)
  export const ARCH_WASM: cs_arch = 13; // WebAssembly architecture
  export const ARCH_BPF: cs_arch = 14; // Berkeley Packet Filter architecture (including eBPF)
  export const ARCH_RISCV: cs_arch = 15; // RISCV architecture
  export const ARCH_SH: cs_arch = 16; // SH architecture
  export const ARCH_TRICORE: cs_arch = 17; // TriCore architecture
  // export const ARCH_ALPHA = 18; // Alpha architecture
  // export const ARCH_HPPA = 19; // HPPA architecture
  export const ARCH_MAX: cs_arch = 18; // The maximum architecture value.
  export const ARCH_ALL: cs_arch = 0xffff; // Represents a mask that includes all architecture values.

  // Modes
  export const MODE_LITTLE_ENDIAN: cs_mode = 0; // little-endian mode (default mode)
  export const MODE_ARM: cs_mode = 0; // 32-bit ARM
  export const MODE_16: cs_mode = 1 << 1; // 16-bit mode (X86)
  export const MODE_32: cs_mode = 1 << 2; // 32-bit mode (X86)
  export const MODE_64: cs_mode = 1 << 3; // 64-bit mode (X86, PPC)
  export const MODE_THUMB: cs_mode = 1 << 4; // ARM's Thumb mode, including Thumb-2
  export const MODE_MCLASS: cs_mode = 1 << 5; // ARM's Cortex-M series
  export const MODE_V8: cs_mode = 1 << 6; // ARMv8 A32 encodings for ARM
  export const MODE_MICRO: cs_mode = 1 << 4; // MicroMips mode (MIPS)
  export const MODE_MIPS3: cs_mode = 1 << 5; // Mips III ISA
  export const MODE_MIPS32R6: cs_mode = 1 << 6; // Mips32r6 ISA
  export const MODE_MIPS2: cs_mode = 1 << 7; // Mips II ISA
  export const MODE_V9: cs_mode = 1 << 4; // SparcV9 mode (Sparc)
  export const MODE_QPX: cs_mode = 1 << 4; // Quad Processing eXtensions mode (PPC)
  export const MODE_SPE: cs_mode = 1 << 5; // Signal Processing Engine mode (PPC)
  export const MODE_BOOKE: cs_mode = 1 << 6; // Book-E mode (PPC)
  export const MODE_PS: cs_mode = 1 << 7; // Paired-singles mode (PPC)
  export const MODE_M68K_000: cs_mode = 1 << 1; // M68K 68000 mode
  export const MODE_M68K_010: cs_mode = 1 << 2; // M68K 68010 mode
  export const MODE_M68K_020: cs_mode = 1 << 3; // M68K 68020 mode
  export const MODE_M68K_030: cs_mode = 1 << 4; // M68K 68030 mode
  export const MODE_M68K_040: cs_mode = 1 << 5; // M68K 68040 mode
  export const MODE_M68K_060: cs_mode = 1 << 6; // M68K 68060 mode
  export const MODE_BIG_ENDIAN: cs_mode = 1 << 31; // big-endian mode
  export const MODE_MIPS32: cs_mode = MODE_32; // Mips32 ISA (Mips)
  export const MODE_MIPS64: cs_mode = MODE_64; // Mips64 ISA (Mips)
  export const MODE_M680X_6301: cs_mode = 1 << 1; // M680X Hitachi 6301,6303 mode
  export const MODE_M680X_6309: cs_mode = 1 << 2; // M680X Hitachi 6309 mode
  export const MODE_M680X_6800: cs_mode = 1 << 3; // M680X Motorola 6800,6802 mode
  export const MODE_M680X_6801: cs_mode = 1 << 4; // M680X Motorola 6801,6803 mode
  export const MODE_M680X_6805: cs_mode = 1 << 5; // M680X Motorola/Freescale 6805 mode
  export const MODE_M680X_6808: cs_mode = 1 << 6; // M680X Motorola/Freescale/NXP 68HC08 mode
  export const MODE_M680X_6809: cs_mode = 1 << 7; // M680X Motorola 6809 mode
  export const MODE_M680X_6811: cs_mode = 1 << 8; // M680X Motorola/Freescale/NXP 68HC11 mode
  export const MODE_M680X_CPU12: cs_mode = 1 << 9; // M680X Motorola/Freescale/NXP CPU12
  export const MODE_M680X_HCS08: cs_mode = 1 << 10; // M680X Freescale/NXP HCS08 mode
  export const MODE_BPF_CLASSIC: cs_mode = 0; // Classic BPF mode (default)
  export const MODE_BPF_EXTENDED: cs_mode = 1 << 0; // Extended BPF mode
  export const MODE_RISCV32: cs_mode = 1 << 0; // RISCV RV32G
  export const MODE_RISCV64: cs_mode = 1 << 1; // RISCV RV64G
  export const MODE_RISCVC: cs_mode = 1 << 2; // RISCV compressed instructure mode
  export const MODE_MOS65XX_6502: cs_mode = 1 << 1; // MOS65XXX MOS 6502
  export const MODE_MOS65XX_65C02: cs_mode = 1 << 2; // MOS65XXX WDC 65c02
  export const MODE_MOS65XX_W65C02: cs_mode = 1 << 3; // MOS65XXX WDC W65c02
  export const MODE_MOS65XX_65816: cs_mode = 1 << 4; // MOS65XXX WDC 65816, 8-bit m/x
  export const MODE_MOS65XX_65816_LONG_M: cs_mode = 1 << 5; // MOS65XXX WDC 65816, 16-bit m, 8-bit x
  export const MODE_MOS65XX_65816_LONG_X: cs_mode = 1 << 6; // MOS65XXX WDC 65816, 8-bit m, 16-bit x
  export const MODE_MOS65XX_65816_LONG_MX: cs_mode =
    MODE_MOS65XX_65816_LONG_M | MODE_MOS65XX_65816_LONG_X;
  export const MODE_SH2: cs_mode = 1 << 1; // SH2
  export const MODE_SH2A: cs_mode = 1 << 2; // SH2A
  export const MODE_SH3: cs_mode = 1 << 3; // SH3
  export const MODE_SH4: cs_mode = 1 << 4; // SH4
  export const MODE_SH4A: cs_mode = 1 << 5; // SH4A
  export const MODE_SHFPU: cs_mode = 1 << 6; // w/ FPU
  export const MODE_SHDSP: cs_mode = 1 << 7; // w/ DSP
  export const MODE_TRICORE_110: cs_mode = 1 << 1; // Tricore 1.1
  export const MODE_TRICORE_120: cs_mode = 1 << 2; // Tricore 1.2
  export const MODE_TRICORE_130: cs_mode = 1 << 3; // Tricore 1.3
  export const MODE_TRICORE_131: cs_mode = 1 << 4; // Tricore 1.3.1
  export const MODE_TRICORE_160: cs_mode = 1 << 5; // Tricore 1.6
  export const MODE_TRICORE_161: cs_mode = 1 << 6; // Tricore 1.6.1
  export const MODE_TRICORE_162: cs_mode = 1 << 7; // Tricore 1.6.2
  // export const MODE_TRICORE_162 = 1 << 7; // Tricore 1.6.2
  // export const MODE_HPPA_11 = 1 << 1; // HPPA 1.1
  // export const MODE_HPPA_20 = 1 << 2; // HPPA 2.0
  // export const MODE_HPPA_20W = CS.MODE_HPPA_20 | (1 << 3); // HPPA 2.0 wide

  // Runtime option for the disassembled engine
  export const OPT_INVALID: cs_opt_type = 0; // No option specified
  export const OPT_SYNTAX: cs_opt_type = 1; // Intel X86 asm syntax (CS_ARCH_X86 arch Assembly output syntax)
  export const OPT_DETAIL: cs_opt_type = 2; // Break down instruction structure into details
  export const OPT_MODE: cs_opt_type = 3; // Change engine's mode at run-time
  export const OPT_MEM: cs_opt_type = 4; // Change engine's mode at run-time
  export const OPT_SKIPDATA: cs_opt_type = 5; // Skip data when disassembling
  export const OPT_SKIPDATA_SETUP: cs_opt_type = 6; // Setup user-defined function for SKIPDATA option
  export const OPT_MNEMONIC: cs_opt_type = 7; // Customize instruction mnemonic
  export const OPT_UNSIGNED: cs_opt_type = 8; // print immediate operands in unsigned form
  export const OPT_NO_BRANCH_OFFSET: cs_opt_type = 9; // ARM, prints branch immediates without offset.
  export const OPT_BUFFER: cs_opt_type = 10; // Adds the raw buffer to the insn and detail object.

  // Capstone option value
  export const OPT_OFF: cs_opt_value = 0; // Turn OFF an option - default option of CS_OPT_DETAIL
  export const OPT_ON: cs_opt_value = 3; // Turn ON an option (CS_OPT_DETAIL)
  // export const OPT_DETAIL_REAL: cs_opt_value = 1 << 1; // If enabled, always sets the real instruction detail. Even if the instruction is an alias.

  // Capstone syntax value
  export const OPT_SYNTAX_DEFAULT: cs_opt_value = 0; // Default assembly syntax of all platforms (CS_OPT_SYNTAX)
  export const OPT_SYNTAX_INTEL: cs_opt_value = 1; // Intel X86 asm syntax - default syntax on X86 (CS_OPT_SYNTAX, CS_ARCH_X86)
  export const OPT_SYNTAX_ATT: cs_opt_value = 2; // ATT asm syntax (CS_OPT_SYNTAX, CS_ARCH_X86)
  export const OPT_SYNTAX_NOREGNAME: cs_opt_value = 3; // Asm syntax prints register name with only number - (CS_OPT_SYNTAX, CS_ARCH_PPC, CS_ARCH_ARM)
  export const OPT_SYNTAX_MASM: cs_opt_value = 4; // X86 Intel Masm syntax (CS_OPT_SYNTAX).
  export const OPT_SYNTAX_MOTOROLA: cs_opt_value = 5; // MOS65XX use $ as hex prefix.
  // export const OPT_SYNTAX_CS_REG_ALIAS = 1 << 7; // Prints common register alias which are not defined in LLVM (ARM: r9 = sb etc.)
  // export const OPT_SYNTAX_PERCENT = 1 << 8; // Prints the % in front of PPC registers.

  // Common instruction groups - to be consistent across all architectures.
  export const GRP_INVALID: cs_group_type = 0; // uninitialized/invalid group.
  export const GRP_JUMP: cs_group_type = 1; // all jump instructions (conditional+direct+indirect jumps)
  export const GRP_CALL: cs_group_type = 2; // all call instructions
  export const GRP_RET: cs_group_type = 3; // all return instructions
  export const GRP_INT: cs_group_type = 4; // all interrupt instructions (int+syscall)
  export const GRP_IRET: cs_group_type = 5; // all interrupt return instructions
  export const GRP_PRIVILEGE: cs_group_type = 6; // all privileged instructions
  export const GRP_BRANCH_RELATIVE: cs_group_type = 7; // all relative branching instructions

  // Common instruction operand types - to be consistent across all architectures.
  export const OP_INVALID: cs_op_type = 0; // Uninitialized/invalid operand.
  export const OP_REG: cs_op_type = 1; // Register operand.
  export const OP_IMM: cs_op_type = 2; // Immediate operand.
  export const OP_MEM: cs_op_type = 0x80; // Memory operand.
  export const OP_FP: cs_op_type = 3; // Floating-Point operand.

  // Common instruction operand access types - to be consistent across all architectures. It is possible to combine access types, for example: CS_AC_READ | CS_AC_WRITE
  export const AC_INVALID: cs_ac_type = 0; // Uninitialized/invalid access type.
  export const AC_READ: cs_ac_type = 1 << 0; // Operand read from memory or register.
  export const AC_WRITE: cs_ac_type = 1 << 1; // Operand written to memory or register.

  // query id for cs_support()
  export const SUPPORT_DIET = ARCH_ALL + 1;
  export const SUPPORT_X86_REDUCE = ARCH_ALL + 2;

  // Manifest Constants
  export const MNEMONIC_SIZE = 32;
  export const INSN_SIZE = 240;
  export const DETAIL_SIZE = 1864;
  export const MAX_IMPL_W_REGS = 20;
  export const MAX_IMPL_R_REGS = 20;
  export const MAX_NUM_GROUPS = 8;

  /**
   * Retrieves the offset relative to the start of the buffer where the instruction resides.
   *
   * NOTE: this assumes position is (>=1)
   * @param insns - The instructions to analyze.
   * @param position - The index of the specific insn.
   * @returns The offset of the instruction relative to the buffer.
   */
  export function INSN_OFFSET(insns: cs_insn[], position: number): number {
    const base: number = insns[0].address;
    const positional: number = insns[position - 1].address;
    return positional - base;
  }

  export class CAPSTONE {
    private arch: cs_arch; // The chosen architecture for this instance(cannot be changed)
    private mode: cs_mode; // The mode associated with the chooses arch(can be changed via CS.OPT_MODE)
    private handle_ptr: pointer_t<csh>; // The address of the cash handle
    private arch_info: { instance: any; name: string }; // Decides what architecture specific info will be present in cs_detail
    private opt_buffer: boolean = false; // Option toggle for CS.OPT_BUFFER

    /**
     * Create a new instance of the Capstone disassembly engine.
     *
     * @param arch - The architecture type.
     * @param mode - The mode type.
     */
    constructor(arch: cs_arch, mode: cs_mode) {
      this.arch = arch;
      this.mode = mode;
      this.handle_ptr = 0;
      this.open();
      this.arch_info = this.init(arch);
    }

    /**
     * Return the Capstone library version as a string.
     *
     * @public
     * @returns The Capstone library version as a string in the format "major.minor".
     */
    public version(): string {
      const major_ptr: number = Memory.malloc(4);
      const minor_ptr: number = Memory.malloc(4);
      Wrapper.ccall(
        'cs_version',
        'number',
        ['pointer', 'pointer'],
        [major_ptr, minor_ptr],
      );
      const major: number = Memory.read(major_ptr, 'i32');
      const minor: number = Memory.read(minor_ptr, 'i32');
      Memory.free(major_ptr);
      Memory.free(minor_ptr);
      return `${major}.${minor}`;
    }

    /**
     * Check if Capstone supports a specific query.
     *
     * @public
     * @param query - The query ID to check.
     * @returns A boolean indicating whether Capstone supports the given query.
     */
    public support(query: number): boolean {
      var ret: boolean = Wrapper.ccall(
        'cs_support',
        'number',
        ['number'],
        [query],
      );
      return Boolean(ret);
    }

    /**
     * Get the error message string for a given error code.
     *
     * @public
     * @param code - The error code.
     * @returns The error message string corresponding to the given error code.
     */
    public strerror(code: number): string {
      return Wrapper.ccall('cs_strerror', 'string', ['number'], [code]);
    }

    /**
     * Get the error code for the most recent Capstone error that occurred with the given handle.
     *
     * @public
     * @param handle - The handle for which to get the error code.
     * @returns The error code for the most recent Capstone error.
     */
    public errno(handle: csh): cs_err {
      return Wrapper.ccall('cs_errno', 'number', ['pointer'], [handle]);
    }

    private init(arch: cs_arch): { instance: Function; name: string } {
      const arch_map: { [key: number]: { instance: any; name: string } } = {
        [CS.ARCH_ARM]: { instance: cs_arm, name: 'arm' },
        [CS.ARCH_ARM64]: { instance: cs_arm64, name: 'arm64' },
        [CS.ARCH_AARCH64]: { instance: cs_arm64, name: 'arm64' },
        [CS.ARCH_MIPS]: { instance: cs_mips, name: 'mips' },
        [CS.ARCH_X86]: { instance: cs_x86, name: 'x86' },
        [CS.ARCH_PPC]: { instance: cs_ppc, name: 'ppc' },
        [CS.ARCH_SPARC]: { instance: cs_sparc, name: 'sparc' },
        [CS.ARCH_SYSZ]: { instance: cs_sysz, name: 'sysz' },
        [CS.ARCH_XCORE]: { instance: cs_xcore, name: 'xcore' },
        [CS.ARCH_TMS320C64X]: { instance: cs_tms320c64x, name: 'tms320c64x' },
        [CS.ARCH_M680X]: { instance: cs_m680x, name: 'm680x' },
        [CS.ARCH_M68K]: { instance: cs_m68k, name: 'm68k' },
        [CS.ARCH_EVM]: { instance: cs_evm, name: 'evm' },
        [CS.ARCH_MOS65XX]: { instance: cs_mos65xx, name: 'mos65xx' },
        [CS.ARCH_WASM]: { instance: cs_wasm, name: 'wasm' },
        [CS.ARCH_BPF]: { instance: cs_bpf, name: 'bpf' },
        [CS.ARCH_RISCV]: { instance: cs_riscv, name: 'riscv' },
        [CS.ARCH_SH]: { instance: cs_sh, name: 'sh' },
        [CS.ARCH_TRICORE]: { instance: cs_tricore, name: 'tricore' },
      };
      return arch_map[arch];
    }

    /**
     * Handler to parse the cs_opt_skipdata obj
     *
     * @private
     * @param skipdata - User-customized setup for SKIPDATA option
     * @returns The pointer to the cs_opt_skipdata struct
     */
    private skipdata_cb(setup: any): number {
      const { mnemonic, callback, user_data } = setup;
      const skipdata_struct: pointer_t<cs_opt_skipdata> = Memory.malloc(24);
      typeof mnemonic === 'string' &&
        Memory.write(skipdata_struct, mnemonic, 'char*');
      const callback_ptr: pointer_t<Function> = skipdata_struct + 8;
      const user_data_ptr: pointer_t<any> = skipdata_struct + 16;
      if (typeof callback === 'function') {
        const cb_ptr = Wrapper.addFunction(function (
          code_ptr: any,
          code_size: any,
          offset: any,
          user_data: any,
        ): number {
          const code = [];
          for (let i = 0; i < code_size; i++)
            code.push(Memory.read(parseInt(code_ptr), 'u8'));
          return callback(code, code_size, offset /* TODO: user_data*/);
        },
        'iiiii');
        Memory.write(callback_ptr, cb_ptr, '*');
      }

      return skipdata_struct;
    }

    /**
     * Dereferences a pointer to a cs_insn strict to retrieve information about a disassembled instruction.
     *
     * @private
     * @param insn_ptr - The pointer to the disassembled instruction.
     * @returns Information about the disassembled instruction.
     */
    private deref(insn_ptr: pointer_t<cs_insn>): cs_insn {
      const insn_id: number = Memory.read(insn_ptr, 'u32');
      const insn_addr: number = Memory.read(insn_ptr + 8, 'u64');
      const insn_size: number = Memory.read(insn_ptr + 16, 'u16');
      const insn_mn: string = Wrapper.UTF8ToString(insn_ptr + 42);
      const insn_op_str: string = Wrapper.UTF8ToString(insn_ptr + 66 + 8);
      const insn_bytes: number[] = [];

      for (let j = 0; j < insn_size; j++) {
        const byte = Memory.read(insn_ptr + 18 + j, 'u8');
        insn_bytes.push(byte);
      }

      const insn: cs_insn = {
        id: insn_id,
        address: insn_addr,
        size: insn_size,
        mnemonic: insn_mn,
        op_str: insn_op_str,
        bytes: new Uint8Array(insn_bytes),
      };

      const detail_ptr: pointer_t<pointer_t<cs_detail>> = Memory.read(
        insn_ptr + 238,
        '*',
      );
      const has_detail = detail_ptr != Memory.nullptr;
      if (has_detail) {
        insn.detail = this.get_detail(detail_ptr);
      }
      if (this.opt_buffer) {
        const heap = Wrapper.HEAPU8.buffer;
        if (has_detail)
          insn.detail.buffer = new Uint8Array(
            heap,
            Wrapper._cs_detail_buffer(insn_ptr),
            DETAIL_SIZE,
          );
        insn.buffer = new Uint8Array(
          heap,
          Wrapper._cs_insn_buffer(insn_ptr),
          DETAIL_SIZE,
        );
      }
      return insn;
    }

    /**
     * Converts an array of `cs_insn` objects into a pointer to an array of cs_insn structures.
     *
     * @private
     * @param insns - Array of `cs_insn` objects to be converted.
     * @returns A pointer to the array of cs_insn structures.
     */
    private ref(insns: cs_insn[] | cs_insn): pointer_t<cs_insn[] | cs_insn> {
      if (!Array.isArray(insns)) insns = [insns];
      const count: number = insns.length;
      const insns_ptr: pointer_t<cs_insn[]> = Memory.malloc(INSN_SIZE * count);
      for (let i = 0; i < count; i++) {
        const insn = insns[i];
        const insn_ptr = insns_ptr + i * INSN_SIZE;
        insn.id !== undefined &&
          insn.id !== null &&
          Memory.write(insn_ptr, insn.id, 'i32');
        insn.address !== undefined &&
          insn.address !== null &&
          Memory.write(insn_ptr + 8, insn.address, 'i64');
        insn.size !== undefined &&
          insn.size !== null &&
          Memory.write(insn_ptr + 16, insn.size, 'i16');
        insn.mnemonic !== undefined &&
          insn.mnemonic !== null &&
          Memory.write(insn_ptr + 42, insn.mnemonic, 'char*');
        insn.op_str !== undefined &&
          insn.op_str !== null &&
          Memory.write(insn_ptr + 66 + 8, insn.op_str, 'char*');

        for (let j = 0; j < (insn.size || 0); j++) {
          insn.bytes[j] !== undefined &&
            insn.bytes[j] !== null &&
            Memory.write(insn_ptr + 18 + j, insn.bytes[j], 'u8');
        }

        if (insn.detail) {
          const detail: pointer_t<pointer_t<cs_detail>> = insn_ptr + 238;
          const detail_ptr: pointer_t<cs_detail> = Memory.malloc(1864);
          const arch_info_ptr: pointer_t<any> = detail_ptr + 96;
          let arch;
          let op_ptr;
          let op;
          Memory.write(detail, detail_ptr, '*');
          for (let i = 0; i < (insn.detail.regs_read_count || 0); i++)
            insn.detail.regs_read !== undefined &&
              insn.detail.regs_read !== null &&
              Memory.write(detail_ptr + i, insn.detail.regs_read[i], 'i16');
          insn.detail.regs_read_count !== undefined &&
            insn.detail.regs_read_count !== null &&
            Memory.write(detail_ptr + 40, insn.detail.regs_read_count, 'ubyte');
          for (let i = 0; i < (insn.detail.regs_write_count || 0); i++)
            insn.detail.regs_write[i] !== undefined &&
              insn.detail.regs_write[i] !== null &&
              Memory.write(
                detail_ptr + 42 + i,
                insn.detail.regs_write[i],
                'i16',
              );
          insn.detail.regs_write_count !== undefined &&
            insn.detail.regs_write_count !== null &&
            Memory.write(
              detail_ptr + 82,
              insn.detail.regs_write_count,
              'ubyte',
            );
          for (let i = 0; i < (insn.detail.groups_count || 0); i++)
            insn.detail.groups[i] !== undefined &&
              insn.detail.groups[i] !== null &&
              Memory.write(detail_ptr + 83 + i, insn.detail.groups[i], 'ubyte');
          insn.detail.groups_count !== undefined &&
            insn.detail.groups_count !== null &&
            Memory.write(detail_ptr + 91, insn.detail.groups_count, 'ubyte');
          insn.detail.writeback !== undefined &&
            insn.detail.writeback !== null &&
            Memory.write(detail_ptr + 92, insn.detail.writeback, 'bool');
          switch (this.arch) {
            case ARCH_ARM:
              arch = insn.detail.arm;
              arch.op_count !== undefined &&
                arch.op_count !== null &&
                Memory.write(arch_info_ptr + 32, arch.op_count, 'ubyte');
              for (let i = 0; i < (arch.op_count || 0); i++) {
                op_ptr = arch_info_ptr + 40 + i * 48;
                op = arch.operands[i];
                op.type !== undefined &&
                  op.type !== null &&
                  Memory.write(op_ptr + 12, op.type, 'i32');
                switch (arch.operands[i].type || 0) {
                  case ARM.OP_SYSREG:
                  case ARM.OP_REG:
                    op.reg !== undefined &&
                      op.reg !== null &&
                      Memory.write(op_ptr + 16, op.reg, 'i32');
                    break;
                  case ARM.OP_IMM:
                  case ARM.OP_PIMM:
                    op.imm !== undefined &&
                      op.imm !== null &&
                      Memory.write(op_ptr + 16, op.imm, 'i32');
                    break;
                  case ARM.OP_FP:
                    op.fp !== undefined &&
                      op.fp !== null &&
                      Memory.write(op_ptr + 16, op.fp, 'double');
                    break;
                  case ARM.OP_SETEND:
                    op.setend !== undefined &&
                      op.setend !== null &&
                      Memory.write(op_ptr + 16, op.setend, 'i32');
                    break;
                  case ARM.OP_MEM:
                    op.mem.base !== undefined &&
                      op.mem.base !== null &&
                      Memory.write(op_ptr + 16, op.mem.base, 'i32');
                    op.mem.index !== undefined &&
                      op.mem.index !== null &&
                      Memory.write(op_ptr + 20, op.mem.index, 'i32');
                    op.mem.scale !== undefined &&
                      op.mem.scale !== null &&
                      Memory.write(op_ptr + 24, op.mem.scale, 'i32');
                    op.mem.disp !== undefined &&
                      op.mem.disp !== null &&
                      Memory.write(op_ptr + 28, op.mem.disp, 'i32');
                    op.mem.lshift !== undefined &&
                      op.mem.lshift !== null &&
                      Memory.write(op_ptr + 32, op.mem.lshift, 'i32');
                    break;
                }
              }
              break;
            case ARCH_ARM64:
              arch = insn.detail.arm64;
              arch.op_count !== undefined &&
                arch.op_count !== null &&
                Memory.write(arch_info_ptr + 7, arch.op_count, 'ubyte');
              for (let i = 0; i < (arch.op_count || 0); i++) {
                op_ptr = arch_info_ptr + 8 + i * 56;
                op = arch.operands[i];
                op.type !== undefined &&
                  op.type !== null &&
                  Memory.write(op_ptr + 20, op.type, 'i32');
                switch (arch.operands[i].type || 0) {
                  case ARM64.OP_REG:
                  case ARM64.OP_REG_MRS:
                  case ARM64.OP_REG_MSR:
                    op.reg !== undefined &&
                      op.reg !== null &&
                      Memory.write(op_ptr + 32, op.reg, 'i32');
                    break;
                  case ARM64.OP_CIMM:
                  case ARM64.OP_IMM:
                    op.imm !== undefined &&
                      op.imm !== null &&
                      Memory.write(op_ptr + 32, op.imm, 'i64');
                    break;
                  case ARM64.OP_FP:
                    op.fp !== undefined &&
                      op.fp !== null &&
                      Memory.write(op_ptr + 32, op.fp, 'double');
                    break;
                  case ARM64.OP_PSTATE:
                    op.pstate !== undefined &&
                      op.pstate !== null &&
                      Memory.write(op_ptr + 32, op.pstate, 'i32');
                    break;
                  case ARM64.OP_SYS:
                    op.sys !== undefined &&
                      op.sys !== null &&
                      Memory.write(op_ptr + 32, op.sys, 'i32');
                    break;
                  case ARM64.OP_BARRIER:
                    op.barrier !== undefined &&
                      op.barrier !== null &&
                      Memory.write(op_ptr + 32, op.barrier, 'i32');
                    break;
                  case ARM64.OP_PREFETCH:
                    op.prefetch !== undefined &&
                      op.prefetch !== null &&
                      Memory.write(op_ptr + 32, op.prefetch, 'i32');
                    break;
                  case ARM64.OP_MEM:
                    op.mem.base !== undefined &&
                      op.mem.base !== null &&
                      Memory.write(op_ptr + 32, op.mem.base, 'i32');
                    op.mem.index !== undefined &&
                      op.mem.index !== null &&
                      Memory.write(op_ptr + 36, op.mem.index, 'i32');
                    op.mem.disp !== undefined &&
                      op.mem.disp !== null &&
                      Memory.write(op_ptr + 32, op.mem.disp, 'i32');
                    break;
                  case ARM64.OP_SVCR:
                    op.sme_index.reg !== undefined &&
                      op.sme_index.reg !== null &&
                      Memory.write(op_ptr + 32, op.sme_index.reg, 'i32');
                    op.sme_index.base !== undefined &&
                      op.sme_index.base !== null &&
                      Memory.write(op_ptr + 36, op.sme_index.base, 'i32');
                    op.sme_index.disp !== undefined &&
                      op.sme_index.disp !== null &&
                      Memory.write(op_ptr + 40, op.sme_index.disp, 'i32');
                    break;
                }
              }
              break;
            case ARCH_MIPS:
              arch = insn.detail.mips;
              arch.op_count !== undefined &&
                arch.op_count !== null &&
                Memory.write(arch_info_ptr + 0, arch.op_count, 'ubyte');
              for (let i = 0; i < (arch.op_count || 0); i++) {
                op_ptr = arch_info_ptr + 8 + i * 24;
                op = arch.operands[i];
                op.type !== undefined &&
                  op.type !== null &&
                  Memory.write(op_ptr, op.type, 'i32');
                switch (arch.operands[i].type || 0) {
                  case MIPS.OP_REG:
                    op.reg !== undefined &&
                      op.reg !== null &&
                      Memory.write(op_ptr + 8, op.reg, 'i32');
                    break;
                  case MIPS.OP_IMM:
                    op.imm !== undefined &&
                      op.imm !== null &&
                      Memory.write(op_ptr + 8, op.imm, 'long');
                    break;
                  case MIPS.OP_MEM:
                    op.mem.base !== undefined &&
                      op.mem.base !== null &&
                      Memory.write(op_ptr + 8, op.mem.base, 'i32');
                    op.mem.disp !== undefined &&
                      op.mem.disp !== null &&
                      Memory.write(op_ptr + 12, op.mem.disp, 'long');
                    break;
                }
              }
              break;
            case ARCH_X86:
              arch = insn.detail.x86;
              arch.op_count !== undefined &&
                arch.op_count !== null &&
                Memory.write(arch_info_ptr + 64, arch.op_count, 'ubyte');
              arch.disp !== undefined &&
                arch.disp !== null &&
                Memory.write(arch_info_ptr + 16, arch.disp, 'long');
              for (let i = 0; i < (arch.op_count || 0); i++) {
                op_ptr = arch_info_ptr + 72 + i * 48;
                op = arch.operands[i];
                op.type !== undefined &&
                  op.type !== null &&
                  Memory.write(op_ptr, op.type, 'i32');
                switch (arch.operands[i].type || 0) {
                  case X86.OP_REG:
                    op.reg !== undefined &&
                      op.reg !== null &&
                      Memory.write(op_ptr + 8, op.reg, 'i32');
                    break;
                  case X86.OP_IMM:
                    op.imm !== undefined &&
                      op.imm !== null &&
                      Memory.write(op_ptr + 8, op.imm, 'long');
                    break;
                  case X86.OP_MEM:
                    op.mem.segment !== undefined &&
                      op.mem.segment !== null &&
                      Memory.write(op_ptr + 8, op.mem.segment, 'i32');
                    op.mem.base !== undefined &&
                      op.mem.base !== null &&
                      Memory.write(op_ptr + 12, op.mem.base, 'i32');
                    op.mem.index !== undefined &&
                      op.mem.index !== null &&
                      Memory.write(op_ptr + 16, op.mem.index, 'i32');
                    op.mem.scale !== undefined &&
                      op.mem.scale !== null &&
                      Memory.write(op_ptr + 20, op.mem.scale, 'i32');
                    break;
                }
              }
              break;
            case ARCH_PPC:
              arch = insn.detail.ppc;
              arch.op_count !== undefined &&
                arch.op_count !== null &&
                Memory.write(arch_info_ptr + 9, arch.op_count, 'ubyte');
              for (let i = 0; i < (arch.op_count || 0); i++) {
                op_ptr = arch_info_ptr + 16 + i * 24;
                op = arch.operands[i];
                op.type !== undefined &&
                  op.type !== null &&
                  Memory.write(op_ptr, op.type, 'i32');
                switch (arch.operands[i].type || 0) {
                  case PPC.OP_REG:
                    op.reg !== undefined &&
                      op.reg !== null &&
                      Memory.write(op_ptr + 8, op.reg, 'i32');
                    break;
                  case PPC.OP_IMM:
                    op.imm !== undefined &&
                      op.imm !== null &&
                      Memory.write(op_ptr + 8, op.imm, 'long');
                    break;
                  case PPC.OP_CRX:
                    op.crx.scale !== undefined &&
                      op.crx.scale !== null &&
                      Memory.write(op_ptr + 8, op.crx.scale, 'u32');
                    op.crx.reg !== undefined &&
                      op.crx.reg !== null &&
                      Memory.write(op_ptr + 12, op.crx.reg, 'i32');
                    op.crx.cond !== undefined &&
                      op.crx.cond !== null &&
                      Memory.write(op_ptr + 16, op.crx.cond, 'i32');
                    break;
                  case PPC.OP_MEM:
                    op.mem.base !== undefined &&
                      op.mem.base !== null &&
                      Memory.write(op_ptr + 8, op.mem.base, 'i32');
                    op.mem.disp !== undefined &&
                      op.mem.disp !== null &&
                      Memory.write(op_ptr + 12, op.mem.disp, 'long');
                    break;
                }
              }
              break;
            case ARCH_SPARC:
              arch = insn.detail.sparc;
              arch.op_count !== undefined &&
                arch.op_count !== null &&
                Memory.write(arch_info_ptr + 8, arch.op_count, 'ubyte');
              for (let i = 0; i < (arch.op_count || 0); i++) {
                op_ptr = arch_info_ptr + 16 + i * 16;
                op = arch.operands[i];
                op.type !== undefined &&
                  op.type !== null &&
                  Memory.write(op_ptr, op.type, 'i32');
                switch (arch.operands[i].type || 0) {
                  case SPARC.OP_REG:
                    op.reg !== undefined &&
                      op.reg !== null &&
                      Memory.write(op_ptr + 8, op.reg, 'i32');
                    break;
                  case SPARC.OP_IMM:
                    op.imm !== undefined &&
                      op.imm !== null &&
                      Memory.write(op_ptr, op.imm, 'i32');
                    break;
                  case SPARC.OP_MEM:
                    op.mem.base !== undefined &&
                      op.mem.base !== null &&
                      Memory.write(op_ptr + 8, op.mem.base, 'ubyte');
                    op.mem.index !== undefined &&
                      op.mem.index !== null &&
                      Memory.write(op_ptr + 9, op.mem.index, 'ubyte');
                    op.mem.disp !== undefined &&
                      op.mem.disp !== null &&
                      Memory.write(op_ptr + 12, op.mem.disp, 'i32');
                    break;
                }
              }
              break;
            case ARCH_SYSZ:
              arch = insn.detail.sysz;
              arch.op_count !== undefined &&
                arch.op_count !== null &&
                Memory.write(arch_info_ptr + 4, arch.op_count, 'ubyte');
              for (let i = 0; i < (arch.op_count || 0); i++) {
                op_ptr = arch_info_ptr + 8 + i * 32;
                op = arch.operands[i];
                op.type !== undefined &&
                  op.type !== null &&
                  Memory.write(op_ptr, op.type, 'i32');
                switch (arch.operands[i].type || 0) {
                  case SYSZ.OP_REG:
                    op.reg !== undefined &&
                      op.reg !== null &&
                      Memory.write(op_ptr + 8, op.reg, 'i32');
                    break;
                  case SYSZ.OP_IMM:
                    op.imm !== undefined &&
                      op.imm !== null &&
                      Memory.write(op_ptr + 8, op.imm, 'long');
                    break;
                  case SYSZ.OP_MEM:
                    op.mem.base !== undefined &&
                      op.mem.base !== null &&
                      Memory.write(op_ptr + 8, op.mem.base, 'ubyte');
                    op.mem.index !== undefined &&
                      op.mem.index !== null &&
                      Memory.write(op_ptr + 9, op.mem.index, 'ubyte');
                    op.mem.length !== undefined &&
                      op.mem.length !== null &&
                      Memory.write(op_ptr + 16, op.mem.length, 'ulong');
                    op.mem.disp !== undefined &&
                      op.mem.disp !== null &&
                      Memory.write(op_ptr + 24, op.mem.disp, 'long');
                    break;
                }
              }
              break;
            case ARCH_XCORE:
              arch = insn.detail.xcore;
              arch.op_count !== undefined &&
                arch.op_count !== null &&
                Memory.write(arch_info_ptr + 0, arch.op_count, 'ubyte');
              for (let i = 0; i < (arch.op_count || 0); i++) {
                op_ptr = arch_info_ptr + 4 + i * 16;
                op = arch.operands[i];
                op.type !== undefined &&
                  op.type !== null &&
                  Memory.write(op_ptr, op.type, 'i32');
                switch (arch.operands[i].type || 0) {
                  case XCORE.OP_REG:
                    op.reg !== undefined &&
                      op.reg !== null &&
                      Memory.write(op_ptr + 4, op.reg, 'i32');
                    break;
                  case XCORE.OP_IMM:
                    op.imm !== undefined &&
                      op.imm !== null &&
                      Memory.write(op_ptr + 4, op.imm, 'i32');
                    break;
                  case XCORE.OP_MEM:
                    op.mem.base !== undefined &&
                      op.mem.base !== null &&
                      Memory.write(op_ptr + 4, op.mem.base, 'ubyte');
                    op.mem.index !== undefined &&
                      op.mem.index !== null &&
                      Memory.write(op_ptr + 5, op.mem.index, 'ubyte');
                    op.mem.disp !== undefined &&
                      op.mem.disp !== null &&
                      Memory.write(op_ptr + 8, op.mem.disp, 'i32');
                    op.mem.direct !== undefined &&
                      op.mem.direct !== null &&
                      Memory.write(op_ptr + 12, op.mem.direct, 'i32');
                    break;
                }
              }
              break;
            case ARCH_M68K:
              arch = insn.detail.m68k;
              arch.op_count !== undefined &&
                arch.op_count !== null &&
                Memory.write(arch_info_ptr + 232, arch.op_count, 'ubyte');
              for (let i = 0; i < (arch.op_count || 0); i++) {
                op_ptr = arch_info_ptr + i * 56;
                op = arch.operands[i];
                op.type !== undefined &&
                  op.type !== null &&
                  Memory.write(op_ptr, op.type, 'i32');
                switch (arch.operands[i].type || 0) {
                  case M68K.OP_REG:
                    op.reg !== undefined &&
                      op.reg !== null &&
                      Memory.write(op_ptr, op.reg, 'i32');
                    break;
                  case M68K.OP_IMM:
                    op.imm !== undefined &&
                      op.imm !== null &&
                      Memory.write(op_ptr, op.imm, 'ulong');
                    break;
                  case M68K.OP_FP_DOUBLE:
                    op.dimm !== undefined &&
                      op.dimm !== null &&
                      Memory.write(op_ptr, op.dimm, 'double');
                    break;
                  case M68K.OP_FP_SINGLE:
                    op.simm !== undefined &&
                      op.simm !== null &&
                      Memory.write(op_ptr, op.simm, 'float');
                    break;
                  case M68K.OP_REG_PAIR:
                    break;
                  case M68K.OP_REG_BITS:
                    op.register_bits !== undefined &&
                      op.register_bits !== null &&
                      Memory.write(op_ptr, op.register_bits, 'i32');
                    break;
                  case M68K.OP_BR_DISP:
                    op.br_disp.disp !== undefined &&
                      op.br_disp.disp !== null &&
                      Memory.write(op_ptr + 36, op.br_disp.disp, 'i32');
                    op.br_disp.disp_size !== undefined &&
                      op.br_disp.disp_size !== null &&
                      Memory.write(op_ptr + 40, op.br_disp.disp_size, 'ubyte');
                    break;
                  case M68K.OP_MEM:
                    const mem = op.mem;
                    mem.base_reg !== undefined &&
                      mem.base_reg !== null &&
                      Memory.write(op_ptr + 8, mem.base_reg, 'i32');
                    mem.index_reg !== undefined &&
                      mem.index_reg !== null &&
                      Memory.write(op_ptr + 12, mem.index_reg, 'i32');
                    mem.in_base_reg !== undefined &&
                      mem.in_base_reg !== null &&
                      Memory.write(op_ptr + 16, mem.in_base_reg, 'i32');
                    mem.in_disp !== undefined &&
                      mem.in_disp !== null &&
                      Memory.write(op_ptr + 20, mem.in_disp, 'u32');
                    mem.out_disp !== undefined &&
                      mem.out_disp !== null &&
                      Memory.write(op_ptr + 24, mem.out_disp, 'i32');
                    mem.disp !== undefined &&
                      mem.disp !== null &&
                      Memory.write(op_ptr + 28, mem.disp, 'short');
                    mem.scale !== undefined &&
                      mem.scale !== null &&
                      Memory.write(op_ptr + 30, mem.scale, 'ubyte');
                    mem.bitfield !== undefined &&
                      mem.bitfield !== null &&
                      Memory.write(op_ptr + 31, mem.bitfield, 'ubyte');
                    mem.width !== undefined &&
                      mem.width !== null &&
                      Memory.write(op_ptr + 32, mem.width, 'ubyte');
                    mem.offset !== undefined &&
                      mem.offset !== null &&
                      Memory.write(op_ptr + 33, mem.offset, 'ubyte');
                    mem.index_size !== undefined &&
                      mem.index_size !== null &&
                      Memory.write(op_ptr + 34, mem.index_size, 'ubyte');
                    break;
                }
              }
              break;
            case ARCH_TMS320C64X:
              arch = insn.detail.tms320c64x;
              arch.op_count !== undefined &&
                arch.op_count !== null &&
                Memory.write(arch_info_ptr + 0, arch.op_count, 'ubyte');
              for (let i = 0; i < (arch.op_count || 0); i++) {
                op_ptr = arch_info_ptr + 4 + i * 32;
                op = arch.operands[i];
                op.type !== undefined &&
                  op.type !== null &&
                  Memory.write(op_ptr, op.type, 'i32');
                switch (arch.operands[i].type || 0) {
                  case TMS320C64X.OP_REG:
                    op.reg !== undefined &&
                      op.reg !== null &&
                      Memory.write(op_ptr + 4, op.reg, 'i32');
                    break;
                  case TMS320C64X.OP_IMM:
                    op.imm !== undefined &&
                      op.imm !== null &&
                      Memory.write(op_ptr + 4, op.imm, 'i32');
                    break;
                  case TMS320C64X.OP_MEM:
                    op.mem.base !== undefined &&
                      op.mem.base !== null &&
                      Memory.write(op_ptr + 4, op.mem.base, 'u32');
                    op.mem.disp !== undefined &&
                      op.mem.disp !== null &&
                      Memory.write(op_ptr + 8, op.mem.disp, 'i32');
                    op.mem.unit !== undefined &&
                      op.mem.unit !== null &&
                      Memory.write(op_ptr + 12, op.mem.unit, 'i32');
                    op.mem.scaled !== undefined &&
                      op.mem.scaled !== null &&
                      Memory.write(op_ptr + 16, op.mem.scaled, 'i32');
                    op.mem.disptype !== undefined &&
                      op.mem.disptype !== null &&
                      Memory.write(op_ptr + 20, op.mem.disptype, 'i32');
                    op.mem.direction !== undefined &&
                      op.mem.direction !== null &&
                      Memory.write(op_ptr + 24, op.mem.direction, 'i32');
                    op.mem.modify !== undefined &&
                      op.mem.modify !== null &&
                      Memory.write(op_ptr + 28, op.mem.modify, 'i32');
                    break;
                  case TMS320C64X.OP_REGPAIR:
                    op.reg !== undefined &&
                      op.reg !== null &&
                      Memory.write(op_ptr + 4, op.reg, 'u32');
                    break;
                }
              }
              break;
            case ARCH_M680X:
              arch = insn.detail.m680x;
              arch.op_count !== undefined &&
                arch.op_count !== null &&
                Memory.write(arch_info_ptr + 1, arch.op_count, 'ubyte');
              for (let i = 0; i < (arch.op_count || 0); i++) {
                op_ptr = arch_info_ptr + 4 + i * 24;
                op = arch.operands[i];
                op.type !== undefined &&
                  op.type !== null &&
                  Memory.write(op_ptr, op.type, 'i32');
                switch (arch.operands[i].type || 0) {
                  case M680X.OP_IMMEDIATE:
                    op.imm !== undefined &&
                      op.imm !== null &&
                      Memory.write(op_ptr + 4, op.imm, 'i32');
                    break;
                  case M680X.OP_REGISTER:
                    op.reg !== undefined &&
                      op.reg !== null &&
                      Memory.write(op_ptr + 4, op.reg, 'i32');
                    break;
                  case M680X.OP_INDEXED:
                    op.idx.base_reg !== undefined &&
                      op.idx.base_reg !== null &&
                      Memory.write(op_ptr + 4, op.idx.base_reg, 'i32');
                    op.idx.offset_reg !== undefined &&
                      op.idx.offset_reg !== null &&
                      Memory.write(op_ptr + 8, op.idx.offset_reg, 'i32');
                    op.idx.offset !== undefined &&
                      op.idx.offset !== null &&
                      Memory.write(op_ptr + 12, op.idx.offset, 'short');
                    op.idx.offset_addr !== undefined &&
                      op.idx.offset_addr !== null &&
                      Memory.write(op_ptr + 14, op.idx.offset_addr, 'ushort');
                    op.idx.offset_bits !== undefined &&
                      op.idx.offset_bits !== null &&
                      Memory.write(op_ptr + 16, op.idx.offset_bits, 'ubyte');
                    op.idx.inc_dec !== undefined &&
                      op.idx.inc_dec !== null &&
                      Memory.write(op_ptr + 17, op.idx.inc_dec, 'byte');
                    op.idx.flags !== undefined &&
                      op.idx.flags !== null &&
                      Memory.write(op_ptr + 18, op.idx.flags, 'ubyte');
                    break;
                  case M680X.OP_RELATIVE:
                    op.rel.address !== undefined &&
                      op.rel.address !== null &&
                      Memory.write(op_ptr + 4, op.rel.address, 'ushort');
                    op.rel.offset !== undefined &&
                      op.rel.offset !== null &&
                      Memory.write(op_ptr + 6, op.rel.offset, 'short');
                    break;
                  case M680X.OP_EXTENDED:
                    op.ext.address !== undefined &&
                      op.ext.address !== null &&
                      Memory.write(op_ptr + 4, op.ext.address, 'ushort');
                    op.ext.indirect !== undefined &&
                      op.ext.indirect !== null &&
                      Memory.write(op_ptr + 6, op.ext.indirect, 'bool');
                    break;
                  case M680X.OP_DIRECT:
                    op.direct_addr !== undefined &&
                      op.direct_addr !== null &&
                      Memory.write(op_ptr + 4, op.direct_addr, 'ubyte');
                    break;
                  case M680X.OP_CONSTANT:
                    op.const_val !== undefined &&
                      op.const_val !== null &&
                      Memory.write(op_ptr + 4, op.const_val, 'ubyte');
                    break;
                }
              }
              break;
            case ARCH_EVM:
              arch = insn.detail.evm;
              break;
            case ARCH_MOS65XX:
              arch = insn.detail.mos65xx;
              arch.op_count !== undefined &&
                arch.op_count !== null &&
                Memory.write(arch_info_ptr + 5, arch.op_count, 'ubyte');
              for (let i = 0; i < (arch.op_count || 0); i++) {
                op_ptr = arch_info_ptr + 8 + i * 8;
                op = arch.operands[i];
                op.type !== undefined &&
                  op.type !== null &&
                  Memory.write(op_ptr, op.type, 'i32');
                switch (arch.operands[i].type || 0) {
                  case MOS65XX.OP_REG:
                    op.reg !== undefined &&
                      op.reg !== null &&
                      Memory.write(op_ptr + 4, op.reg, 'i32');
                    break;
                  case MOS65XX.OP_IMM:
                    op.imm !== undefined &&
                      op.imm !== null &&
                      Memory.write(op_ptr + 4, op.imm, 'i32');
                    break;
                  case MOS65XX.OP_MEM:
                    op.mem !== undefined &&
                      op.mem !== null &&
                      Memory.write(op_ptr + 4, op.mem, 'i32');
                    break;
                }
              }
              break;
            case ARCH_WASM:
              arch = insn.detail.wasm;
              arch.op_count !== undefined &&
                arch.op_count !== null &&
                Memory.write(arch_info_ptr + 0, arch.op_count, 'ubyte');
              for (let i = 0; i < (arch.op_count || 0); i++) {
                op_ptr = arch_info_ptr + 8 + i * 32;
                op = arch.operands[i];
                op.type !== undefined &&
                  op.type !== null &&
                  Memory.write(op_ptr, op.type, 'i32');
                switch (arch.operands[i].type || 0) {
                  case WASM.OP_INT7:
                    op.int7 !== undefined &&
                      op.int7 !== null &&
                      Memory.write(op_ptr + 8, op.int7, 'ubyte');
                    break;
                  case WASM.OP_VARUINT32:
                    op.varuint32 !== undefined &&
                      op.varuint32 !== null &&
                      Memory.write(op_ptr + 8, op.varuint32, 'u32');
                    break;
                  case WASM.OP_VARUINT64:
                    op.varuint64 !== undefined &&
                      op.varuint64 !== null &&
                      Memory.write(op_ptr + 8, op.varuint64, 'u64');
                    break;
                  case WASM.OP_UINT32:
                    op.uint32 !== undefined &&
                      op.uint32 !== null &&
                      Memory.write(op_ptr + 8, op.uint32, 'u32');
                    break;
                  case WASM.OP_UINT64:
                    op.uint64 !== undefined &&
                      op.uint64 !== null &&
                      Memory.write(op_ptr + 8, op.uint64, 'u32');
                    break;
                  case WASM.OP_IMM:
                    for (let i = 0; i < 2; i++) {
                      op.immediate[i] !== undefined &&
                        op.immediate[i] !== null &&
                        Memory.write(op_ptr + 8 + i, op.immediate[i], 'u32');
                    }
                    break;
                  case WASM.OP_BRTABLE:
                    op.brtable.length !== undefined &&
                      op.brtable.length !== null &&
                      Memory.write(op_ptr + 8, op.brtable.length, 'u32');
                    op.brtable.address !== undefined &&
                      op.brtable.address !== null &&
                      Memory.write(op_ptr + 12, op.brtable.address, 'u64');
                    op.brtable.default_target !== undefined &&
                      op.brtable.default_target !== null &&
                      Memory.write(
                        op_ptr + 20,
                        op.brtable.default_target,
                        'u32',
                      );
                    break;
                }
              }
              break;
            case ARCH_BPF:
              arch = insn.detail.bpf;
              arch.op_count !== undefined &&
                arch.op_count !== null &&
                Memory.write(arch_info_ptr + 0, arch.op_count, 'ubyte');
              for (let i = 0; i < (arch.op_count || 0); i++) {
                op_ptr = arch_info_ptr + 8 + i * 24;
                op = arch.operands[i];
                op.type !== undefined &&
                  op.type !== null &&
                  Memory.write(op_ptr, op.type, 'i32');
                switch (arch.operands[i].type || 0) {
                  case BPF.OP_REG:
                    op.reg !== undefined &&
                      op.reg !== null &&
                      Memory.write(op_ptr + 8, op.reg, 'i32');
                    break;
                  case BPF.OP_IMM:
                    op.imm !== undefined &&
                      op.imm !== null &&
                      Memory.write(op_ptr + 8, op.imm, 'long');
                    break;
                  case BPF.OP_OFF:
                    op.off !== undefined &&
                      op.off !== null &&
                      Memory.write(op_ptr + 8, op.off, 'u32');
                    break;
                  case BPF.OP_MEM:
                    op.mem.base !== undefined &&
                      op.mem.base !== null &&
                      Memory.write(op_ptr + 8, op.mem.base, 'i32');
                    op.mem.disp !== undefined &&
                      op.mem.disp !== null &&
                      Memory.write(op_ptr + 12, op.mem.disp, 'u32');
                    break;
                  case BPF.OP_MMEM:
                    op.mmem !== undefined &&
                      op.mmem !== null &&
                      Memory.write(op_ptr + 8, op.mmem, 'u32');
                    break;
                  case BPF.OP_MSH:
                    op.msh !== undefined &&
                      op.msh !== null &&
                      Memory.write(op_ptr + 8, op.msh, 'u32');
                    break;
                  case BPF.OP_EXT:
                    op.ext !== undefined &&
                      op.ext !== null &&
                      Memory.write(op_ptr + 8, op.ext, 'u32');
                    break;
                }
              }
              break;
            case ARCH_RISCV:
              arch = insn.detail.riscv;
              arch.op_count !== undefined &&
                arch.op_count !== null &&
                Memory.write(arch_info_ptr + 1, arch.op_count, 'ubyte');
              for (let i = 0; i < (arch.op_count || 0); i++) {
                op_ptr = arch_info_ptr + 8 + i * 24;
                op = arch.operands[i];
                op.type !== undefined &&
                  op.type !== null &&
                  Memory.write(op_ptr, op.type, 'i32');
                switch (arch.operands[i].type || 0) {
                  case RISCV.OP_REG:
                    op.reg !== undefined &&
                      op.reg !== null &&
                      Memory.write(op_ptr + 8, op.reg, 'u32');
                    break;
                  case RISCV.OP_IMM:
                    op.imm !== undefined &&
                      op.imm !== null &&
                      Memory.write(op_ptr + 8, op.imm, 'i32');
                    break;
                  case RISCV.OP_MEM:
                    op.mem.base !== undefined &&
                      op.mem.base !== null &&
                      Memory.write(op_ptr + 8, op.mem.base, 'u32');
                    op.mem.disp !== undefined &&
                      op.mem.disp !== null &&
                      Memory.write(op_ptr + 12, op.mem.disp, 'i64');
                    break;
                }
              }
              break;
            case ARCH_SH:
              arch = insn.detail.sh;
              arch.op_count !== undefined &&
                arch.op_count !== null &&
                Memory.write(arch_info_ptr + 5, arch.op_count, 'ubyte');
              for (let i = 0; i < (arch.op_count || 0); i++) {
                op_ptr = arch_info_ptr + 8 + i * 58;
                op = arch.operands[i];
                op.type !== undefined &&
                  op.type !== null &&
                  Memory.write(op_ptr, op.type, 'i32');
                switch (arch.operands[i].type || 0) {
                  case SH.OP_REG:
                    op.reg !== undefined &&
                      op.reg !== null &&
                      Memory.write(op_ptr + 8, op.reg, 'i32');
                    break;
                  case SH.OP_IMM:
                    op.imm !== undefined &&
                      op.imm !== null &&
                      Memory.write(op_ptr + 8, op.imm, 'long');
                    break;
                  case SH.OP_MEM:
                    op.mem.address !== undefined &&
                      op.mem.address !== null &&
                      Memory.write(op_ptr + 8, op.mem.address, 'i32');
                    op.mem.reg !== undefined &&
                      op.mem.reg !== null &&
                      Memory.write(op_ptr + 12, op.mem.reg, 'i32');
                    op.mem.disp !== undefined &&
                      op.mem.disp !== null &&
                      Memory.write(op_ptr + 16, op.mem.disp, 'i32');
                    break;
                }
              }
              break;
            case ARCH_TRICORE:
              arch = insn.detail.tricore;
              arch.op_count !== undefined &&
                arch.op_count !== null &&
                Memory.write(arch_info_ptr + 0, arch.op_count, 'ubyte');
              for (let i = 0; i < (arch.op_count || 0); i++) {
                op_ptr = arch_info_ptr + 4 + i * 16;
                op = arch.operands[i];
                op.type !== undefined &&
                  op.type !== null &&
                  Memory.write(op_ptr, op.type, 'i32');
                switch (arch.operands[i].type || 0) {
                  case TRICORE.OP_REG:
                    op.reg !== undefined &&
                      op.reg !== null &&
                      Memory.write(op_ptr + 4, op.reg, 'u32');
                    break;
                  case TRICORE.OP_IMM:
                    op.imm !== undefined &&
                      op.imm !== null &&
                      Memory.write(op_ptr + 4, op.imm, 'i32');
                    break;
                  case TRICORE.OP_MEM:
                    op.mem.base !== undefined &&
                      op.mem.base !== null &&
                      Memory.write(op_ptr + 4, op.mem.base, 'ubyte');
                    op.mem.disp !== undefined &&
                      op.mem.disp !== null &&
                      Memory.write(op_ptr + 8, op.mem.disp, 'i32');
                    break;
                }
              }
              break;
          }
        }
      }
      return insns_ptr;
    }

    /**
     * Retrieves the detail information of a disassembled instruction from the cs_detail struct.
     *
     * @private
     * @param pointer - The pointer to the detail information.
     * @returns The detail information of the disassembled instruction.
     */
    private get_detail(pointer: pointer_t<cs_detail>): cs_detail {
      const detail: cs_detail = {} as cs_detail;
      const arch_info_ptr: pointer_t<any> = pointer + 96;
      const regs_read_count: number = Memory.read(pointer + 40, 'ubyte');
      const regs_write_count: number = Memory.read(pointer + 82, 'ubyte');
      const groups_count: number = Memory.read(pointer + 91, 'ubyte');

      detail.regs_write = [];
      detail.groups = [];
      detail.regs_read = [];
      detail.regs_read_count = regs_read_count;
      detail.regs_write_count = regs_write_count;
      detail.groups_count = groups_count;
      detail.writeback = Memory.read(pointer + 92, 'bool');

      for (let i = 0; i < regs_read_count; i++) {
        detail.regs_read[i] = Memory.read(pointer + 0 + i, 'ushort');
      }

      for (let i = 0; i < regs_write_count; i++) {
        detail.regs_write[i] = Memory.read(pointer + 42 + i, 'ushort');
      }

      for (let i = 0; i < groups_count; i++) {
        detail.groups[i] = Memory.read(pointer + 83 + i, 'ubyte');
      }

      detail[this.arch_info.name] = new this.arch_info.instance(
        arch_info_ptr,
        Memory,
      );

      return detail;
    }

    /**
     * Set an option for the Capstone disassembly engine.
     *
     * @public
     * @param option - The option type to set.
     * @param value - The value to set for the option.
     */
    public option(
      option: cs_opt_type,
      value: cs_opt_value | boolean | cs_opt_mnem | cs_opt_skipdata,
    ): void {
      const handle: csh = Memory.read(this.handle_ptr, '*');

      if (!handle) {
        return;
      }

      let opt_val: any = 0;

      if (option === OPT_MNEMONIC) {
        if (
          typeof value !== 'object' ||
          value === undefined ||
          value === null ||
          ((value as cs_opt_mnem).id === undefined &&
            (value as cs_opt_mnem).mnemonic === undefined) ||
          ((value as cs_opt_mnem).id !== undefined &&
            typeof (value as cs_opt_mnem).id !== 'number') ||
          ((value as cs_opt_mnem).mnemonic !== undefined &&
            typeof (value as cs_opt_mnem).mnemonic !== 'string')
        ) {
          throw new Error(
            'When using CS.OPT_MNEMONIC, the value parameter needs to be an object with the following properties,: { id: number, mnemonic: string | null }',
          );
        }

        let str_ptr;
        const mnemonic_len = (value as cs_opt_mnem).mnemonic.length;
        if ((value as cs_opt_mnem).mnemonic) {
          str_ptr = Memory.malloc(mnemonic_len + 1);
          for (let i = 0; i < (value as cs_opt_mnem).mnemonic.length; i++) {
            Memory.write(
              str_ptr + i,
              (value as cs_opt_mnem).mnemonic.charCodeAt(i),
              'i8',
            );
          }
          Memory.write(str_ptr + mnemonic_len, 0, 'i8');
        } else {
          str_ptr = Memory.malloc(1);
          Memory.write(str_ptr, 0, 'i8');
        }
        const obj_ptr = Memory.malloc(8);
        Memory.write(obj_ptr, (value as cs_opt_mnem).id, 'i32');
        Memory.write(obj_ptr + 4, str_ptr, 'i32');

        opt_val = obj_ptr;
      } else if (option === OPT_SKIPDATA_SETUP) {
        if (typeof value != 'object')
          throw new Error(
            'When using CS.OPT_SKIPDATA_SETUP, the value parameter needs to be an object with the following properties,: { mnemonic: string | null, callback: cs_skipdata_cb_t | null, user_data: object }',
          );
        // TODO opt_val = this.skipdata_cb(value)
        return;
      } else if (option === OPT_BUFFER) {
        this.opt_buffer =
          typeof value === 'boolean' ? value : value === OPT_ON ? true : false;
        return;
      } else {
        opt_val =
          typeof value === 'boolean' ? (value ? OPT_ON : OPT_OFF) : value;
      }

      const ret: cs_err = Wrapper.ccall(
        'cs_option',
        'number',
        ['pointer', 'number', 'number'],
        [handle, option, opt_val],
      );

      if (ret !== ERR_OK) {
        const error = `capstone: Function cs_option failed with code ${ret}:\n${this.strerror(
          ret,
        )}`;
        throw new Error(error);
      }

      if (option === OPT_MNEMONIC && opt_val !== 0) {
        Memory.free(Memory.read(opt_val, '*'));
        Memory.free(opt_val);
      }
    }

    /**
     * Create the capstone instance handle
     *
     * @private
     */
    private open(): void {
      this.handle_ptr = Memory.malloc(4);
      const ret: cs_err = Wrapper.ccall(
        'cs_open',
        'number',
        ['number', 'number', 'number'],
        [this.arch, this.mode, this.handle_ptr],
      );
      if (ret != ERR_OK) {
        Memory.write(this.handle_ptr, 0, '*');
        const error =
          'capstone: Function cs_open failed with code ' +
          ret +
          ':\n' +
          this.strerror(ret);
        throw new Error(error);
      }
    }

    /**
     * Free the capstone instance handle and cleanup resources
     *
     * @public
     */
    public close(): void {
      const ret: cs_err = Wrapper.ccall(
        'cs_close',
        'number',
        ['pointer'],
        [this.handle_ptr],
      );
      if (ret != ERR_OK) {
        const error =
          'capstone: Function cs_close failed with code ' +
          ret +
          ':\n' +
          this.strerror(ret);
        throw new Error(error);
      }

      Memory.allocations.delete(this.handle_ptr);

      if (Memory.allocations.size !== 0) Memory.free(Memory.allocations);
    }

    /**
     * Disassemble binary data.
     *
     * @public
     * @param buffer - The binary data to disassemble, as a Buffer, array, or Uint8Array.
     * @param addr - The starting address of the binary data.
     * @param [max_len] - (Optional) The maximum number of instructions to disassemble.
     * @returns An array of disassembled instructions.
     */
    public disasm(
      buffer: Buffer | number[] | Uint8Array,
      addr: number,
      max_len?: number,
    ): cs_insn[] {
      const handle: csh = Memory.read(this.handle_ptr, 'i32');
      const buffer_len: number = buffer.length;
      const buffer_ptr: pointer_t<Buffer | number[] | Uint8Array> =
        Memory.malloc(buffer_len);
      const insn_ptr: pointer_t<pointer_t<cs_insn>> = Memory.malloc(4);

      Wrapper.writeArrayToMemory(buffer, buffer_ptr);

      const insn_count: number = Wrapper.ccall(
        'cs_disasm',
        'number',
        ['number', 'number', 'number', 'number', 'number', 'number'],
        [handle, buffer_ptr, buffer_len, addr, 0, max_len || 0, insn_ptr],
      );

      if (insn_count > 0) {
        const insn_arr_ptr: pointer_t<cs_insn[]> = Memory.read(insn_ptr, 'i32');
        const instructions: cs_insn[] = [];

        for (let i = 0; i < insn_count; i++) {
          const insnOffset: pointer_t<cs_insn> = insn_arr_ptr + i * INSN_SIZE;
          const insn: cs_insn = this.deref(insnOffset);
          instructions.push(insn);
        }
        Memory.free([insn_ptr, buffer_ptr]);
        return instructions;
      } else {
        Memory.free([insn_ptr, buffer_ptr]);

        const code: cs_err = this.errno(handle);
        const error: string =
          'capstone: Function cs_disasm failed with code ' +
          code +
          ':\n' +
          this.strerror(code);
        throw new Error(error);
      }
    }

    /**
     * Perform iterative disassembly on binary data.
     *
     * @public
     * @param data - An object containing the binary data to disassemble, the starting address, and the previous instruction.
     * @param data.buffer - The binary data to disassemble, as a Buffer, array, or Uint8Array.
     * @param data.address - the address of the current instruction
     * @param data.insn - the previous iterations instructions or {} on iteration 0
     * @returns A boolean indicating whether another instruction was successfully disassembled.
     */
    public disasm_iter(data: {
      buffer: Buffer | number[] | Uint8Array;
      addr: number;
      insn: {} | cs_insn | null;
    }): boolean {
      const { buffer, addr } = data;
      const handle: csh = Memory.read(this.handle_ptr, 'i32');
      const buffer_len: number = buffer.length;
      const code_mem: pointer_t<Buffer | number[] | Uint8Array> = Memory.malloc(
        buffer.length,
      );
      const cast_ptr: pointer_t<any> = Memory.malloc(24);
      const code_ptr: pointer_t<pointer_t<Buffer | number[] | Uint8Array>> =
        cast_ptr;
      const size_ptr: pointer_t<number> = cast_ptr + 8;
      const addr_ptr: pointer_t<number> = cast_ptr + 16;
      const insn_ptr: pointer_t<cs_insn> = Wrapper._cs_malloc(handle);

      Memory.write(addr_ptr, addr, 'i64');
      Memory.write(size_ptr, buffer_len, 'i32');
      Wrapper.writeArrayToMemory(buffer, code_mem);
      Memory.write(code_ptr, code_mem, 'i32');

      const ret: boolean = Wrapper.ccall(
        'cs_disasm_iter',
        'boolean',
        ['number', 'number', 'number', 'number', 'pointer'],
        [handle, code_ptr, size_ptr, addr_ptr, insn_ptr],
      );

      if (ret) {
        const new_addr: number = Memory.read(addr_ptr, 'i64');
        const new_size: number = Memory.read(size_ptr, 'i16');
        const new_bytes = [];
        for (let j = 0; j < new_size; j++) {
          const byte = Memory.read(Memory.read(code_ptr, 'i32') + j, 'u8');
          new_bytes.push(byte);
        }

        const insn: cs_insn = this.deref(insn_ptr);

        data.buffer = new Uint8Array(new_bytes);
        data.addr = new_addr;
        data.insn = insn;
      }
      Memory.free(code_mem);
      Memory.free(cast_ptr);
      Wrapper._cs_free(insn_ptr, 1);

      return ret;
    }

    /**
     * Retrieve information about registers accessed by an instruction.
     *
     * @public
     * @param insn - The instruction to analyze.
     * @returns An object containing arrays of registers read and written by the instruction.
     */
    public regs_access(insn: cs_insn): {
      regs_read: cs_regs;
      regs_read_count: number;
      regs_write: cs_regs;
      regs_write_count: number;
    } {
      if (!insn.detail)
        throw new Error(
          'capstone: In order to use regs_access() you need to have CS.OPT_DETAIL on',
        );
      const handle: csh = Memory.read(this.handle_ptr, 'i32');
      const insn_pointer: pointer_t<cs_insn> = this.ref(insn);
      const regs_read_ptr: pointer_t<cs_regs> = Memory.malloc(64 * 2);
      const regs_read_count_ptr: pointer_t<number> = Memory.malloc(1);
      const regs_write_ptr: pointer_t<cs_regs> = Memory.malloc(64 * 2);
      const regs_write_count_ptr: pointer_t<number> = Memory.malloc(1);

      const ret: cs_err = Wrapper._cs_regs_access(
        handle,
        insn_pointer,
        regs_read_ptr,
        regs_read_count_ptr,
        regs_write_ptr,
        regs_write_count_ptr,
      );
      if (ret != ERR_OK) {
        Memory.write(this.handle_ptr, 0, '*');
        const error = `capstone: Function regs_access failed with code ${ret}:\n${this.strerror(
          ret,
        )}`;
        throw new Error(error);
      }
      const regs_read: cs_regs = [];
      const regs_read_count: number = Memory.read(regs_read_count_ptr, 'i8');
      const regs_write: cs_regs = [];
      const regs_write_count: number = Memory.read(regs_write_count_ptr, 'i8');

      for (let i = 0; i < regs_read_count; i++) {
        const reg: number = Memory.read(regs_read_ptr + i, 'i16');
        regs_read.push(reg);
      }
      for (let i = 0; i < regs_write_count; i++) {
        const reg: number = Memory.read(regs_write_ptr + i, 'i16');
        regs_write.push(reg);
      }
      Memory.free(insn_pointer);
      Memory.free(regs_read_ptr);
      Memory.free(regs_read_count_ptr);
      Memory.free(regs_write_ptr);
      Memory.free(regs_write_count_ptr);
      return {
        regs_read,
        regs_read_count,
        regs_write,
        regs_write_count,
      };
    }

    /**
     * Get the number of operands of a specific type for an instruction.
     *
     * @public
     * @param insn - The instruction to analyze.
     * @param op_type - The type of operand to count.
     * @returns The number of operands of the specified type for the instruction.
     */
    public op_count(insn: cs_insn, op_type: number): number {
      if (!insn.detail)
        throw new Error(
          'capstone: In order to use op_count() you need to have CS.OPT_DETAIL on',
        );
      const handle: csh = Memory.read(this.handle_ptr, 'i32');
      const pointer: pointer_t<cs_insn> = this.ref(insn);
      const operand_count: number = Wrapper._cs_op_count(
        handle,
        pointer,
        op_type,
      );
      Memory.free(pointer);
      return operand_count;
    }

    /**
     * Get the index of a specific operand of a specific type at a given position for an instruction.
     *
     * @public
     * @param insn - The instruction to analyze.
     * @param op_type - The type of operand to search for.
     * @param position - The position of the operand to find (zero-based).
     * @returns The index of the operand within the instruction's operand list, or -1 if not found.
     */
    public op_index(insn: cs_insn, op_type: number, position: number): number {
      if (!insn.detail)
        throw new Error(
          'capstone: In order to use op_index() you need to have CS.OPT_DETAIL on',
        );
      const handle: csh = Memory.read(this.handle_ptr, 'i32');
      const pointer: pointer_t<cs_insn> = this.ref(insn);
      const index: number = Wrapper._cs_op_index(
        handle,
        pointer,
        op_type,
        position,
      );
      Memory.free(pointer);
      return index;
    }

    /**
     * Check if an instruction belongs to a specific group.
     *
     * @public
     * @param insn - The instruction to check.
     * @param group_id - The ID of the group to check against.
     * @returns A boolean indicating whether the instruction belongs to the specified group.
     */
    public insn_group(insn: cs_insn, group_id: number): boolean {
      if (!insn.detail)
        throw new Error(
          'capstone: In order to use insn_group() you need to have CS.OPT_DETAIL on',
        );
      const handle: csh = Memory.read(this.handle_ptr, 'i32');
      const pointer: pointer_t<cs_insn> = this.ref(insn);

      const valid_group: boolean = Boolean(
        Wrapper._cs_insn_group(handle, pointer, group_id),
      );
      Memory.free(pointer);
      return valid_group;
    }

    /**
     * Retrieves the registers read by an instruction.
     *
     * @public
     * @param insn - The instruction to analyze.
     * @param reg_id - The register to look for.
     * @returns A boolean indicating whether the instruction reads a specific register.
     */
    public reg_read(insn: cs_insn, reg_id: number): boolean {
      if (!insn.detail)
        throw new Error(
          'capstone: In order to use reg_read() you need to have CS.OPT_DETAIL on',
        );
      const handle: csh = Memory.read(this.handle_ptr, 'i32');
      const pointer: pointer_t<cs_insn> = this.ref(insn);

      const valid_reg: boolean = Boolean(
        Wrapper._cs_reg_read(handle, pointer, reg_id),
      );
      Memory.free(pointer);
      return valid_reg;
    }

    /**
     * Retrieves the registers written to by an instruction.
     *
     * @public
     * @param insn - The instruction to analyze.
     * @param reg_id - The register to look for.
     * @returns A boolean indicating whether the instruction writes to a specific register.
     */
    public reg_write(insn: cs_insn, reg_id: number): boolean {
      if (!insn.detail)
        throw new Error(
          'capstone: In order to use reg_write() you need to have CS.OPT_DETAIL on',
        );
      const handle: csh = Memory.read(this.handle_ptr, 'i32');
      const pointer: pointer_t<cs_insn> = this.ref(insn);

      const valid_reg: boolean = Boolean(
        Wrapper._cs_reg_write(handle, pointer, reg_id),
      );
      Memory.free(pointer);
      return valid_reg;
    }

    /**
     * Retrieves the name of the instruction group to which an instruction belongs.
     *
     * @public
     * @param insn - The instruction to analyze.
     * @returns The name of the instruction group.
     */
    public group_name(group_id: number): string {
      const handle: csh = Memory.read(this.handle_ptr, '*');
      const ret: string = Wrapper.ccall(
        'cs_group_name',
        'string',
        ['pointer', 'number'],
        [handle, group_id],
      );
      return ret;
    }

    /**
     * Retrieves the name of a register referenced by an operand in an instruction.
     *
     * @public
     * @param reg_id - The register to look for.
     * @returns The name of the register referenced by the operand.
     */
    public reg_name(reg_id: number): string {
      const handle: csh = Memory.read(this.handle_ptr, '*');
      const ret: string = Wrapper.ccall(
        'cs_reg_name',
        'string',
        ['pointer', 'number'],
        [handle, reg_id],
      );
      return ret;
    }

    /**
     * Retrieves the name of the instruction mnemonic.
     *
     * @public
     * @param insn_id - The instruction id to look for.
     * @returns The mnemonic of the instruction.
     */
    public insn_name(insn_id: number): string {
      const handle: csh = Memory.read(this.handle_ptr, '*');
      const ret: string = Wrapper.ccall(
        'cs_insn_name',
        'string',
        ['pointer', 'number'],
        [handle, insn_id],
      );
      return ret;
    }

    /**
     * Formats the given instructions to a printable string.
     *
     * @public
     * @param instructions - The instruction or array of instructions to format.
     * @param [options={hex_comment: true, colors: false, ASCII: false, address: true, bytes: true}] - Formatting options.
     * @returns The formatted string
     */
    public fmt(
      instructions: cs_insn | cs_insn[],
      options: cs_opt_fmt = {
        hex_comment: true,
        colors: false,
        ASCII: false,
        address: true,
        bytes: true,
      },
    ): string {
      if (!Array.isArray(instructions)) instructions = [instructions];

      const {
        hex_comment = true,
        colors = false,
        ASCII = false,
        address = true,
        bytes = true,
      } = options;
      const insn_count = instructions.length;

      const format_bytes = (insn_bytes: Uint8Array | number[]): string => {
        if (!bytes) return '';
        const byte_str = [];
        for (let j = 0; j < insn_bytes.length; j++) {
          byte_str.push(
            ((insn_bytes[j] >> 4) & 0xf).toString(16) + // upper nibble
              (insn_bytes[j] & 0xf).toString(16), // lower nibble
          );
        }
        return byte_str.join(' ').padEnd(24);
      };

      const format_ascii = (insn_bytes: Uint8Array | number[]): string => {
        if (!ASCII) return '';
        const ascii_str = [];
        for (let j = 0; j < insn_bytes.length; j++) {
          const byte = insn_bytes[j];
          ascii_str.push(
            (byte - 32) >>> 31 === 0 && (126 - byte) >>> 31 === 0
              ? String.fromCharCode(byte)
              : '.',
          );
        }
        return ascii_str.join('').padEnd(10);
      };

      const format_operands = (op_str: string): string => {
        const match = /#(0x(?:-)?\d+)/.exec(op_str);
        if (match && match[1]) {
          op_str += `${colors ? '\x1b[90m' : ''}\t// ${parseInt(match[1])}${
            colors ? '\x1b[0m' : ''
          }`;
        }

        if (!colors) return op_str;
        op_str.replace(
          /#(?:0x(?:-)?[a-fA-f0-9]+|\d+)/g,
          function (match: string): string {
            return '\x1b[34m' + match + '\x1b[0m';
          },
        );
        return op_str;
      };

      let fmt_output = '';

      for (let i = 0; i < insn_count; i++) {
        const insn = instructions[i];
        const {
          mnemonic = '',
          op_str: operands = '',
          address: insn_address,
          bytes: insn_bytes,
        } = insn;

        if (address && !isNaN(insn_address)) {
          fmt_output += `0x${insn_address.toString(16)}:\t`;
        }

        fmt_output += `${format_bytes(insn_bytes)}${format_ascii(insn_bytes)}${
          colors ? '\x1b[33m' : ''
        }${mnemonic.padEnd(10)}${colors ? '\x1b[0m' : ''}${format_operands(
          operands,
        ).padEnd(10)}${i + 1 < insn_count ? '\n' : ''}`;
      }

      return fmt_output;
    }
  }
}

export default CS;
export {
  Wrapper,
  ARM64,
  ARM,
  BPF,
  EVM,
  M680X,
  M68K,
  MIPS,
  MOS65XX,
  PPC,
  RISCV,
  SH,
  SPARC,
  TMS320C64X,
  TRICORE,
  WASM,
  X86,
  XCORE,
  type cs_opt_skipdata,
  type cs_opt_mnem,
  type cs_insn,
  type cs_detail,
  type cs_arch,
  type cs_mode,
  type cs_err,
  type cs_opt_type,
  type cs_opt_value,
  type cs_group_type,
  type cs_op_type,
  type cs_ac_type,
  type cs_regs,
  type cs_arm64_op,
  type cs_arm_op,
  type cs_bpf_op,
  type cs_m680x_op,
  type cs_m68k_op,
  type cs_mips_op,
  type cs_mos65xx_op,
  type cs_ppc_op,
  type cs_riscv_op,
  type cs_sh_op,
  type cs_sparc_op,
  type cs_tms320c64x_op,
  type cs_tricore_op,
  type cs_wasm_op,
  type cs_x86_op,
  type cs_xcore_op,
  type cs_opt_fmt,
};
