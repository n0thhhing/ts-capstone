import Module from "./capstone.js";
import * as constants from "./constants.js";

// @ts-ignore
const Wrapper = new Module();
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
type csh = number;
type ptr = number;

namespace cs {
  Object.assign(cs, constants);
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
  export const ARCH_M680X: cs_arch = 10; // 680X architecture;
  export const ARCH_EVM: cs_arch = 11; // Ethereum architecture
  export const ARCH_MAX: cs_arch = 12; // The maximum architecture value.
  export const ARCH_ALL: cs_arch = 0xffff; // Represents a mask that includes all architecture values.

  // Modes
  export const MODE_LITTLE_ENDIAN: cs_mode = 0; // Little-Endian mode (default mode)
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
  export const MODE_MIPSGP64: cs_mode = 1 << 7; // General Purpose Registers are 64-bit wide (MIPS)
  export const MODE_V9: cs_mode = 1 << 4; // SparcV9 mode (Sparc)
  export const MODE_QPX: cs_mode = 1 << 4; // Quad Processing eXtensions mode (PPC)
  export const MODE_M68K_000: cs_mode = 1 << 1; // M68K 68000 mode
  export const MODE_M68K_010: cs_mode = 1 << 2; // M68K 68010 mode
  export const MODE_M68K_020: cs_mode = 1 << 3; // M68K 68020 mode
  export const MODE_M68K_030: cs_mode = 1 << 4; // M68K 68030 mode
  export const MODE_M68K_040: cs_mode = 1 << 5; // M68K 68040 mode
  export const MODE_M68K_060: cs_mode = 1 << 6; // M68K 68060 mode
  export const MODE_BIG_ENDIAN: cs_mode = 1 << 31; // Big-Endian mode
  export const MODE_MIPS32: cs_mode = 1 << 2; // Mips32 ISA (Mips)
  export const MODE_MIPS64: cs_mode = 1 << 3; // Mips64 ISA (Mips)
  export const MODE_M680X_6301: cs_mode = 1 << 1; // M680X Hitachi 6301,6303 mode
  export const MODE_M680X_6309: cs_mode = 1 << 2; // M680X Hitachi 6309 mode
  export const MODE_M680X_6800: cs_mode = 1 << 3; // M680X Hitachi 6800,6802 mode
  export const MODE_M680X_6801: cs_mode = 1 << 4; // M680X Hitachi 6801,6803 mode
  export const MODE_M680X_6805: cs_mode = 1 << 5; // Motorola/Freescale 6805 mode
  export const MODE_M680X_6808: cs_mode = 1 << 6; // Motorola/Freescale/NXP 68HC08 mode
  export const MODE_M680X_6809: cs_mode = 1 << 7; // M680X Motorola 6809 mode
  export const MODE_M680X_6811: cs_mode = 1 << 8; // Motorola/Freescale/NXP 68HC11 mode
  export const MODE_M680X_CPU12: cs_mode = 1 << 9; // Motorola/Freescale/NXP CPU12
  export const MODE_M680X_HCS08: cs_mode = 1 << 10; // M68HC12/HCS12 mode

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

  // Capstone option value
  export const OPT_OFF: cs_opt_value = 0; // Turn OFF an option - default option of CS_OPT_DETAIL
  export const OPT_ON: cs_opt_value = 3; // Turn ON an option (CS_OPT_DETAIL)

  // Capstone syntax value
  export const OPT_SYNTAX_DEFAULT: cs_opt_value = 0; // Default assembly syntax of all platforms (CS_OPT_SYNTAX)
  export const OPT_SYNTAX_INTEL: cs_opt_value = 1; // Intel X86 asm syntax - default syntax on X86 (CS_OPT_SYNTAX, CS_ARCH_X86)
  export const OPT_SYNTAX_ATT: cs_opt_value = 2; // ATT asm syntax (CS_OPT_SYNTAX, CS_ARCH_X86)
  export const OPT_SYNTAX_NOREGNAME: cs_opt_value = 3; // Asm syntax prints register name with only number - (CS_OPT_SYNTAX, CS_ARCH_PPC, CS_ARCH_ARM)
  export const OPT_SYNTAX_MASM: cs_opt_value = 4; // X86 Intel Masm syntax (CS_OPT_SYNTAX).

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
  export const OP_MEM: cs_op_type = 3; // Memory operand.
  export const OP_FP: cs_op_type = 4; // Floating-Point operand.

  // Common instruction operand access types - to be consistent across all architectures. It is possible to combine access types, for example: CS_AC_READ | CS_AC_WRITE
  export const AC_INVALID: cs_ac_type = 0; // Uninitialized/invalid access type.
  export const AC_READ: cs_ac_type = 1 << 0; // Operand read from memory or register.
  export const AC_WRITE: cs_ac_type = 1 << 1; // Operand written to memory or register.

  // query id for cs_support()
  export const SUPPORT_DIET = 0xffff + 1;
  export const SUPPORT_X86_REDUCE = 0xffff + 2;

  // Manifest Constants
  export const CS_MNEMONIC_SIZE = 32;
  export const CS_INSN_SIZE = 232;

  export function version(): string {
    const majorPtr: number = Wrapper._malloc(4);
    const minorPtr: number = Wrapper._malloc(4);
    Wrapper.ccall(
      "cs_version",
      "number",
      ["pointer", "pointer"],
      [majorPtr, minorPtr],
    );
    const major = Wrapper.getValue(majorPtr, "i32");
    const minor = Wrapper.getValue(minorPtr, "i32");
    Wrapper._free(majorPtr);
    Wrapper._free(minorPtr);
    return `${major}.${minor}`;
  }

  export function support(query: number): boolean {
    var ret: boolean = Wrapper.ccall(
      "cs_support",
      "number",
      ["number"],
      [query],
    );
    return Boolean(ret);
  }

  export function strerror(code: number): string {
    return Wrapper.ccall("cs_strerror", "string", ["number"], [code]);
  }

  export function errno(handle: number): cs_err {
    return Wrapper.ccall("cs_errno", "number", ["pointer"], [handle]);
  }

  export class Capstone {
    public arch: cs_arch;
    public mode: cs_mode;
    private handlePtr: ptr;

    constructor(arch: number, mode: number) {
      this.arch = arch;
      this.mode = mode;
      this.handlePtr = 0;
      this.open();
    }

    private setI64(pointer: ptr, value: number): void {
      Wrapper.HEAPU32[(pointer >> 2) + 1] = (value / 4294967296) | 0; // upper
      Wrapper.HEAPU32[pointer >> 2] = value | 0; // lower
    }

    private getI64(pointer: ptr): number {
      return (
        Wrapper.HEAPU32[(pointer >> 2) + 1] * 4294967296 +
        (Wrapper.HEAPU32[pointer >> 2] | 0)
      ); // combine upper and lower 32
    }

    private dereferenceInsn(insnPtr: ptr): cs_insn {
      const insnId: number = Wrapper.getValue(insnPtr, "i32");
      const insnAddr: number = this.getI64(insnPtr + 8);
      const insnSize: number = Wrapper.getValue(insnPtr + 16, "i16");
      const insnMn: string = Wrapper.UTF8ToString(insnPtr + 34);
      const insnOp: string = Wrapper.UTF8ToString(insnPtr + 66);
      const insnBytes = [];

      for (let j = 0; j < insnSize; j++) {
        let byte = Wrapper.getValue(insnPtr + 18 + j, "i8");
        if (byte < 0) {
          byte += 256;
        }
        insnBytes.push(byte);
      }

      const insn: cs_insn = {
        id: insnId,
        address: insnAddr,
        size: insnSize,
        mnemonic: insnMn,
        op_str: insnOp,
        bytes: insnBytes,
      };

      return insn;
    }

    public option(
      option: cs_opt_type,
      value: cs_opt_value | boolean | { id: number; name: string },
    ): void {
      const handle: csh = Wrapper.getValue(this.handlePtr, "*");
      if (typeof value === "boolean") {
        if (value) value = OPT_ON;
        else value = OPT_OFF;
      }
      if (!handle) {
        return;
      }

      let objPtr: ptr = 0;

      if (option === OPT_MNEMONIC) {
        if (
          typeof value !== "object" ||
          value === null ||
          typeof value.id !== "number" ||
          typeof value.name !== "string"
        ) {
          throw new Error(
            "When using cs.OPT_MNEMONIC, the value parameter needs to be an object: { id: number, name: string }",
          );
        }

        const strPtr: ptr = Wrapper._malloc(value.name.length + 1);
        for (let i = 0; i < value.name.length; i++) {
          Wrapper.setValue(strPtr + i, value.name.charCodeAt(i), "i8");
        }
        Wrapper.setValue(strPtr + value.name.length, 0, "i8");

        objPtr = Wrapper._malloc(8);
        Wrapper.setValue(objPtr, value.id, "i32");
        Wrapper.setValue(objPtr + 4, strPtr, "i32");
      }

      const ret: cs_err = Wrapper.ccall(
        "cs_option",
        "number",
        ["pointer", "number", "number"],
        [handle, option, option === OPT_MNEMONIC ? objPtr : value],
      );

      if (ret !== ERR_OK) {
        const error = new Error(
          "capstone: Function cs_option failed with code " +
            ret +
            ":\n" +
            strerror(ret),
        );
        throw error;
      }

      if (objPtr !== 0) {
        Wrapper._free(Wrapper.getValue(objPtr, "*"));
        Wrapper._free(objPtr);
      }
    }

    private open(): void {
      this.handlePtr = Wrapper._malloc(4);
      const ret: cs_err = Wrapper.ccall(
        "cs_open",
        "number",
        ["number", "number", "number"],
        [this.arch, this.mode, this.handlePtr],
      );
      if (ret != ERR_OK) {
        Wrapper.setValue(this.handlePtr, 0, "*");
        const error =
          "capstone: Function cs_open failed with code " +
          ret +
          ":\n" +
          strerror(ret);
        throw error;
      }
    }

    public close(): void {
      const ret: cs_err = Wrapper.ccall(
        "cs_close",
        "number",
        ["pointer"],
        [this.handlePtr],
      );
      if (ret != ERR_OK) {
        const error =
          "capstone: Function cs_close failed with code " +
          ret +
          ":\n" +
          strerror(ret);
        throw error;
      }
      Wrapper._free(this.handlePtr);
    }

    public disasm(
      buffer: Buffer | number[] | Uint8Array,
      addr: number,
      maxLen?: number,
    ): cs_insn[] {
      const handle: csh = Wrapper.getValue(this.handlePtr, "i32");
      const bufferLen: number = buffer.length;
      const bufferPtr: ptr = Wrapper._malloc(bufferLen);
      const insnPtr: ptr = Wrapper._malloc(4);

      Wrapper.writeArrayToMemory(buffer, bufferPtr);

      const insnCount: number = Wrapper.ccall(
        "cs_disasm",
        "number",
        ["number", "number", "number", "number", "number", "number"],
        [handle, bufferPtr, bufferLen, addr, 0, maxLen || 0, insnPtr],
      );

      if (insnCount > 0) {
        const insnArrayPtr: ptr = Wrapper.getValue(insnPtr, "i32");
        const instructions: cs_insn[] = [];

        for (let i = 0; i < insnCount; i++) {
          const insnOffset: ptr = insnArrayPtr + i * CS_INSN_SIZE;
          const insn: cs_insn = this.dereferenceInsn(insnOffset);
          instructions.push(insn);
        }
        return instructions;
      } else {
        Wrapper._free(insnPtr);

        const code: cs_err = cs.errno(handle);
        const error =
          "capstone: Function cs_disasm failed with code " +
          code +
          ":\n" +
          strerror(code);
        throw error;
      }

      this.close();
    }

    public disasm_iter(data: {
      buffer: Buffer | number[] | Uint8Array;
      addr: number;
      insn: {} | cs_insn | null;
    }): boolean {
      const { buffer, addr } = data;
      const handle: csh = Wrapper.getValue(this.handlePtr, "i32");
      const bufferLen: number = buffer.length;
      const codeMem: ptr = Wrapper._malloc(buffer.length);
      const castPtr: ptr = Wrapper._malloc(42);
      const codePtr: ptr = castPtr;
      const sizePtr: ptr = castPtr + 8;
      const addrPtr: ptr = castPtr + 16;
      const insnPtr: ptr = Wrapper._cs_malloc(4);

      Wrapper.setValue(sizePtr, bufferLen, "i32");
      this.setI64(addrPtr, addr);
      Wrapper.writeArrayToMemory(buffer, codeMem);
      Wrapper.setValue(codePtr, codeMem, "i32");

      const ret: boolean = Wrapper.ccall(
        "cs_disasm_iter",
        "boolean",
        ["number", "number", "number", "number", "pointer"],
        [handle, codePtr, sizePtr, addrPtr, insnPtr],
      );

      if (ret) {
        const newAddr: number = this.getI64(addrPtr);
        const newSize: number = Wrapper.getValue(sizePtr, "i16");
        const newBytes = [];
        for (let j = 0; j < newSize; j++) {
          let byte = Wrapper.getValue(
            Wrapper.getValue(codePtr, "i32") + j,
            "i8",
          );
          if (byte < 0) {
            byte += 256;
          }
          newBytes.push(byte);
        }

        const insn: cs_insn = this.dereferenceInsn(insnPtr);

        data.buffer = Buffer.from(newBytes);
        data.addr = newAddr;
        data.insn = insn;
      }
      Wrapper._free(codeMem);
      Wrapper._free(castPtr);
      Wrapper._free(insnPtr);

      return ret;
    }

    public reg_name(reg_id: number): string {
      const handle: csh = Wrapper.getValue(this.handlePtr, "*");
      const ret: string = Wrapper.ccall(
        "cs_reg_name",
        "string",
        ["pointer", "number"],
        [handle, reg_id],
      );
      return ret;
    }

    public insn_name(insn_id: number): string {
      const handle: csh = Wrapper.getValue(this.handlePtr, "*");
      const ret: string = Wrapper.ccall(
        "cs_insn_name",
        "string",
        ["pointer", "number"],
        [handle, insn_id],
      );
      return ret;
    }
  }
}

export default cs;
export { Wrapper };
