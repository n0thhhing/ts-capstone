import Module from "./capstone.js";
import * as constants from "./constants.js";

const Wrapper = new Module();

namespace cs {
  Object.assign(cs, constants);
  // Return codes
  export const ERR_OK = 0; // No error: everything was fine
  export const ERR_MEM = 1; // Out-Of-Memory error: cs_open(), cs_disasm(), cs_disasm_iter()
  export const ERR_ARCH = 2; // Unsupported architecture: cs_open()
  export const ERR_HANDLE = 3; // Invalid handle: cs_op_count(), cs_op_index()
  export const ERR_CSH = 4; // Invalid csh argument: cs_close(), cs_errno(), cs_option()
  export const ERR_MODE = 5; // Invalid/unsupported mode: cs_open()
  export const ERR_OPTION = 6; // Invalid/unsupported option: cs_option()
  export const ERR_DETAIL = 7; // Information is unavailable because detail option is OFF
  export const ERR_MEMSETUP = 8; // Dynamic memory management uninitialized (see OPT_MEM)
  export const ERR_VERSION = 9; // Unsupported version (bindings)
  export const ERR_DIET = 10; // Access irrelevant data in "diet" engine
  export const ERR_SKIPDATA = 11; // Access irrelevant data for "data" instruction in SKIPDATA mode
  export const ERR_X86_ATT = 12; // X86 AT&T syntax is unsupported (opt-out at compile time)
  export const ERR_X86_INTEL = 13; // X86 Intel syntax is unsupported (opt-out at compile time)
  export const ERR_X86_MASM = 14; // X86 Intel syntax is unsupported (opt-out at compile time)

  // Architectures
  export const ARCH_ARM = 0; // ARM architecture (including Thumb, Thumb-2)
  export const ARCH_ARM64 = 1; // ARM-64, also called AArch64
  export const ARCH_AARCH64 = 1; // AArch-64, also called ARM-64
  export const ARCH_MIPS = 2; // Mips architecture
  export const ARCH_X86 = 3; // X86 architecture (including x86 & x86-64)
  export const ARCH_PPC = 4; // PowerPC architecture
  export const ARCH_SPARC = 5; // Sparc architecture
  export const ARCH_SYSZ = 6; // SystemZ architecture
  export const ARCH_XCORE = 7; // XCore architecture
  export const ARCH_M68K = 8; // 68K architecture
  export const ARCH_TMS320C64X = 9; // TMS320C64x architecture
  export const ARCH_M680X = 10; // 680X architecture;
  export const ARCH_EVM = 11; // Ethereum architecture
  export const ARCH_MAX = 12; // The maximum architecture value.
  export const ARCH_ALL = 0xffff; // Represents a mask that includes all architecture values.

  // Modes
  export const MODE_LITTLE_ENDIAN = 0; // Little-Endian mode (default mode)
  export const MODE_ARM = 0; // 32-bit ARM
  export const MODE_16 = 1 << 1; // 16-bit mode (X86)
  export const MODE_32 = 1 << 2; // 32-bit mode (X86)
  export const MODE_64 = 1 << 3; // 64-bit mode (X86, PPC)
  export const MODE_THUMB = 1 << 4; // ARM's Thumb mode, including Thumb-2
  export const MODE_MCLASS = 1 << 5; // ARM's Cortex-M series
  export const MODE_V8 = 1 << 6; // ARMv8 A32 encodings for ARM
  export const MODE_MICRO = 1 << 4; // MicroMips mode (MIPS)
  export const MODE_MIPS3 = 1 << 5; // Mips III ISA
  export const MODE_MIPS32R6 = 1 << 6; // Mips32r6 ISA
  export const MODE_MIPSGP64 = 1 << 7; // General Purpose Registers are 64-bit wide (MIPS)
  export const MODE_V9 = 1 << 4; // SparcV9 mode (Sparc)
  export const MODE_QPX = 1 << 4; // Quad Processing eXtensions mode (PPC)
  export const MODE_M68K_000 = 1 << 1; // M68K 68000 mode
  export const MODE_M68K_010 = 1 << 2; // M68K 68010 mode
  export const MODE_M68K_020 = 1 << 3; // M68K 68020 mode
  export const MODE_M68K_030 = 1 << 4; // M68K 68030 mode
  export const MODE_M68K_040 = 1 << 5; // M68K 68040 mode
  export const MODE_M68K_060 = 1 << 6; // M68K 68060 mode
  export const MODE_BIG_ENDIAN = 1 << 31; // Big-Endian mode
  export const MODE_MIPS32 = 1 << 2; // Mips32 ISA (Mips)
  export const MODE_MIPS64 = 1 << 3; // Mips64 ISA (Mips)
  export const MODE_M680X_6301 = 1 << 1; // M680X Hitachi 6301,6303 mode
  export const MODE_M680X_6309 = 1 << 2; // M680X Hitachi 6309 mode
  export const MODE_M680X_6800 = 1 << 3; // M680X Hitachi 6800,6802 mode
  export const MODE_M680X_6801 = 1 << 4; // M680X Hitachi 6801,6803 mode
  export const MODE_M680X_6805 = 1 << 5; // Motorola/Freescale 6805 mode
  export const MODE_M680X_6808 = 1 << 6; // Motorola/Freescale/NXP 68HC08 mode
  export const MODE_M680X_6809 = 1 << 7; // M680X Motorola 6809 mode
  export const MODE_M680X_6811 = 1 << 8; // Motorola/Freescale/NXP 68HC11 mode
  export const MODE_M680X_CPU12 = 1 << 9; // Motorola/Freescale/NXP CPU12
  export const MODE_M680X_HCS08 = 1 << 10; // M68HC12/HCS12 mode

  // Runtime option for the disassembled engine
  export const OPT_INVALID = 0; // No option specified
  export const OPT_SYNTAX = 1; // Intel X86 asm syntax (CS_ARCH_X86 arch Assembly output syntax)
  export const OPT_DETAIL = 2; // Break down instruction structure into details
  export const OPT_MODE = 3; // Change engine's mode at run-time
  export const OPT_MEM = 4; // Change engine's mode at run-time
  export const OPT_SKIPDATA = 5; // Skip data when disassembling
  export const OPT_SKIPDATA_SETUP = 6; // Setup user-defined function for SKIPDATA option
  export const OPT_MNEMONIC = 7; // Customize instruction mnemonic
  export const OPT_UNSIGNED = 8; // print immediate operands in unsigned form

  // Capstone option value
  export const OPT_OFF = 0; // Turn OFF an option - default option of CS_OPT_DETAIL
  export const OPT_ON = 3; // Turn ON an option (CS_OPT_DETAIL)

  // Capstone syntax value
  export const OPT_SYNTAX_DEFAULT = 0; // Default assembly syntax of all platforms (CS_OPT_SYNTAX)
  export const OPT_SYNTAX_INTEL = 1; // Intel X86 asm syntax - default syntax on X86 (CS_OPT_SYNTAX, CS_ARCH_X86)
  export const OPT_SYNTAX_ATT = 2; // ATT asm syntax (CS_OPT_SYNTAX, CS_ARCH_X86)
  export const OPT_SYNTAX_NOREGNAME = 3; // Asm syntax prints register name with only number - (CS_OPT_SYNTAX, CS_ARCH_PPC, CS_ARCH_ARM)
  export const OPT_SYNTAX_MASM = 4; // X86 Intel Masm syntax (CS_OPT_SYNTAX).

  // Common instruction groups - to be consistent across all architectures.
  export const GRP_INVALID = 0; // uninitialized/invalid group.
  export const GRP_JUMP = 1; // all jump instructions (conditional+direct+indirect jumps)
  export const GRP_CALL = 2; // all call instructions
  export const GRP_RET = 3; // all return instructions
  export const GRP_INT = 4; // all interrupt instructions (int+syscall)
  export const GRP_IRET = 5; // all interrupt return instructions
  export const GRP_PRIVILEGE = 6; // all privileged instructions
  export const GRP_BRANCH_RELATIVE = 7; // all relative branching instructions

  // Common instruction operand types - to be consistent across all architectures.
  export const OP_INVALID = 0; // Uninitialized/invalid operand.
  export const OP_REG = 1; // Register operand.
  export const OP_IMM = 2; // Immediate operand.
  export const OP_MEM = 3; // Memory operand.
  export const OP_FP = 4; // Floating-Point operand.

  // Common instruction operand access types - to be consistent across all architectures. It is possible to combine access types, for example: CS_AC_READ | CS_AC_WRITE
  export const AC_INVALID = 0; // Uninitialized/invalid access type.
  export const AC_READ = 1 << 0; // Operand read from memory or register.
  export const AC_WRITE = 1 << 1; // Operand written to memory or register.

  // query id for cs_support()
  export const SUPPORT_DIET = 0xffff + 1;
  export const SUPPORT_X86_REDUCE = 0xffff + 2;

  export function version() {
    const majorPtr = Wrapper._malloc(4);
    const minorPtr = Wrapper._malloc(4);
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

  export function support(query: number) {
    var ret = Wrapper.ccall("cs_support", "number", ["number"], [query]);
    return Boolean(ret);
  }

  export function strerror(code: number) {
    return Wrapper.ccall("cs_strerror", "string", ["number"], [code]);
  }

  export function errno(handle: number) {
    return Wrapper.ccall("cs_errno", "number", ["pointer"], [handle]);
  }

  export class Capstone {
    public arch: number;
    public mode: number;
    private handlePtr: number;

    constructor(arch: number, mode: number) {
      this.arch = arch;
      this.mode = mode;
      this.open();
    }

    private dereferenceInsn(insnPtr: number) {
      const insnId = Wrapper.getValue(insnPtr, "i32");
      const insnAddr = Wrapper.getValue(insnPtr + 8, "i64");
      const insnSize = Wrapper.getValue(insnPtr + 16, "i16");
      const insnMn = Wrapper.UTF8ToString(insnPtr + 34);
      const insnOp = Wrapper.UTF8ToString(insnPtr + 66);
      const insnBytes = [];

      for (let j = 0; j < insnSize; j++) {
        let byte = Wrapper.getValue(insnPtr + 18 + j, "i8");
        if (byte < 0) {
          byte += 256;
        }
        insnBytes.push(byte);
      }

      const insn = {
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
      option: number,
      value: number | { id: number; name: string },
    ) {
      if (typeof value === "boolean") {
        if (value) value = OPT_ON;
        else value = OPT_OFF;
      }
      const handle = Wrapper.getValue(this.handlePtr, "*");
      if (!handle) {
        return;
      }

      let objPtr = 0;

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

        const strPtr = Wrapper._malloc(value.name.length + 1);
        for (let i = 0; i < value.name.length; i++) {
          Wrapper.setValue(strPtr + i, value.name.charCodeAt(i), "i8");
        }
        Wrapper.setValue(strPtr + value.name.length, 0, "i8");

        objPtr = Wrapper._malloc(8);
        Wrapper.setValue(objPtr, value.id, "i32");
        Wrapper.setValue(objPtr + 4, strPtr, "i32");
      }

      const ret = Wrapper.ccall(
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

    private open() {
      this.handlePtr = Wrapper._malloc(4);
      const resOpen = Wrapper.ccall(
        "cs_open",
        "number",
        ["number", "number", "number"],
        [this.arch, this.mode, this.handlePtr],
      );
      if (resOpen != ERR_OK) {
        Wrapper.setValue(this.handlePtr, 0, "*");
        const error =
          "capstone: Function cs_open failed with code " +
          ret +
          ":\n" +
          strerror(ret);
        throw error;
      }
    }

    public close() {
      const ret = Wrapper.ccall(
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

    public disasm(buffer: Buffer, addr: number, maxLen?: number) {
      const bufferLen = buffer.length;
      const bufferPtr = Wrapper._malloc(bufferLen);
      const handle = Wrapper.getValue(this.handlePtr, "i32");
      const insnPtr = Wrapper._malloc(4);

      Wrapper.writeArrayToMemory(buffer, bufferPtr);

      const insnCount = Wrapper.ccall(
        "cs_disasm",
        "number",
        ["number", "number", "number", "number", "number", "number"],
        [handle, bufferPtr, bufferLen, addr, 0, maxLen || 0, insnPtr],
      );

      if (insnCount > 0) {
        const insnArrayPtr = Wrapper.getValue(insnPtr, "i32");
        const insnSize = 232;
        const instructions = [];

        for (let i = 0; i < insnCount; i++) {
          const insnOffset = insnArrayPtr + i * insnSize;
          const insn = this.dereferenceInsn(insnOffset);
          instructions.push(insn);
        }
        return instructions;
      } else {
        Wrapper._free(insnPtr);

        const code = cs.errno(handle);
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
      buffer: Buffer;
      addr: number;
      insn: object | null;
    }) {
      const { buffer, addr } = data;
      const handle = Wrapper.getValue(this.handlePtr, "i32");
      const bufferLen = buffer.length;
      const codeMem = Wrapper._malloc(buffer.length);
      const castPtr = Wrapper._malloc(42);
      const codePtr = castPtr;
      const sizePtr = castPtr + 8;
      const addrPtr = castPtr + 16;
      const insnPtr = Wrapper._cs_malloc(4);

      Wrapper.setValue(sizePtr, bufferLen, "i32");
      Wrapper.setValue(addrPtr, addr, "i64");
      Wrapper.writeArrayToMemory(buffer, codeMem);
      Wrapper.setValue(codePtr, codeMem, "i32");

      const ret = Wrapper.ccall(
        "cs_disasm_iter",
        "boolean",
        ["number", "number", "number", "number", "pointer"],
        [handle, codePtr, sizePtr, addrPtr, insnPtr],
      );

      if (ret) {
        const newAddr = Wrapper.getValue(addrPtr, "i64");
        const newSize = Wrapper.getValue(sizePtr, "i16");
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

        const insn = this.dereferenceInsn(insnPtr, "i32");

        data.buffer = Buffer.from(newBytes);
        data.addr = newAddr;
        data.insn = insn;
      }
      Wrapper._free(codeMem);
      Wrapper._free(castPtr);
      Wrapper._free(insnPtr);

      return ret;
    }

    public reg_name(reg_id: number) {
      const handle = Wrapper.getValue(this.handlePtr, "*");
      const ret = Wrapper.ccall(
        "cs_reg_name",
        "string",
        ["pointer", "number"],
        [handle, reg_id],
      );
      return ret;
    }

    public insn_name(insn_id: number) {
      const handle = Wrapper.getValue(this.handlePtr, "*");
      const ret = Wrapper.ccall(
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
