#include <stdio.h>

#include "../../capstone/include/capstone/capstone.h"

#define X86                                                                    \
  "\x8d\x4c\x32\x08\x01\xd8\x81\xc6\x34\x12\x00\x00\x05\x23\x01\x00\x00\x36"   \
  "\x8b\x84\x91\x23\x01\x00\x00\x41\x8d\x84\x39\x89\x67\x00\x00\x8d\x87\x89"   \
  "\x67\x00\x00\xb4\xc6\x66\xe9\xb8\x00\x00\x00\x67\xff\xa0\x23\x01\x00\x00"   \
  "\x66\xe8\xcb\x00\x00\x00\x74\xfc"
#define M68K                                                                   \
  "\x48\x32\x12\x34\x56\x78\xD2\x2A\xAB\xCD\x54\x03\x00\x00\x4C\x38\x00\x01"   \
  "\x4C\x0A\x00\x02\xD0\x2C\x4C\x0C\x00\x04\xD0\x2C\x4C\xFE\x00\x00\x00\x00"   \
  "\x12\x34\x56\x78\x32\x60\x4E\x00\x00\x11\x32\x61\x4E\x00\x00\x11\x32\x62"   \
  "\x4E\x00\x00\x11\xD3\xC0\x4C\x07\x00\x11\xD4\xC0\x4C\x06\x00\x11\xD5\xC0"   \
  "\x4C\x05\x00\x11\xD6\xC0\x4C\x04\x00\x11\xD7\xC0\x4C\x03\x00\x11\x42\x00"   \
  "\x4E\x71\x42\x41\x4E\x71\x42\x42\x4E\x71\x46\x00\x4E\x71\x46\x01\x4E\x71"   \
  "\x46\x02\x46\x03\x4E\x71\x46\x04\x4E\x71\x46\x05\x4E\x71\x46\x06\x4E\x71"
#define WASM "\x20\x00\x20\x01\x41\x20\x10\xc9\x01\x45\x0b"
#define TRICORE                                                                \
  "\x09\xcf\xbc\xf5\x09\xf4\x01\x00\x89\xfb\x8f\x74\x89\xfe\x48\x01\x29\x00"   \
  "\x19\x25\x29\x03\x09\xf4\x85\xf9\x68\x0f\x16\x01"
#define SH2A "\x32\x11\x92\x0\x32\x49\x31\x0"
#define RISCV                                                                  \
  "\x37\x34\x00\x00\x97\x82\x00\x00\xef\x00\x80\x00\xef\xf0\x1f\xff\xe7\x00"   \
  "\x45\x00\xe7\x00\xc0\xff\x63\x05\x41\x00\xe3\x9d\x61\xfe\x63\xca\x93\x00"   \
  "\x63\x53\xb5\x00\x63\x65\xd6\x00\x63\x76\xf7\x00\x03\x88\x18\x00\x03\x99"   \
  "\x49\x00\x03\xaa\x6a\x00\x03\xcb\x2b\x01\x03\xdc\x8c\x01\x23\x86\xad\x03"   \
  "\x23\x9a\xce\x03\x23\x8f\xef\x01\x93\x00\xe0\x00\x13\xa1\x01\x01\x13\xb2"   \
  "\x02\x7d\x13\xc3\x03\xdd\x13\xe4\xc4\x12\x13\xf5\x85\x0c\x13\x96\xe6\x01"   \
  "\x13\xd7\x97\x01\x13\xd8\xf8\x40\x33\x89\x49\x01\xb3\x0a\x7b\x41\x33\xac"   \
  "\xac\x01\xb3\x3d\xde\x01\x33\xd2\x62\x40\xb3\x43\x94\x00\x33\xe5\xc5\x00"   \
  "\xb3\x76\xf7\x00\xb3\x54\x39\x01\xb3\x50\x31\x00\x33\x9f\x0f\x00"
#define EBPF                                                                   \
  "\x97\x09\x00\x00\x37\x13\x03\x00\xdc\x02\x00\x00\x20\x00\x00\x00\x30\x00"   \
  "\x00\x00\x00\x00\x00\x00\xdb\x3a\x00\x01\x00\x00\x00\x00\x84\x02\x00\x00"   \
  "\x00\x00\x00\x00\x6d\x33\x17\x02\x00\x00\x00\x00"
#define MW65C02                                                                \
  "\x07\x12\x27\x12\x47\x12\x67\x12\x87\x12\xa7\x12\xc7\x12\xe7\x12"           \
  "\x10\xfe\x0f\x12\xfd\x4f\x12\xfd\x8f\x12\xfd\xcf\x12\xfd"
#define EVM "\x60\x61\x50"
#define TMS320C64X                                                             \
  "\x01\xac\x88\x40\x81\xac\x88\x43\x00\x00\x00\x00\x02\x90\x32\x96\x02\x80"   \
  "\x46\x9e\x05\x3c\x83\xe6\x0b\x0c\x8b\x24"
#define XCORE                                                                  \
  "\xfe\x0f\xfe\x17\x13\x17\xc6\xfe\xec\x17\x97\xf8\xec\x4f\x1f\xfd\xec\x37"   \
  "\x07\xf2\x45\x5b\xf9\xfa\x02\x06\x1b\x10\x09\xfd\xec\xa7"
#define CPU12                                                                  \
  "\x00\x04\x01\x00\x0c\x00\x80\x0e\x00\x80\x00\x11\x1e\x10\x00\x80\x00"       \
  "\x3b\x4a\x10\x00\x04\x4b\x01\x04\x4f\x7f\x80\x00\x8f\x10\x00\xb7\x52"       \
  "\xb7\xb1\xa6\x67\xa6\xfe\xa6\xf7\x18\x02\xe2\x30\x39\xe2\x10\x00"           \
  "\x18\x0c\x30\x39\x10\x00\x18\x11\x18\x12\x10\x00\x18\x19\x00\x18\x1e\x00"   \
  "\x18\x3e\x18\x3f\x00"
#define SYSZ                                                                   \
  "\xed\x00\x00\x00\x00\x1a\x5a\x0f\x1f\xff\xc2\x09\x80\x00\x00\x00\x07\xf7"   \
  "\xeb\x2a\xff\xff\x7f\x57\xe3\x01\xff\xff\x7f\x57\xeb\x00\xf0\x00\x00\x24"   \
  "\xb2\x4f\x00\x78\xec\x18\x00\x00\xc1\x7f"
#define SPARC                                                                  \
  "\x80\xa0\x40\x02\x85\xc2\x60\x08\x85\xe8\x20\x01\x81\xe8\x00\x00\x90\x10"   \
  "\x20\x01\xd5\xf6\x10\x16\x21\x00\x00\x0a\x86\x00\x40\x02\x01\x00\x00\x00"   \
  "\x12\xbf\xff\xff\x10\xbf\xff\xff\xa0\x02\x00\x09\x0d\xbf\xff\xff\xd4\x20"   \
  "\x60\x00\xd4\x4e\x00\x16\x2a\xc2\x80\x03"
#define PPC                                                                    \
  "\x10\x00\x1f\xec\xe0\x6d\x80\x04\xe4\x6d\x80\x04\x10\x60\x1c\x4c\x10\x60"   \
  "\x1c\x0c\xf0\x6d\x80\x04\xf4\x6d\x80\x04\x10\x60\x1c\x4e\x10\x60\x1c\x0e"   \
  "\x10\x60\x1a\x10\x10\x60\x1a\x11\x10\x63\x20\x2a\x10\x63\x20\x2b\x10\x83"   \
  "\x20\x40\x10\x83\x20\xC0\x10\x83\x20\x00\x10\x83\x20\x80\x10\x63\x20\x24"   \
  "\x10\x63\x20\x25\x10\x63\x29\x3a\x10\x63\x29\x3b\x10\x63\x29\x1c\x10\x63"   \
  "\x29\x1d\x10\x63\x29\x1e\x10\x63\x29\x1f\x10\x63\x24\x20\x10\x63\x24\x21"   \
  "\x10\x63\x24\x60\x10\x63\x24\x61\x10\x63\x24\xA0\x10\x63\x24\xA1\x10\x63"   \
  "\x24\xE0\x10\x63\x24\xE1\x10\x60\x20\x90\x10\x60\x20\x91\x10\x63\x29\x38"   \
  "\x10\x63\x29\x39\x10\x63\x01\x32\x10\x63\x01\x33\x10\x63\x01\x18\x10\x63"   \
  "\x01\x19\x10\x63\x01\x1A\x10\x63\x01\x1B\x10\x60\x19\x10\x10\x60\x19\x11"   \
  "\x10\x60\x18\x50\x10\x60\x18\x51\x10\x63\x29\x3e\x10\x63\x29\x3f\x10\x63"   \
  "\x29\x3c\x10\x63\x29\x3d\x10\x60\x18\x30\x10\x60\x18\x31\x10\x60\x18\x34"   \
  "\x10\x60\x18\x35\x10\x63\x29\x2e\x10\x63\x29\x2f\x10\x63\x20\x28\x10\x63"   \
  "\x20\x29\x10\x63\x29\x14\x10\x63\x29\x15\x10\x63\x29\x16\x10\x63\x29\x17"
#define MIPS                                                                   \
  "\x0C\x10\x00\x97\x00\x00\x00\x00\x24\x02\x00\x0c\x8f\xa2\x00\x00\x34\x21"   \
  "\x34\x56"
#define ARM64                                                                  \
  "\x09\x00\x38\xd5\xbf\x40\x00\xd5\x0c\x05\x13\xd5\x20\x50\x02\x0e\x20\xe4"   \
  "\x3d\x0f\x00\x18\xa0\x5f\xa2\x00\xae\x9e\x9f\x37\x03\xd5\xbf\x33\x03\xd5"   \
  "\xdf\x3f\x03\xd5\x21\x7c\x02\x9b\x21\x7c\x00\x53\x00\x40\x21\x4b\xe1\x0b"   \
  "\x40\xb9\x20\x04\x81\xda\x20\x08\x02\x8b\x10\x5b\xe8\x3c\xfd\x7b\xba\xa9"   \
  "\xfd\xc7\x43\xf8"
#define ARM                                                                    \
  "\x86\x48\x60\xf4\x4d\x0f\xe2\xf4\xED\xFF\xFF\xEB\x04\xe0\x2d\xe5\x00\x00"   \
  "\x00\x00\xe0\x83\x22\xe5\xf1\x02\x03\x0e\x00\x00\xa0\xe3\x02\x30\xc1\xe7"   \
  "\x00\x00\x53\xe3\x00\x02\x01\xf1\x05\x40\xd0\xe8\xf4\x80\x00\x00"

int main(void) {
  /*
  typedef struct x86_op_mem {
          x86_reg segment; ///< segment register (or X86_REG_INVALID if
  irrelevant) x86_reg base;	///< base register (or X86_REG_INVALID if
  irrelevant) x86_reg index;	///< index register (or X86_REG_INVALID if
  irrelevant) int scale;	///< scale for index register int64_t disp;
  ///< displacement value } x86_op_mem;

  /// Instruction operand
  typedef struct cs_x86_op {
          x86_op_type type;	///< operand type
          union {
                  x86_reg reg;	  ///< register value for REG operand
                  int64_t imm;		///< immediate value for IMM operand
                  x86_op_mem mem;		///< base/index/scale/disp value
  for MEM operand
          };

          /// size of this operand (in bytes).
          uint8_t size;

          /// How is this operand accessed? (READ, WRITE or READ|WRITE)
          /// This field is combined of cs_ac_type.
          /// NOTE: this field is irrelevant if engine is compiled in DIET mode.
          uint8_t access;

          /// AVX broadcast type, or 0 if irrelevant
          x86_avx_bcast avx_bcast;

          /// AVX zero opmask {z}
          bool avx_zero_opmask;
  } cs_x86_op;

  typedef struct cs_x86_encoding {
          /// ModR/M offset, or 0 when irrelevant
          uint8_t modrm_offset;

          /// Displacement offset, or 0 when irrelevant.
          uint8_t disp_offset;
          uint8_t disp_size;

          /// Immediate offset, or 0 when irrelevant.
          uint8_t imm_offset;
          uint8_t imm_size;
  } cs_x86_encoding;

  /// Instruction structure
  typedef struct cs_x86 {
          /// Instruction prefix, which can be up to 4 bytes.
          /// A prefix byte gets value 0 when irrelevant.
          /// prefix[0] indicates REP/REPNE/LOCK prefix (See
  X86_PREFIX_REP/REPNE/LOCK above)
          /// prefix[1] indicates segment override (irrelevant for x86_64):
          /// See X86_PREFIX_CS/SS/DS/ES/FS/GS above.
          /// prefix[2] indicates operand-size override (X86_PREFIX_OPSIZE)
          /// prefix[3] indicates address-size override (X86_PREFIX_ADDRSIZE)
          uint8_t prefix[4];

          /// Instruction opcode, which can be from 1 to 4 bytes in size.
          /// This contains VEX opcode as well.
          /// An trailing opcode byte gets value 0 when irrelevant.
          uint8_t opcode[4];

          /// REX prefix: only a non-zero value is relevant for x86_64
          uint8_t rex;

          /// Address size, which can be overridden with above prefix[5].
          uint8_t addr_size;

          /// ModR/M byte
          uint8_t modrm;

          /// SIB value, or 0 when irrelevant.
          uint8_t sib;

          /// Displacement value, valid if encoding.disp_offset != 0
          int64_t disp;

          /// SIB index register, or X86_REG_INVALID when irrelevant.
          x86_reg sib_index;
          /// SIB scale, only applicable if sib_index is valid.
          int8_t sib_scale;
          /// SIB base register, or X86_REG_INVALID when irrelevant.
          x86_reg sib_base;

          /// XOP Code Condition
          x86_xop_cc xop_cc;

          /// SSE Code Condition
          x86_sse_cc sse_cc;

          /// AVX Code Condition
          x86_avx_cc avx_cc;

          /// AVX Suppress all Exception
          bool avx_sae;

          /// AVX static rounding mode
          x86_avx_rm avx_rm;


          union {
                  /// EFLAGS updated by this instruction.
                  /// This can be formed from OR combination of X86_EFLAGS_*
  symbols in x86.h uint64_t eflags;
                  /// FPU_FLAGS updated by this instruction.
                  /// This can be formed from OR combination of X86_FPU_FLAGS_*
  symbols in x86.h uint64_t fpu_flags;
          };

          /// Number of operands of this instruction,
          /// or 0 when instruction has no operand.
          uint8_t op_count;

          cs_x86_op operands[8];	///< operands for this instruction.

          cs_x86_encoding encoding;  ///< encoding information
  } cs_x86;
  */
  csh x86handle;
  cs_insn *x86insn;
  size_t x86count;

  if (cs_open(CS_ARCH_X86, CS_MODE_16, &x86handle) != CS_ERR_OK)
    return -1;
  cs_option(x86handle, CS_OPT_DETAIL, CS_OPT_ON);
  x86count = cs_disasm(x86handle, (uint8_t *)X86, sizeof(X86) - 1, 0x1000, 0,
                       &x86insn);

  if (x86count > 0) {
    size_t j;

    printf("\x1b[31mx86\x1b[0m\n");
    for (j = 0; j < x86count; j++) {
      cs_detail *detail = x86insn[j].detail;
      printf("bytes: ");
      for (int i = 0; i < x86insn[j].size; i++) {
        printf("0x%02x, ", x86insn[j].bytes[i]);
      }
      printf("\n");
      printf("op distance: %d\n",
             ((char *)&detail->x86.operands - (char *)&detail->x86));
      printf("op size: %d\n", sizeof(cs_x86_op));
      printf("size: %d\n", x86insn[j].size);
      printf("regs_read_count: %d\n", detail->regs_read_count);
      printf("regs_read: %d\n", detail->regs_read[0]);
      printf("regs_write_count: %d\n", detail->regs_write_count);
      printf("regs_write: %d\n", detail->regs_write[0]);
      printf("groups_count: %d\n", detail->groups_count);
      printf("groups: %d\n\n", detail->groups[0]);

      cs_x86 *x86 = &(detail->x86);
      printf("prefix: %d\n", x86->prefix[0]);
      printf("opcode: %d\n", x86->opcode[0]);
      printf("rex: %d\n", x86->rex);
      printf("addr_size: %d\n", x86->addr_size);
      printf("modrm: %d\n", x86->modrm);
      printf("sib: %d\n", x86->sib);
      printf("disp: %ld\n", x86->disp);
      printf("sib_index: %d\n", x86->sib_index);
      printf("sib_scale: %d\n", x86->sib_scale);
      printf("sib_base: %d\n", x86->sib_base);
      printf("xop_cc: %d\n", x86->xop_cc);
      printf("sse_cc: %d\n", x86->sse_cc);
      printf("avx_cc: %d\n", x86->avx_cc);
      printf("avx_sae: %s\n", x86->avx_sae ? "true" : "false");
      printf("avx_rm: %d\n", x86->avx_rm);
      printf("eflags: %ld\n\n", x86->eflags);
      printf("fpu_flags: %ld\n\n", x86->fpu_flags);

      cs_x86_encoding encoding = x86->encoding;
      printf("cs_x86_encoding:\n");
      printf("modrm_offset: %d\n", encoding.modrm_offset);
      printf("disp_offset: %d\n", encoding.disp_offset);
      printf("disp_size: %d\n", encoding.disp_size);
      printf("imm_offset: %d\n", encoding.imm_offset);
      printf("imm_size: %d\n", encoding.imm_size);
      printf("\n\n");
      for (int i = 0; i < x86->op_count; i++) {
        cs_x86_op *op = &(x86->operands[i]);
        printf("size: %d\n", op->size);
        printf("access: %d\n", op->access);
        printf("avx_bcast: %d\n", op->avx_bcast);
        printf("avx_zero_opmask: %d\n", op->avx_zero_opmask);
        switch ((int)op->type) {
        case X86_OP_REG:
          printf("reg: %d\n", op->reg);
          break;
        case X86_OP_IMM:
          printf("imm: %d\n", op->imm);
          break;
        case X86_OP_MEM:
          printf("mem\n", i);
          printf("mem.segment: %d\n", op->mem.segment);
          printf("mem.base: %d\n", op->mem.base);
          printf("mem.index: %d\n", op->mem.index);
          printf("mem.scale: %d\n", op->mem.scale);
          printf("mem.disp: %ld\n", op->mem.disp);
          break;
        default:
          break;
        }
      }
    }
    cs_free(x86insn, x86count);
  } else {
    printf("ERROR: Failed to disassemble given code!\n");
  }
  /*
    csh armhandle;
    cs_insn *arminsn;
    size_t armcount;

    if (cs_open(CS_ARCH_ARM, 0, &armhandle) != CS_ERR_OK)
      return -1;
    cs_option(armhandle, CS_OPT_DETAIL, CS_OPT_ON);
    armcount = cs_disasm(armhandle, (uint8_t *)ARM, sizeof(ARM) - 1, 0x1000, 0,
                         &arminsn);
    if (armcount > 0) {
      size_t j;

      printf("\x1b[31marm\x1b[0m\n");
      for (j = 0; j < armcount; j++) {
        cs_detail *detail = arminsn[j].detail;
        printf("regs_read_count: %d\n", detail->regs_read_count);
        cs_arm *arm = &(detail->arm);
        printf("op distance: %d\n",
               ((char *)&detail->arm.operands - (char *)&detail->arm));
        printf("op size: %d\n", sizeof(cs_arm_op));
        printf("usermode: %d\n", arm->usermode);
        printf("vector_size: %d\n", arm->vector_size);
        printf("vector_data: %d\n", arm->vector_data);
        printf("cps_mode: %d\n", arm->cps_mode);
        printf("cps_flag: %d\n", arm->cps_flag);
        printf("cc: %d\n", arm->cc);
        printf("update_flags: %d\n", arm->update_flags);
        printf("writeback: %d\n", arm->writeback);
        printf("post_index: %d\n", arm->post_index);
        printf("mem_barrier: %d\n", arm->mem_barrier);
        for (int i = 0; i < arm->op_count; i++) {
          cs_arm_op *op = &(arm->operands[i]);
          printf("vector_index: %d\n", op->vector_index);
          printf("shift.type: %d\n", op->shift.type);
          printf("shift.value: %d\n", op->shift.value);
          printf("subtracted: %d\n", op->subtracted);
          printf("access: %d\n", sizeof(op->access));
          printf("neon_lane: %d\n", op->neon_lane);
          printf(
              "subtracted distance: %d\n",
              ((char *)&arm->operands[i].subtracted - (char
  *)&arm->operands[i])); switch ((int)op->type) { default: break; case
  ARM_OP_REG: printf("\t\toperands[%u].type: REG = %s(%d)\n", i,
                   cs_reg_name(armhandle, op->reg), op->reg);
            break;
          case ARM_OP_IMM:
            printf("\t\toperands[%u].type: IMM = 0x%x(%d)\n", i, op->imm,
                   op->imm);
            break;
          case ARM_OP_FP:
  #if defined(_KERNEL_MODE)
            // Issue #681: Windows kernel does not support formatting float
  point printf("\t\toperands[%u].type: FP = <float_point_unsupported>\n", i);
  #else
            printf("\t\toperands[%u].type: FP = %f(%d)\n", i, op->fp, op->fp);
  #endif
            break;
          case ARM_OP_MEM:
            printf("\t\toperands[%u].type: MEM\n", i);
            printf("base: %d\n", op->mem.base);
            printf("index: %d\n", op->mem.index);
            printf("scale: %d\n", op->mem.scale);
            printf("disp: %d\n", op->mem.disp);
            printf("lshift: %d\n", op->mem.lshift);
            if (op->mem.base != ARM_REG_INVALID)
              printf("\t\t\toperands[%u].mem.base: REG = %s\n", i,
                     cs_reg_name(armhandle, op->mem.base));
            if (op->mem.index != ARM_REG_INVALID)
              printf("\t\t\toperands[%u].mem.index: REG = %s\n", i,
                     cs_reg_name(armhandle, op->mem.index));
            if (op->mem.scale != 1)
              printf("\t\t\toperands[%u].mem.scale: %u\n", i, op->mem.scale);
            if (op->mem.disp != 0)
              printf("\t\t\toperands[%u].mem.disp: 0x%x\n", i, op->mem.disp);
            if (op->mem.lshift != 0)
              printf("\t\t\toperands[%u].mem.lshift: 0x%x\n", i,
  op->mem.lshift);

            break;
          case ARM_OP_PIMM:
            printf("\t\toperands[%u].type: P-IMM = %u(%d)\n", i, op->imm,
                   op->imm);
            break;
          case ARM_OP_CIMM:
            printf("\t\toperands[%u].type: C-IMM = %u(%d)\n", i, op->imm,
                   op->imm);
            break;
          case ARM_OP_SETEND:
            printf("\t\toperands[%u].type: SETEND = %s(%d)\n", i,
                   op->setend == ARM_SETEND_BE ? "be" : "le", op->setend);
            break;
          case ARM_OP_SYSREG:
            printf("\t\toperands[%u].type: SYSREG = %u(%d)\n", i, op->reg,
                   op->reg);
            break;
          }
        }
        printf("\n\n");
      }
    }

    csh arm64handle;
    cs_insn *arm64insn;
    size_t arm64count;
    if (cs_open(1, 0, &arm64handle) != CS_ERR_OK)
      return -1;
    cs_option(arm64handle, CS_OPT_DETAIL, CS_OPT_ON);
    arm64count = cs_disasm(arm64handle, (uint8_t *)ARM64, sizeof(ARM64) - 1,
                           0x1000, 0, &arm64insn);
    if (arm64count > 0) {
      size_t j;

      printf("\x1b[31marm64\x1b[0m\n");
      for (j = 0; j < arm64count; j++) {
        cs_detail *detail = arm64insn[j].detail;
        printf("regs_read_count: %d\n", detail->regs_read_count);
        cs_arm64 *arm64 = &(detail->arm64);
        printf("cc: %d\n", arm64->cc);
        printf("update_flags: %d\n", arm64->update_flags);
        printf("writeback: %d\n", arm64->writeback);
        printf("post_index: %d\n", arm64->post_index);
        printf("op distance: %d\n",
               ((char *)&detail->arm64.operands - (char *)&detail->arm64));
        printf("op size: %d\n", sizeof(cs_arm64_op));
        printf("post_index distance: %d\n",
               (char *)&arm64->post_index - (char *)&arm64->cc);
        printf("op_count distance: %d\n",
               (char *)&arm64->op_count - (char *)&arm64->cc);
        for (int i = 0; i < arm64->op_count; i++) {
          cs_arm64_op *op = &(arm64->operands[i]);
          printf("vector_index: %d\n", op->vector_index);
          printf("vas: %d\n", op->vas);
          printf("type: %d\n", op->shift.type);
          printf("value: %d\n", op->shift.value);
          printf("ext: %d\n", op->ext);
          printf("access: %d\n", op->access);
          printf("svcr distance: %d\n",
                 (char *)&op->svcr - (char *)&op->vector_index);
          printf("op_type distance: %d\n",
                 (char *)&op->type - (char *)&op->vector_index);
          printf("ext distance: %d\n",
                 (char *)&op->ext - (char *)&op->vector_index);
          printf("shift distance: %d\n",
                 (char *)&op->shift - (char *)&op->vector_index);
          printf("shift.type distance: %d\n",
                 (char *)&op->shift.type - (char *)&op->vector_index);
          printf("shift.value distance: %d\n",
                 (char *)&op->shift.value - (char *)&op->vector_index);
          printf("vector_index distance: %d\n",
                 (char *)&op->vector_index - (char *)&op->vector_index);
          printf("vas distance: %d\n",
                 (char *)&op->vas - (char *)&op->vector_index);
          printf("reg distance: %d\n",
                 (char *)&op->reg - (char *)&op->vector_index);
          printf("mem.index distance: %d\n",
                 (char *)&op->mem.index - (char *)&op->vector_index);
          printf("mem.disp distance: %d\n",
                 (char *)&op->mem.disp - (char *)&op->vector_index);
          printf("sme_index distance: %d\n",
                 (char *)&op->sme_index - (char *)&op->vector_index);
          printf("access distance: %d\n",
                 (char *)&op->access - (char *)&op->vector_index);

          switch (op->type) {
          default:
            break;
          case ARM64_OP_REG:
            printf("\t\toperands[%u].type: REG = %s(%d)\n", i,
                   cs_reg_name(arm64handle, op->reg), op->reg);
            break;
          case ARM64_OP_IMM:
            printf("\t\toperands[%u].type: IMM = 0x%" PRIx64 "(%d)\n", i,
  op->imm, op->imm); break; case ARM64_OP_FP: #if defined(_KERNEL_MODE)
            // Issue #681: Windows kernel does not support formatting float
  point printf("\t\toperands[%u].type: FP = <float_point_unsupported>\n", i);
  #else
            printf("\t\toperands[%u].type: FP = %f(%d)\n", i, op->fp, op->fp);
  #endif
            break;
          case ARM64_OP_MEM:
            printf("base: %d\n", op->mem.base);
            printf("index: %d\n", op->mem.index);
            printf("disp: %d\n", op->mem.disp);
            printf("\t\toperands[%u].type: MEM\n", i);
            if (op->mem.base != ARM64_REG_INVALID)
              printf("\t\t\toperands[%u].mem.base: REG = %s\n", i,
                     cs_reg_name(arm64handle, op->mem.base));
            if (op->mem.index != ARM64_REG_INVALID)
              printf("\t\t\toperands[%u].mem.index: REG = %s\n", i,
                     cs_reg_name(arm64handle, op->mem.index));
            if (op->mem.disp != 0)
              printf("\t\t\toperands[%u].mem.disp: 0x%x\n", i, op->mem.disp);

            break;
          case ARM64_OP_CIMM:
            printf("\t\toperands[%u].type: C-IMM = %u(%d)\n", i, (int)op->imm,
                   op->imm);
            break;
          case ARM64_OP_REG_MRS:
            printf("\t\toperands[%u].type: REG_MRS = 0x%x(%d)\n", i, op->reg,
                   op->reg);
            break;
          case ARM64_OP_REG_MSR:
            printf("\t\toperands[%u].type: REG_MSR = 0x%x(%d)\n", i, op->reg,
                   op->reg);
            break;
          case ARM64_OP_PSTATE:
            printf("\t\toperands[%u].type: PSTATE = 0x%x(%d)\n", i, op->pstate,
                   op->pstate);
            break;
          case ARM64_OP_SYS:
            printf("\t\toperands[%u].type: SYS = 0x%x(%d)\n", i, op->sys,
                   op->sys);
            break;
          case ARM64_OP_PREFETCH:
            printf("\t\toperands[%u].type: PREFETCH = 0x%x(%d)\n", i,
                   op->prefetch, op->prefetch);
            break;
          case ARM64_OP_BARRIER:
            printf("\t\toperands[%u].type: BARRIER = 0x%x(%d)\n", i,
  op->barrier, op->barrier); break;
          }
        }

        printf("\n\n");
      }
    }

    const char *s_addressing_modes[] = {
        "<invalid mode>",

        "Register Direct - Data",
        "Register Direct - Address",

        "Register Indirect - Address",
        "Register Indirect - Address with Postincrement",
        "Register Indirect - Address with Predecrement",
        "Register Indirect - Address with Displacement",

        "Address Register Indirect With Index - 8-bit displacement",
        "Address Register Indirect With Index - Base displacement",

        "Memory indirect - Postindex",
        "Memory indirect - Preindex",

        "Program Counter Indirect - with Displacement",

        "Program Counter Indirect with Index - with 8-Bit Displacement",
        "Program Counter Indirect with Index - with Base Displacement",

        "Program Counter Memory Indirect - Postindexed",
        "Program Counter Memory Indirect - Preindexed",

        "Absolute Data Addressing  - Short",
        "Absolute Data Addressing  - Long",
        "Immediate value",
    };
    csh m68khandle;
    cs_insn *m68kinsn;
    size_t m68kcount;

    if (cs_open(CS_ARCH_M68K, CS_MODE_M68K_020, &m68khandle) != CS_ERR_OK)
      return -1;
    cs_option(m68khandle, CS_OPT_DETAIL, CS_OPT_ON);
    m68kcount = cs_disasm(m68khandle, (uint8_t *)M68K, sizeof(M68K) - 1, 0x1000,
                          0, &m68kinsn);
    if (m68kcount > 0) {
      size_t j;

      printf("\x1b[31mm68k\x1b[0m\n");
      for (j = 0; j < m68kcount; j++) {
        cs_detail *detail = m68kinsn[j].detail;
        printf("distance: %ld %d\n",
               ((char *)&detail->m68k.op_size - (char *)&detail->m68k) / 4,
               CS_MODE_M68K_020);
        printf("regs_read_count: %d\n", detail->regs_read_count);
        printf("op_type: %d\n", detail->m68k.operands[0].type);
        printf("op_count: %d\n", detail->m68k.op_count);
        printf("op_size type: %d\n", detail->m68k.op_size.type);
        printf("cpu_size: %d\n", detail->m68k.op_size.cpu_size);
        for (int i = 0; i < detail->m68k.op_count; i++) {
          cs_m68k_op *op = &(detail->m68k.operands[i]);
          printf("disp: %d\n", op->br_disp.disp);
          printf("disp_size: %d\n", op->br_disp.disp_size);
          printf("register bits: %d\n", op->register_bits);
          switch ((int)op->type) {
          default:
            break;
          case M68K_OP_REG:
            printf("\t\toperands[%u].type: REG = %s(%d)\n", i,
                   cs_reg_name(m68khandle, op->reg), op->reg);
            break;
          case M68K_OP_IMM:
            printf("\t\toperands[%u].type: IMM = 0x%x(%d)\n", i, (int)op->imm,
                   op->imm);
            break;
          case M68K_OP_MEM:
            printf("\t\toperands[%u].type: MEM\n", i);
            if (op->mem.base_reg != M68K_REG_INVALID)
              printf("\t\t\toperands[%u].mem.base: REG = %s(%d)\n", i,
                     cs_reg_name(m68khandle, op->mem.base_reg),
  op->mem.base_reg); if (op->mem.index_reg != M68K_REG_INVALID) {
              printf("\t\t\toperands[%u].mem.index: REG = %s(%d)\n", i,
                     cs_reg_name(m68khandle, op->mem.index_reg),
                     op->mem.index_reg);
              printf("\t\t\toperands[%u].mem.index: size = %c(%d)\n", i,
                     op->mem.index_size ? 'l' : 'w', op->mem.index_size);
            }
            printf("\t\t\toperands[%u].mem.disp: 0x%x(%d)\n", i, op->mem.disp,
                   op->mem.disp);
            printf("\t\t\toperands[%u].mem.scale: %d(%d)\n", i, op->mem.scale,
                   op->mem.scale);
            printf("\t\tin_disp: %d\n", op->mem.in_disp);
            printf("\t\tout_disp: %d\n", op->mem.out_disp);
            printf("\t\tbitfield: %d\n", op->mem.bitfield);
            printf("\t\twidth: %d\n", op->mem.width);
            printf("\t\toffset: %d\n", op->mem.offset);
            printf("\t\taddress mode: %s(%d)%d\n",
                   s_addressing_modes[op->address_mode], op->address_mode,
                   (char *)&detail->m68k.operands[i].register_bits -
                       (char *)&detail->m68k.operands[i]);
            break;
          case M68K_OP_FP_SINGLE:
            printf("\t\toperands[%u].type: FP_SINGLE\n", i);
            printf("\t\t\toperands[%u].simm: %f(%d)\n", i, op->simm, op->simm);
            break;
          case M68K_OP_FP_DOUBLE:
            printf("\t\toperands[%u].type: FP_DOUBLE\n", i);
            printf("\t\t\toperands[%u].dimm: %lf(%d)\n", i, op->dimm, op->dimm);
            break;
          case M68K_OP_REG_BITS:
            printf("\t\toperands[%u].type: REG_BITS = $%x(%d)\n", i,
                   op->register_bits, op->register_bits);
            break;
          case M68K_OP_REG_PAIR:
            printf("\t\toperands[%u].type: REG_PAIR = (%s, %s)(%d %d)\n", i,
                   cs_reg_name(m68khandle, op->reg_pair.reg_0),
                   cs_reg_name(m68khandle, op->reg_pair.reg_1),
                   op->reg_pair.reg_0, op->reg_pair.reg_1);
            break;
          }
        }
        printf("\n\n");
      }
    }

    csh mipshandle;
    cs_insn *mipsinsn;
    size_t mipscount;

    if (cs_open(CS_ARCH_MIPS, CS_MODE_MIPS32 | CS_MODE_BIG_ENDIAN, &mipshandle)
  != CS_ERR_OK) return -1; cs_option(mipshandle, CS_OPT_DETAIL, CS_OPT_ON);
    mipscount = cs_disasm(mipshandle, (uint8_t *)MIPS, sizeof(MIPS) - 1, 0x1000,
                          0, &mipsinsn);
    if (mipscount > 0) {
      size_t j;

      printf("\x1b[31mmips\x1b[0m\n");
      for (j = 0; j < mipscount; j++) {
        cs_detail *detail = mipsinsn[j].detail;
        printf("regs_read_count: %d\n", detail->regs_read_count);
        printf("op distance: %d\n",
               ((char *)&detail->mips.operands - (char *)&detail->mips));
        printf("op size: %d\n", sizeof(cs_mips_op));
        cs_mips *mips = &(detail->mips);

        for (int i = 0; i < mips->op_count; i++) {
          cs_mips_op *op = &(mips->operands[i]);
          switch ((int)op->type) {
          default:
            break;
          case MIPS_OP_REG:
            printf("\t\toperands[%u].type: REG = %s(%d)\n", i,
                   cs_reg_name(mipshandle, op->reg), op->reg);
            break;
          case MIPS_OP_IMM:
            printf("\t\toperands[%u].type: IMM = 0x%" PRIx64 "(%d)\n", i,
  op->imm, op->imm); break; case MIPS_OP_MEM: printf("base: %d\n",
  op->mem.base); printf("disp: %d\n", op->mem.disp);
            printf("\t\toperands[%u].type: MEM\n", i);
            if (op->mem.base != MIPS_REG_INVALID)
              printf("\t\t\toperands[%u].mem.base: REG = %s\n", i,
                     cs_reg_name(mipshandle, op->mem.base));
            if (op->mem.disp != 0)
              printf("\t\t\toperands[%u].mem.disp: 0x%" PRIx64 "\n", i,
                     op->mem.disp);

            break;
          }
        }
        printf("\n\n");
      }
    }

    const char *get_bc_name(int bc) {
      switch (bc) {
      default:
      case PPC_BC_INVALID:
        return ("invalid");
      case PPC_BC_LT:
        return ("lt");
      case PPC_BC_LE:
        return ("le");
      case PPC_BC_EQ:
        return ("eq");
      case PPC_BC_GE:
        return ("ge");
      case PPC_BC_GT:
        return ("gt");
      case PPC_BC_NE:
        return ("ne");
      case PPC_BC_UN:
        return ("un");
      case PPC_BC_NU:
        return ("nu");
      case PPC_BC_SO:
        return ("so");
      case PPC_BC_NS:
        return ("ns");
      }
    }

    csh ppchandle;
    cs_insn *ppcinsn;
    size_t ppccount;

    if (cs_open(CS_ARCH_PPC, CS_MODE_BIG_ENDIAN + CS_MODE_PS, &ppchandle) !=
        CS_ERR_OK)
      return -1;
    cs_option(ppchandle, CS_OPT_DETAIL, CS_OPT_ON);
    ppccount = cs_disasm(ppchandle, (uint8_t *)PPC, sizeof(PPC) - 1, 0x1000, 0,
                         &ppcinsn);
    if (ppccount > 0) {
      size_t j;

      printf("\x1b[31mppc\x1b[0m\n");
      for (j = 0; j < ppccount; j++) {
        cs_detail *detail = ppcinsn[j].detail;
        printf("regs_read_count: %d\n", detail->regs_read_count);
        cs_ppc *ppc = &(detail->ppc);
        printf("bc: %d\n", ppc->bc);
        printf("bh: %d\n", ppc->bh);
        printf("update_cr0: %d\n", ppc->update_cr0);

        printf("op distance: %d\n",
               ((char *)&detail->ppc.operands - (char *)&detail->ppc));
        printf("op size: %d\n", sizeof(cs_ppc_op));
        printf("PPC_OP_REG: %d\nPPC_OP_IMM: %d\nPPC_OP_MEM: %d\nPPC_OP_CRX:
  %d\n", PPC_OP_REG, PPC_OP_IMM, PPC_OP_MEM, PPC_OP_CRX); for (int i = 0; i <
  ppc->op_count; i++) { cs_ppc_op *op = &(ppc->operands[i]); printf("type:%d\n",
  op->type);

          switch ((int)op->type) {
          default:
            break;
          case PPC_OP_REG:
            printf("\t\toperands[%u].type: REG = %s(%d)\n", i,
                   cs_reg_name(ppchandle, op->reg), op->reg);
            break;
          case PPC_OP_IMM:
            printf("\t\toperands[%u].type: IMM = 0x%" PRIx64 "(%d)\n", i,
  op->imm, op->imm); break; case PPC_OP_MEM: printf("base: %d\n", op->mem.base);
            printf("disp: %d\n", op->mem.disp);
            printf("\t\toperands[%u].type: MEM\n", i);
            if (op->mem.base != PPC_REG_INVALID)
              printf("\t\t\toperands[%u].mem.base: REG = %s\n", i,
                     cs_reg_name(ppchandle, op->mem.base));
            if (op->mem.disp != 0)
              printf("\t\t\toperands[%u].mem.disp: 0x%x\n", i, op->mem.disp);

            break;
          case PPC_OP_CRX:
            printf("\t\toperands[%u].type: CRX\n", i);
            printf("\t\t\toperands[%u].crx.scale: %d\n", i, op->crx.scale);
            printf("\t\t\toperands[%u].crx.reg: %s(%d)\n", i,
                   cs_reg_name(ppchandle, op->crx.reg), op->crx.reg);
            printf("\t\t\toperands[%u].crx.cond: %s(%d)\n", i,
                   get_bc_name(op->crx.cond), op->crx.cond);
            break;
          }
        }
        printf("\n\n");
      }
    }

    csh sparchandle;
    cs_insn *sparcinsn;
    size_t sparccount;

    if (cs_open(CS_ARCH_SPARC, CS_MODE_BIG_ENDIAN + CS_MODE_V9, &sparchandle) !=
        CS_ERR_OK)
      return -1;
    cs_option(sparchandle, CS_OPT_DETAIL, CS_OPT_ON);
    sparccount = cs_disasm(sparchandle, (uint8_t *)SPARC, sizeof(SPARC) - 1,
                           0x1000, 0, &sparcinsn);
    if (sparccount > 0) {
      size_t j;

      printf("\x1b[31msparc\x1b[0m\n");
      for (j = 0; j < sparccount; j++) {
        cs_detail *detail = sparcinsn[j].detail;
        printf("regs_read_count: %d\n", detail->regs_read_count);
        printf("op distance: %d\n",
               ((char *)&detail->sparc.operands - (char *)&detail->sparc));
        printf("op size: %d\n", sizeof(cs_sparc_op));
        printf("cc: %d\n", detail->sparc.cc);
        printf("hint: %d\n", detail->sparc.hint);
        cs_sparc *sparc = &(detail->sparc);
        for (int i = 0; i < sparc->op_count; i++) {
          cs_sparc_op *op = &(sparc->operands[i]);
          switch ((int)op->type) {
          default:
            break;
          case SPARC_OP_REG:
            printf("\t\toperands[%u].type: REG = %s(%d)\n", i,
                   cs_reg_name(sparchandle, op->reg), op->reg);
            break;
          case SPARC_OP_IMM:
            printf("\t\toperands[%u].type: IMM = 0x%" PRIx64 "(%d)\n", i,
  op->imm, op->imm); break; case SPARC_OP_MEM: printf("base: %d\n",
  op->mem.base); printf("index: %d\n", op->mem.index); printf("disp: %d\n",
  op->mem.disp); printf("\t\toperands[%u].type: MEM\n", i); if (op->mem.base !=
  X86_REG_INVALID) printf("\t\t\toperands[%u].mem.base: REG = %s\n", i,
                     cs_reg_name(sparchandle, op->mem.base));
            if (op->mem.index != X86_REG_INVALID)
              printf("\t\t\toperands[%u].mem.index: REG = %s\n", i,
                     cs_reg_name(sparchandle, op->mem.index));
            if (op->mem.disp != 0)
              printf("\t\t\toperands[%u].mem.disp: 0x%x\n", i, op->mem.disp);

            break;
          }
        }
        printf("\n\n");
      }
    }

    csh syszhandle;
    cs_insn *syszinsn;
    size_t syszcount;

    if (cs_open(CS_ARCH_SYSZ, CS_MODE_BIG_ENDIAN, &syszhandle) != CS_ERR_OK)
      return -1;
    cs_option(syszhandle, CS_OPT_DETAIL, CS_OPT_ON);
    syszcount = cs_disasm(syszhandle, (uint8_t *)SYSZ, sizeof(SYSZ) - 1, 0x1000,
                          0, &syszinsn);
    if (syszcount > 0) {
      size_t j;

      printf("\x1b[31msysz\x1b[0m\n");
      for (j = 0; j < syszcount; j++) {
        cs_detail *detail = syszinsn[j].detail;
        printf("regs_read_count: %d\n", detail->regs_read_count);
        printf("op distance: %d\n",
               ((char *)&detail->sysz.operands - (char *)&detail->sysz));
        printf("op size: %d\n", sizeof(cs_sysz_op));
        printf("cc: %d\n", detail->sysz.cc);
        cs_sysz *sysz = &(detail->sysz);
        for (int i = 0; i < sysz->op_count; i++) {
          cs_sysz_op *op = &(sysz->operands[i]);
          switch ((int)op->type) {
          default:
            break;
          case SYSZ_OP_REG:
            printf("\t\toperands[%u].type: REG = %s(%d)\n", i,
                   cs_reg_name(syszhandle, op->reg), op->reg);
            break;
          case SYSZ_OP_ACREG:
            printf("\t\toperands[%u].type: ACREG = %u(%d)\n", i, op->reg,
                   op->reg);
            break;
          case SYSZ_OP_IMM:
            printf("\t\toperands[%u].type: IMM = 0x%" PRIx64 "(%lld)\n", i,
                   op->imm, op->imm);
            break;
          case SYSZ_OP_MEM:
            printf("base: %d\n", op->mem.base);
            printf("index: %d\n", op->mem.index);
            printf("length: %d\n", op->mem.length);
            printf("disp: %d\n", op->mem.disp);
            printf("\t\toperands[%u].type: MEM\n", i);
            if (op->mem.base != SYSZ_REG_INVALID)
              printf("\t\t\toperands[%u].mem.base: REG = %s\n", i,
                     cs_reg_name(syszhandle, op->mem.base));
            if (op->mem.index != SYSZ_REG_INVALID)
              printf("\t\t\toperands[%u].mem.index: REG = %s\n", i,
                     cs_reg_name(syszhandle, op->mem.index));
            if (op->mem.length != 0)
              printf("\t\t\toperands[%u].mem.length: 0x%" PRIx64 "\n", i,
                     op->mem.length);
            if (op->mem.disp != 0)
              printf("\t\t\toperands[%u].mem.disp: 0x%" PRIx64 "\n", i,
                     op->mem.disp);

            break;
          }
        }
        printf("\n\n");
      }
    }

    csh xcorehandle;
    cs_insn *xcoreinsn;
    size_t xcorecount;

    if (cs_open(CS_ARCH_XCORE, CS_MODE_BIG_ENDIAN, &xcorehandle) != CS_ERR_OK)
      return -1;
    cs_option(xcorehandle, CS_OPT_DETAIL, CS_OPT_ON);
    xcorecount = cs_disasm(xcorehandle, (uint8_t *)XCORE, sizeof(XCORE) - 1,
                           0x1000, 0, &xcoreinsn);
    if (xcorecount > 0) {
      size_t j;

      printf("\x1b[31mxcore\x1b[0m\n");
      for (j = 0; j < xcorecount; j++) {
        cs_detail *detail = xcoreinsn[j].detail;
        printf("regs_read_count: %d\n", detail->regs_read_count);
        cs_xcore *xcore = &(detail->xcore);
        for (int i = 0; i < xcore->op_count; i++) {
          cs_xcore_op *op = &(xcore->operands[i]);
          switch ((int)op->type) {
          default:
            break;
          case XCORE_OP_REG:
            printf("\t\toperands[%u].type: REG = %s(%d)\n", i,
                   cs_reg_name(xcorehandle, op->reg), op->reg);
            break;
          case XCORE_OP_IMM:
            printf("\t\toperands[%u].type: IMM = 0x%x(%d)\n", i, op->imm,
                   op->imm);
            break;
          case XCORE_OP_MEM:
            printf("base: %d\n", op->mem.base);
            printf("index: %d\n", op->mem.index);
            printf("disp: %d\n", op->mem.disp);
            printf("direct: %d\n", op->mem.direct);
            printf("\t\toperands[%u].type: MEM\n", i);
            if (op->mem.base != XCORE_REG_INVALID)
              printf("\t\t\toperands[%u].mem.base: REG = %s(%d)\n", i,
                     cs_reg_name(xcorehandle, op->mem.base), op->mem.base);
            if (op->mem.index != XCORE_REG_INVALID)
              printf("\t\t\toperands[%u].mem.index: REG = %s(%d)\n", i,
                     cs_reg_name(xcorehandle, op->mem.index), op->mem.index);
            if (op->mem.disp != 0)
              printf("\t\t\toperands[%u].mem.disp: 0x%x(%d)\n", i, op->mem.disp,
                     op->mem.disp);
            if (op->mem.direct != 1)
              printf("\t\t\toperands[%u].mem.direct: -1(%d)\n", i,
                     op->mem.direct);

            break;
          }
        }
        printf("\n\n");
      }
    }

    csh tms320c64xhandle;
    cs_insn *tms320c64xinsn;
    size_t tms320c64xcount;

    if (cs_open(CS_ARCH_TMS320C64X, CS_MODE_BIG_ENDIAN, &tms320c64xhandle) !=
        CS_ERR_OK)
      return -1;
    cs_option(tms320c64xhandle, CS_OPT_DETAIL, CS_OPT_ON);
    tms320c64xcount =
        cs_disasm(tms320c64xhandle, (uint8_t *)TMS320C64X, sizeof(TMS320C64X) -
  1, 0x1000, 0, &tms320c64xinsn); if (tms320c64xcount > 0) { size_t j;

      printf("\x1b[31mtms320c64x\x1b[0m\n");
      for (j = 0; j < tms320c64xcount; j++) {
        cs_detail *detail = tms320c64xinsn[j].detail;
        printf("op_str: %s\n", tms320c64xinsn[j].op_str);
        printf("regs_read_count: %d\n", detail->regs_read_count);
        printf("unit: %d\n", detail->tms320c64x.funit.unit);
        printf("side: %d\n", detail->tms320c64x.funit.side);
        printf("crosspath: %d\n", detail->tms320c64x.funit.crosspath);
        printf("parallel: %d\n", detail->tms320c64x.parallel);
        printf("reg: %d\n", detail->tms320c64x.condition.reg);
        printf("zero: %d\n", detail->tms320c64x.condition.zero);
        cs_tms320c64x *tms320c64x = &(detail->tms320c64x);
        for (int i = 0; i < tms320c64x->op_count; i++) {
          cs_tms320c64x_op *op = &(tms320c64x->operands[i]);
          printf("op_type: %d\n", op->type);
          switch ((int)op->type) {
          default:
            break;
          case TMS320C64X_OP_REG:
            printf("\t\toperands[%u].type: REG = %s(%d)\n", i,
                   cs_reg_name(tms320c64xhandle, op->reg), op->reg);
            break;
          case TMS320C64X_OP_IMM:
            printf("\t\toperands[%u].type: IMM = 0x%x(%d)\n", i, op->imm,
                   op->imm);
            break;
          case TMS320C64X_OP_MEM:
            printf("\t\toperands[%u].type: MEM\n", i);
            if (op->mem.base != TMS320C64X_REG_INVALID)
              printf("\t\t\toperands[%u].mem.base: REG = %s(%d)\n", i,
                     cs_reg_name(tms320c64xhandle, op->mem.base), op->mem.base);
            printf("\t\t\toperands[%u].mem.disptype(%d): ", i,
  op->mem.disptype); if (op->mem.disptype == TMS320C64X_MEM_DISP_INVALID) {
              printf("Invalid\n");
              printf("\t\t\toperands[%u].mem.disp: %u(%d)\n", i, op->mem.disp,
                     op->mem.disp);
            }
            if (op->mem.disptype == TMS320C64X_MEM_DISP_CONSTANT) {
              printf("Constant\n");
              printf("\t\t\toperands[%u].mem.disp: %u(%d)\n", i, op->mem.disp,
                     op->mem.disp);
            }
            if (op->mem.disptype == TMS320C64X_MEM_DISP_REGISTER) {
              printf("Register\n");
              printf("\t\t\toperands[%u].mem.disp: %s(%d)\n", i,
                     cs_reg_name(tms320c64xhandle, op->mem.disp), op->mem.disp);
            }
            printf("\t\t\toperands[%u].mem.unit: %u(%d)\n", i, op->mem.unit,
                   op->mem.unit);
            printf("\t\t\toperands[%u].mem.direction(%d): ", i,
                   op->mem.direction);
            if (op->mem.direction == TMS320C64X_MEM_DIR_INVALID)
              printf("Invalid\n");
            if (op->mem.direction == TMS320C64X_MEM_DIR_FW)
              printf("Forward\n");
            if (op->mem.direction == TMS320C64X_MEM_DIR_BW)
              printf("Backward\n");
            printf("\t\t\toperands[%u].mem.modify(%d): ", i, op->mem.modify);
            if (op->mem.modify == TMS320C64X_MEM_MOD_INVALID)
              printf("Invalid\n");
            if (op->mem.modify == TMS320C64X_MEM_MOD_NO)
              printf("No\n");
            if (op->mem.modify == TMS320C64X_MEM_MOD_PRE)
              printf("Pre\n");
            if (op->mem.modify == TMS320C64X_MEM_MOD_POST)
              printf("Post\n");
            printf("\t\t\toperands[%u].mem.scaled: %u\n", i, op->mem.scaled);

            break;
          case TMS320C64X_OP_REGPAIR:
            printf("\t\toperands[%u].type: REGPAIR = %s:%s(%d)\n", i,
                   cs_reg_name(tms320c64xhandle, op->reg + 1),
                   cs_reg_name(tms320c64xhandle, op->reg), op->reg);
            break;
          }
        }
        printf("\n\n");
      }
    }

    static const char *s_access[] = {
        "UNCHANGED",
        "READ",
        "WRITE",
        "READ | WRITE",
    };
    csh m680xhandle;
    cs_insn *m680xinsn;
    size_t m680xcount;

    if (cs_open(CS_ARCH_M680X, CS_MODE_M680X_CPU12, &m680xhandle) != CS_ERR_OK)
      return -1;
    cs_option(m680xhandle, CS_OPT_DETAIL, CS_OPT_ON);
    m680xcount = cs_disasm(m680xhandle, (uint8_t *)CPU12, sizeof(CPU12) - 1,
                           0x1000, 0, &m680xinsn);
    if (m680xcount > 0) {
      size_t j;

      printf("\x1b[31mm680x\x1b[0m\n");
      for (j = 0; j < m680xcount; j++) {
        cs_detail *detail = m680xinsn[j].detail;
        printf("regs_read_count: %d\n", detail->regs_read_count);
        printf("count: %d\n", m680xcount);
        printf("flags: %d\n", detail->m680x.flags);
        cs_m680x *m680x = &(detail->m680x);
        for (int i = 0; i < m680x->op_count; i++) {
          cs_m680x_op *op = &(m680x->operands[i]);
          const char *comment;

          switch ((int)op->type) {
          default:
            break;

          case M680X_OP_REGISTER:
            comment = "";

            if ((i == 0 && (m680x->flags & M680X_FIRST_OP_IN_MNEM)) ||
                ((i == 1 && (m680x->flags & M680X_SECOND_OP_IN_MNEM))))
              comment = " (in mnemonic)";

            printf("\t\toperands[%u].type: REGISTER = %s%s(%d)\n", i,
                   cs_reg_name(m680xhandle, op->reg), comment, op->reg);
            break;

          case M680X_OP_CONSTANT:
            printf("\t\toperands[%u].type: CONSTANT = %u(%d)\n", i,
  op->const_val, op->const_val); break;

          case M680X_OP_IMMEDIATE:
            printf("\t\toperands[%u].type: IMMEDIATE = #%d(%d)\n", i, op->imm,
                   op->imm);
            break;

          case M680X_OP_DIRECT:
            printf("\t\toperands[%u].type: DIRECT = 0x%02x(%d)\n", i,
                   op->direct_addr, op->direct_addr);
            break;

          case M680X_OP_EXTENDED:
            printf("\t\toperands[%u].type: EXTENDED %s = 0x%04x(%d)\n", i,
                   op->ext.indirect ? "true" : "false", op->ext.address,
                   op->ext.address);
            break;

          case M680X_OP_RELATIVE:
            printf("\t\toperands[%u].type: RELATIVE addr = 0x%04x(%d)\n", i,
                   op->rel.address, op->rel.address);
            printf("\t\toperands[%u].type: RELATIVE offset = %d\n", i,
                   op->rel.offset);
            break;

          case M680X_OP_INDEXED:
            printf("base_reg: %d\n", op->idx.base_reg);
            printf("offset_reg: %d\n", op->idx.offset_reg);
            printf("offset: %d\n", op->idx.offset);
            printf("offset_addr: %d\n", op->idx.offset_addr);
            printf("offset_bits: %d\n", op->idx.offset_bits);
            printf("inc_dec: %d\n", op->idx.inc_dec);
            printf("flags: %d\n", op->idx.flags);
            printf("\t\toperands[%u].type: INDEXED%s\n", i,
                   (op->idx.flags & M680X_IDX_INDIRECT) ? " INDIRECT" : "");

            if (op->idx.base_reg != M680X_REG_INVALID)
              printf("\t\t\tbase register: %s\n",
                     cs_reg_name(m680xhandle, op->idx.base_reg));

            if (op->idx.offset_reg != M680X_REG_INVALID)
              printf("\t\t\toffset register: %s\n",
                     cs_reg_name(m680xhandle, op->idx.offset_reg));

            if ((op->idx.offset_bits != 0) &&
                (op->idx.offset_reg == M680X_REG_INVALID) && !op->idx.inc_dec) {
              printf("\t\t\toffset: %d\n", op->idx.offset);

              if (op->idx.base_reg == M680X_REG_PC)
                printf("\t\t\toffset address: 0x%x\n", op->idx.offset_addr);

              printf("\t\t\toffset bits: %u\n", op->idx.offset_bits);
            }

            if (op->idx.inc_dec) {
              const char *post_pre =
                  op->idx.flags & M680X_IDX_POST_INC_DEC ? "post" : "pre";
              const char *inc_dec =
                  (op->idx.inc_dec > 0) ? "increment" : "decrement";

              printf("\t\t\t%s %s: %d\n", post_pre, inc_dec,
                     abs(op->idx.inc_dec));
            }

            break;
          }

          if (op->size != 0)
            printf("\t\t\tsize: %u\n", op->size);

          if (op->access != CS_AC_INVALID)
            printf("\t\t\taccess: %s(%d)\n", s_access[op->access], op->access);
        }
        printf("\n\n");
      }
    }

    csh evmhandle;
    cs_insn *evminsn;
    size_t evmcount;

    if (cs_open(CS_ARCH_EVM, 0, &evmhandle) != CS_ERR_OK)
      return -1;
    cs_option(evmhandle, CS_OPT_DETAIL, CS_OPT_ON);
    evmcount = cs_disasm(evmhandle, (uint8_t *)EVM, sizeof(EVM) - 1, 0x1000, 0,
                         &evminsn);
    if (evmcount > 0) {
      size_t j;

      printf("\x1b[31mevm\x1b[0m\n");
      for (j = 0; j < evmcount; j++) {
        cs_detail *detail = evminsn[j].detail;
        printf("regs_read_count: %d\n", detail->regs_read_count);
        cs_evm *evm = &(detail->evm);
        printf("\tPop:     %u\n", evm->pop);
        printf("\tPush:    %u\n", evm->push);
        printf("\tGas fee: %u\n", evm->fee);
        printf("\n\n");
      }
    }

    csh mos65xxhandle;
    cs_insn *mos65xxinsn;
    size_t mos65xxcount;

    if (cs_open(CS_ARCH_MOS65XX, CS_MODE_MOS65XX_W65C02, &mos65xxhandle) !=
        CS_ERR_OK)
      return -1;
    cs_option(mos65xxhandle, CS_OPT_DETAIL, CS_OPT_ON);
    mos65xxcount = cs_disasm(mos65xxhandle, (uint8_t *)MW65C02,
                             sizeof(MW65C02) - 1, 0x1000, 0, &mos65xxinsn);
    if (mos65xxcount > 0) {
      size_t j;

      printf("\x1b[31mmos65xx\x1b[0m\n");
      for (j = 0; j < mos65xxcount; j++) {
        cs_detail *detail = mos65xxinsn[j].detail;
        printf("op distance: %d\n",
               ((char *)&detail->mos65xx.operands - (char *)&detail->mos65xx));
        printf("op size: %d\n", sizeof(cs_mos65xx_op));
        printf("modifies_flags: %s\n",
               (detail->mos65xx.modifies_flags == 1) ? "true" : "false");
        printf("am: %d\n", detail->mos65xx.am);
        for (int i = 0; i < detail->mos65xx.op_count; i++) {
          cs_mos65xx_op *op = &(detail->mos65xx.operands[i]);
          printf("op_type: %d\n", op->type);
          switch ((int)op->type) {
          default:
            break;
          case MOS65XX_OP_REG:
            printf("\t\toperands[%u].type: REG = %s(%d)\n", i,
                   cs_reg_name(mos65xxhandle, op->reg), op->reg);
            break;
          case MOS65XX_OP_IMM:
            printf("\t\toperands[%u].type: IMM = 0x%x(%d)\n", i, op->imm,
                   op->imm);
            break;
          case MOS65XX_OP_MEM:
            printf("\t\toperands[%u].type: MEM = 0x%x(%d)\n", i, op->mem,
                   op->mem);
            break;
          }
        }
        printf("\n\n");
      }
    }

    csh wasmhandle;
    cs_insn *wasminsn;
    size_t wasmcount;

    if (cs_open(CS_ARCH_WASM, 0, &wasmhandle) != CS_ERR_OK)
      return -1;
    cs_option(wasmhandle, CS_OPT_DETAIL, CS_OPT_ON);
    wasmcount = cs_disasm(wasmhandle, (uint8_t *)WASM, sizeof(WASM) - 1, 0x1000,
                          0, &wasminsn);
    if (wasmcount > 0) {
      size_t j;

      printf("\x1b[31mwasm\x1b[0m\n");
      for (j = 0; j < wasmcount; j++) {
        printf("%s %s\n", wasminsn[j].mnemonic, wasminsn[j].op_str);
        cs_detail *detail = wasminsn[j].detail;
        printf("op distance: %d\n",
               ((char *)&detail->wasm.operands - (char *)&detail->wasm));
        printf("op_count: %d\n", detail->wasm.op_count);
        if (detail->wasm.op_count > 0) {
          printf("op_type: %d\n", detail->wasm.operands[0].type);
          printf("varuint32: %d\n", detail->wasm.operands[0].varuint32);
        }
        printf("op size: %d\n", sizeof(cs_wasm_op));
        printf("\n\n");
      }
    }

    static const char *ext_name[] = {
        [BPF_EXT_LEN] = "#len",
    };

    csh bpfhandle;
    cs_insn *bpfinsn;
    size_t bpfcount;

    if (cs_open(CS_ARCH_BPF, CS_MODE_BPF_EXTENDED, &bpfhandle) != CS_ERR_OK)
      return -1;
    cs_option(bpfhandle, CS_OPT_DETAIL, CS_OPT_ON);
    bpfcount = cs_disasm(bpfhandle, (uint8_t *)EBPF, sizeof(EBPF) - 1, 0x1000,
  0, &bpfinsn); if (bpfcount > 0) { size_t j;

      printf("\x1b[31mbpf\x1b[0m\n");
      for (j = 0; j < bpfcount; j++) {
        cs_detail *detail = bpfinsn[j].detail;
        printf("op distance: %d\n",
               ((char *)&detail->bpf.operands - (char *)&detail->bpf));
        printf("op size: %d\n", sizeof(cs_bpf_op));
        printf("op_count %d\n", detail->bpf.op_count);
        for (int i = 0; i < detail->bpf.op_count; i++) {
          cs_bpf_op *op = &(detail->bpf.operands[i]);
          printf("op_type: %d\n", op->type);
          printf("access: %d\n", op->access);
          switch (op->type) {
          case BPF_OP_INVALID:
            printf("INVALID\n");
            break;
          case BPF_OP_REG:
            printf("REG = %s(%d)\n", cs_reg_name(bpfhandle, op->reg), op->reg);
            break;
          case BPF_OP_IMM:
            printf("IMM = 0x%" PRIx64 "(%d)\n", op->imm, op->imm);
            break;
          case BPF_OP_OFF:
            printf("OFF = +0x%x(%d)\n", op->off, op->off);
            break;
          case BPF_OP_MEM:
            printf("MEM\n");
            if (op->mem.base != BPF_REG_INVALID)
              printf("\t\t\toperands[%u].mem.base: REG = %s(%d)\n", i,
                     cs_reg_name(bpfhandle, op->mem.base), op->mem.base);
            printf("\t\t\toperands[%u].mem.disp: 0x%x(%d)\n", i, op->mem.disp,
                   op->mem.disp);
            break;
          case BPF_OP_MMEM:
            printf("MMEM = M[0x%x](%d)\n", op->mmem, op->mmem);
            break;
          case BPF_OP_MSH:
            printf("MSH = 4*([0x%x]&0xf)(%d)\n", op->msh, op->msh);
            break;
          case BPF_OP_EXT:
            printf("EXT = %s(%d)\n", ext_name[op->ext], op->ext);
            break;
          }
        }
        printf("\n\n");
      }
    }
    csh riscvhandle;
    cs_insn *riscvinsn;
    size_t riscvcount;

    if (cs_open(CS_ARCH_RISCV, CS_MODE_RISCV32, &riscvhandle) != CS_ERR_OK)
      return -1;
    cs_option(riscvhandle, CS_OPT_DETAIL, CS_OPT_ON);
    riscvcount = cs_disasm(riscvhandle, (uint8_t *)RISCV, sizeof(RISCV) - 1,
                           0x1000, 0, &riscvinsn);
    if (riscvcount > 0) {
      size_t j;

      printf("\x1b[31mriscv\x1b[0m\n");
      for (j = 0; j < riscvcount; j++) {
        cs_detail *detail = riscvinsn[j].detail;
        printf("op distance: %d\n",
               ((char *)&detail->riscv.operands - (char *)&detail->riscv));
        printf("op size: %d\n", sizeof(cs_riscv_op));
        printf("op_count: %d\n", detail->riscv.op_count);
        printf("need_effective_addr: %s\n",
               (detail->riscv.need_effective_addr == 1) ? "true" : "false");
        for (int i = 0; i < detail->riscv.op_count; i++) {
          cs_riscv_op *op = &(detail->riscv.operands[i]);
          printf("op_type: %d\n", op->type);
          switch ((int)op->type) {
          default:
            printf("\terror in opt_type: %u\n", (int)op->type);
            break;
          case RISCV_OP_REG:
            printf("\t\toperands[%u].type: REG = %s(%d)\n", i,
                   cs_reg_name(riscvhandle, op->reg), op->reg);
            break;
          case RISCV_OP_IMM:
            printf("\t\toperands[%u].type: IMM = 0x%" PRIx64 "(%d)\n", i,
  op->imm, op->imm); break; case RISCV_OP_MEM: printf("\t\toperands[%u].type:
  MEM\n", i); if (op->mem.base != RISCV_REG_INVALID)
              printf("\t\t\toperands[%u].mem.base: REG = %s(%d)\n", i,
                     cs_reg_name(riscvhandle, op->mem.base), op->mem.base);
            if (op->mem.disp != 0)
              printf("\t\t\toperands[%u].mem.disp: 0x%" PRIx64 "(%d)\n", i,
                     op->mem.disp, op->mem.disp);

            break;
          }
        }
        printf("\n\n");
      }
    }
    csh shhandle;
    cs_insn *shinsn;
    size_t shcount;

    if (cs_open(CS_ARCH_SH, CS_MODE_SH2A, &shhandle) != CS_ERR_OK)
      return -1;
    cs_option(shhandle, CS_OPT_DETAIL, CS_OPT_ON);
    shcount = cs_disasm(shhandle, (uint8_t *)SH2A, sizeof(SH2A) - 1, 0x1000, 0,
                        &shinsn);
    if (shcount > 0) {
      size_t j;

      printf("\x1b[31msh\x1b[0m\n");
      for (j = 0; j < shcount; j++) {
        cs_detail *detail = shinsn[j].detail;
        printf("op distance: %d\n",
               ((char *)&detail->sh.operands - (char *)&detail->sh));
        printf("op size: %d\n", sizeof(cs_sh_op));
        printf("imm distance(%d): %d\n", sizeof(detail->sh.operands[0].imm),
               (char *)&detail->sh.operands[0].imm -
                   (char *)&detail->sh.operands[0]);
        printf("reg distance(%d): %d\n", sizeof(detail->sh.operands[0].reg),
               (char *)&detail->sh.operands[0].reg -
                   (char *)&detail->sh.operands[0]);
        printf("mem.address distance(%d): %d\n",
               sizeof(detail->sh.operands[0].mem.address),
               (char *)&detail->sh.operands[0].mem.address -
                   (char *)&detail->sh.operands[0]);
        printf("mem.reg distance(%d): %d\n",
               sizeof(detail->sh.operands[0].mem.reg),
               (char *)&detail->sh.operands[0].mem.reg -
                   (char *)&detail->sh.operands[0]);
        printf("mem.disp distance(%d): %d\n",
               sizeof(detail->sh.operands[0].mem.disp),
               (char *)&detail->sh.operands[0].mem.disp -
                   (char *)&detail->sh.operands[0]);
        printf("op_count: %d\n", detail->sh.op_count);
        printf("\n\n");
      }
    }

    csh tricorehandle;
    cs_insn *tricoreinsn;
    size_t tricorecount;

    if (cs_open(CS_ARCH_TRICORE, CS_MODE_TRICORE_162, &tricorehandle) !=
        CS_ERR_OK)
      return -1;
    cs_option(tricorehandle, CS_OPT_DETAIL, CS_OPT_ON);
    tricorecount = cs_disasm(tricorehandle, (uint8_t *)TRICORE,
                             sizeof(TRICORE) - 1, 0x1000, 0, &tricoreinsn);
    if (tricorecount > 0) {
      size_t j;

      printf("\x1b[31mtricore\x1b[0m\n");
      for (j = 0; j < tricorecount; j++) {
        cs_detail *detail = tricoreinsn[j].detail;
        printf("op distance: %d\n",
               ((char *)&detail->tricore.operands - (char *)&detail->tricore));
        printf("op size: %d\n", sizeof(cs_tricore_op));
        printf("detail size: %d\n", sizeof(cs_detail));
        for (int i = 0; i < detail->tricore.op_count; i++) {
          cs_tricore_op *op = &(detail->tricore.operands[i]);
          switch ((int)op->type) {
          default:
            break;
          case TRICORE_OP_REG:
            printf("\t\toperands[%u].type: REG = %s(%d)\n", i,
                   cs_reg_name(tricorehandle, op->reg), op->reg);
            break;
          case TRICORE_OP_IMM:
            printf("\t\toperands[%u].type: IMM = 0x%x(%d)\n", i, op->imm,
                   op->imm);
            break;
          case TRICORE_OP_MEM:
            printf("\t\toperands[%u].type: MEM\n", i);
            if (op->mem.base != TRICORE_REG_INVALID)
              printf("\t\t\toperands[%u].mem.base: REG = %s(%d)\n", i,
                     cs_reg_name(tricorehandle, op->mem.base), op->mem.base);
            if (op->mem.disp != 0)
              printf("\t\t\toperands[%u].mem.disp: 0x%x(%d)\n", i, op->mem.disp,
                     op->mem.disp);

            break;
          }
        }
        printf("op_count: %d\n", detail->tricore.op_count);
        if (detail->tricore.op_count > 0) {
          printf("op_type: %d\n", detail->tricore.operands[0].type);
        }
        printf("update_flags offset: %d\n",
               (char *)&detail->tricore.update_flags - (char
  *)&detail->tricore); printf("\n\n");
      }
    }

    cs_close(&mipshandle);
    cs_close(&arm64handle);
    cs_close(&armhandle);
    cs_close(&ppchandle);
    cs_close(&sparchandle);
    cs_close(&syszhandle);
    cs_close(&riscvhandle);
    cs_close(&shhandle);
    cs_close(&tricorehandle);
    cs_close(&bpfhandle);
    cs_close(&wasmhandle);
    cs_close(&mos65xxhandle);
    cs_close(&evmhandle);
    cs_close(&m680xhandle);
    cs_close(&tms320c64xhandle);
    cs_close(&xcorehandle);
    cs_close(&m68khandle);
    cs_close(&x86handle);*/
  return 0;
}
