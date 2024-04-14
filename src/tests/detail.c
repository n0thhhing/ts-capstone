#include <stdio.h>

#include "../../capstone/include/capstone/capstone.h"

#define X86 "\x55\x48\x8b\x05\xb8\x13\x00\x00"
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
  "\x97\x09\x00\x00\x37\x13\x03\x00"                                           \
  "\xdc\x02\x00\x00\x20\x00\x00\x00"                                           \
  "\x30\x00\x00\x00\x00\x00\x00\x00"                                           \
  "\xdb\x3a\x00\x01\x00\x00\x00\x00"                                           \
  "\x84\x02\x00\x00\x00\x00\x00\x00"                                           \
  "\x6d\x33\x17\x02\x00\x00\x00\x00"
#define MW65C02                                                                \
  "\x07\x12\x27\x12\x47\x12\x67\x12\x87\x12\xa7\x12\xc7\x12\xe7\x12"           \
  "\x10\xfe\x0f\x12\xfd\x4f\x12\xfd\x8f\x12\xfd\xcf\x12\xfd"
#define EVM "\x60\x61\x50"
#define TMS320C64X                                                             \
  "\x01\xac\x88\x40\x81\xac\x88\x43\x00\x00\x00\x00\x02\x90\x32\x96\x02\x80"   \
  "\x46\x9e\x05\x3c\x83\xe6\x0b\x0c\x8b\x24"

int main(void) {
  csh x86handle;
  cs_insn *x86insn;
  size_t x86count;

  if (cs_open(CS_ARCH_X86, CS_MODE_64, &x86handle) != CS_ERR_OK)
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
      printf("disp: %d\n", x86->disp);
      printf("sib_index: %d\n", x86->sib_index);
      printf("sib_scale: %d\n", x86->sib_scale);
      printf("sib_base: %d\n", x86->sib_base);
      printf("xop_cc: %d\n", x86->xop_cc);
      printf("sse_cc: %d\n", x86->sse_cc);
      printf("avx_cc: %d\n", x86->avx_cc);
      printf("avx_sae: %s\n", x86->avx_sae ? "true" : "false");
      printf("avx_rm: %d\n", x86->avx_rm);
      printf("eflags: %d\n\n", x86->eflags);

      cs_x86_encoding encoding = x86->encoding;
      printf("cs_x86_encoding:\n");
      printf("modrm_offset: %d\n", encoding.modrm_offset);
      printf("disp_offset: %d\n", encoding.disp_offset);
      printf("disp_size: %d\n", encoding.disp_size);
      printf("imm_offset: %d\n", encoding.imm_offset);
      printf("imm_size: %d\n", encoding.imm_size);
      printf("\n\n");
    }
    cs_free(x86insn, x86count);
  } else {
    printf("ERROR: Failed to disassemble given code!\n");
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
                   cs_reg_name(m68khandle, op->mem.base_reg), op->mem.base_reg);
          if (op->mem.index_reg != M68K_REG_INVALID) {
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

  csh tms320c64xhandle;
  cs_insn *tms320c64xinsn;
  size_t tms320c64xcount;

  if (cs_open(CS_ARCH_TMS320C64X, CS_MODE_BIG_ENDIAN, &tms320c64xhandle) !=
      CS_ERR_OK)
    return -1;
  cs_option(tms320c64xhandle, CS_OPT_DETAIL, CS_OPT_ON);
  tms320c64xcount =
      cs_disasm(tms320c64xhandle, (uint8_t *)TMS320C64X, sizeof(TMS320C64X) - 1,
                0x1000, 0, &tms320c64xinsn);
  if (tms320c64xcount > 0) {
    size_t j;

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
          printf("\t\t\toperands[%u].mem.disptype(%d): ", i, op->mem.disptype);
          if (op->mem.disptype == TMS320C64X_MEM_DISP_INVALID) {
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
  bpfcount = cs_disasm(bpfhandle, (uint8_t *)EBPF, sizeof(EBPF) - 1, 0x1000, 0,
                       &bpfinsn);
  if (bpfcount > 0) {
    size_t j;

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
          printf("\t\toperands[%u].type: IMM = 0x%" PRIx64 "(%d)\n", i, op->imm,
                 op->imm);
          break;
        case RISCV_OP_MEM:
          printf("\t\toperands[%u].type: MEM\n", i);
          if (op->mem.base != RISCV_REG_INVALID)
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
             (char *)&detail->tricore.update_flags - (char *)&detail->tricore);
      printf("\n\n");
    }
  }

  cs_close(&riscvhandle);
  cs_close(&bpfhandle);
  cs_close(&shhandle);
  cs_close(&tricorehandle);
  cs_close(&wasmhandle);
  cs_close(&mos65xxhandle);
  cs_close(&x86handle);
  cs_close(&m68khandle);
  return 0;
}
