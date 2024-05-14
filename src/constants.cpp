#include <emscripten/bind.h>
#include <stddef.h>
#include "../capstone/include/capstone/capstone.h"

using namespace emscripten;

// cs_insn
int INSN_SIZE = sizeof(cs_insn);
int INSN_ID_OFFSET = offsetof(cs_insn, id);
int INSN_ADDR_OFFSET = offsetof(cs_insn, address);
int INSN_SIZE_OFFSET = offsetof(cs_insn, size);
int INSN_MNEMONIC_OFFSET = offsetof(cs_insn, mnemonic);
int INSN_OP_STR = offsetof(cs_insn, op_str);
int INSN_BYTES_OFFSET = offsetof(cs_insn, bytes);
int INSN_DETAIL_OFFSET = offsetof(cs_insn, detail);

// cs_detail
int DETAIL_SIZE = sizeof(cs_detail);
int DETAIL_REGS_READ_OFFSET = offsetof(cs_detail, regs_read);
int DETAIL_REGS_READ_COUNT_OFFSET = offsetof(cs_detail, regs_read_count);
int DETAIL_REGS_WRITE_OFFSET = offsetof(cs_detail, regs_write);
int DETAIL_REGS_WRITE_COUNT_OFFSET = offsetof(cs_detail, regs_write_count);
int DETAIL_GROUPS_OFFSET = offsetof(cs_detail, groups);
int DETAIL_GROUPS_COUNT_OFFSET = offsetof(cs_detail, groups_count);
int DETAIL_WRITEBACK_OFFSET = offsetof(cs_detail, writeback);
int DETAIL_ARCH_INFO_OFFSET = offsetof(cs_detail, x86);

// cs_arm
int ARM_SIZE = sizeof(cs_arm);
int ARM_USERMODE_OFFSET = offsetof(cs_arm, usermode);
int ARM_VECTOR_SIZE_OFFSET = offsetof(cs_arm, vector_size);

EMSCRIPTEN_BINDINGS(constants) {
  constant("INSN_SIZE", INSN_SIZE);
  constant("INSN_ID_OFFSET", INSN_ID_OFFSET);
  constant("INSN_ADDR_OFFSET", INSN_ADDR_OFFSET);
  constant("INSN_SIZE_OFFSET", INSN_SIZE_OFFSET);
  constant("INSN_MNEMONIC_OFFSET", INSN_MNEMONIC_OFFSET);
  constant("INSN_OP_STR", INSN_OP_STR);
  constant("INSN_BYTES_OFFSET", INSN_BYTES_OFFSET);
  constant("INSN_DETAIL_OFFSET", INSN_DETAIL_OFFSET);

  constant("DETAIL_SIZE", DETAIL_SIZE);
  constant("DETAIL_REGS_READ_OFFSET", DETAIL_REGS_READ_OFFSET);
  constant("DETAIL_REGS_READ_COUNT_OFFSET", DETAIL_REGS_READ_COUNT_OFFSET);
  constant("DETAIL_REGS_WRITE_OFFSET", DETAIL_REGS_WRITE_OFFSET);
  constant("DETAIL_REGS_WRITE_COUNT_OFFSET", DETAIL_REGS_WRITE_COUNT_OFFSET);
  constant("DETAIL_GROUPS_OFFSET", DETAIL_GROUPS_OFFSET);
  constant("DETAIL_GROUPS_COUNT_OFFSET", DETAIL_GROUPS_COUNT_OFFSET);
  constant("DETAIL_WRITEBACK_OFFSET", DETAIL_WRITEBACK_OFFSET);
  constant("DETAIL_ARCH_INFO_OFFSET", DETAIL_ARCH_INFO_OFFSET);
}