#include <emscripten/bind.h>
#include <stddef.h>
#include "../capstone/include/capstone/capstone.h"

using namespace emscripten;

int INSN_ID_OFFSET = offsetof(cs_insn, id);
int INSN_ADDR_OFFSET = offsetof(cs_insn, address);
int INSN_SIZE_OFFSET = offsetof(cs_insn, size);
int INSN_MNEMONIC_OFFSET = offsetof(cs_insn, mnemonic);
int INSN_OP_STR = offsetof(cs_insn, op_str);
int INSN_BYTES_OFFSET = offsetof(cs_insn, bytes);
int INSN_DETAIL_OFFSET = offsetof(cs_insn, detail);

int DETAIL_REGS_READ_OFFSET = offsetof(cs_detail, regs_read);

EMSCRIPTEN_BINDINGS(constants) {
  constant("INSN_ID_OFFSET", INSN_ID_OFFSET);
  constant("INSN_ADDR_OFFSET", INSN_ADDR_OFFSET);
  constant("INSN_SIZE_OFFSET", INSN_SIZE_OFFSET);
  constant("INSN_MNEMONIC_OFFSET", INSN_MNEMONIC_OFFSET);
  constant("INSN_OP_STR", INSN_OP_STR);
  constant("INSN_BYTES_OFFSET", INSN_BYTES_OFFSET);
  constant("INSN_DETAIL_OFFSET", INSN_DETAIL_OFFSET);
}