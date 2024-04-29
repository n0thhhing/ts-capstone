#ifdef __cplusplus
extern "C" {
#endif

#include "../capstone/include/capstone/capstone.h"

unsigned long long cs_insn_offset(const cs_insn *insns, size_t post) {
    return CS_INSN_OFFSET(insns, post);
}

unsigned long long x86_rel_addr(cs_insn *insn) {
    return X86_REL_ADDR(*insn);
}

#ifdef __cplusplus
}
#endif
