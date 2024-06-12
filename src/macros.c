#ifdef __cplusplus
extern "C" {
#endif

#include "../capstone/include/capstone/capstone.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

uint8_t* cs_insn_buffer(cs_insn *insn) {
    uint8_t *buf = (uint8_t *)malloc(sizeof(cs_insn));
    if (buf != NULL) {
        memcpy(buf, insn, sizeof(cs_insn));
    }
    return buf;
}

uint8_t* cs_detail_buffer(cs_insn *insn) {
    uint8_t *buf = NULL;
    if (insn->detail != NULL) {
        buf = (uint8_t *)malloc(sizeof(cs_detail));
        if (buf != NULL) {
            memcpy(buf, insn->detail, sizeof(cs_detail));
        }
    }
    return buf;
}

#ifdef __cplusplus
}
#endif