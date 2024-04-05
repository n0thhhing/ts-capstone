#include <stdio.h>
#include <inttypes.h>

#include "../../capstone/include/capstone/capstone.h"
//#include <capstone/capstone.h>
#define X86 "\x55\x48\x8b\x05\xb8\x13\x00\x00"
#define M68K "\x48\x32\x12\x34\x56\x78\xD2\x2A\xAB\xCD\x54\x03\x00\x00\x4C\x38\x00\x01\x4C\x0A\x00\x02\xD0\x2C\x4C\x0C\x00\x04\xD0\x2C\x4C\xFE\x00\x00\x00\x00\x12\x34\x56\x78\x32\x60\x4E\x00\x00\x11\x32\x61\x4E\x00\x00\x11\x32\x62\x4E\x00\x00\x11\xD3\xC0\x4C\x07\x00\x11\xD4\xC0\x4C\x06\x00\x11\xD5\xC0\x4C\x05\x00\x11\xD6\xC0\x4C\x04\x00\x11\xD7\xC0\x4C\x03\x00\x11\x42\x00\x4E\x71\x42\x41\x4E\x71\x42\x42\x4E\x71\x46\x00\x4E\x71\x46\x01\x4E\x71\x46\x02\x46\x03\x4E\x71\x46\x04\x4E\x71\x46\x05\x4E\x71\x46\x06\x4E\x71"
#define WASM "\x01\x00\x4D\x44\x01\x00\xF9\x44\x01\x00\x51\x44\x01\x00\xFB\x44\x01\x00\x55\x44\x01\x00\xFD\x44\x01\x00\x59\x44\x01\x00\xFF\x44\x01\x00\x01\x45\x00\x00\x00\x00\x01\x00\x03\x45\x00\x00\x00\x00\x01\x00\x05\x45\x01\x00\x07\x45\x01\x00\x09\x45\x01\x00\x0B\x45\x00\x41\x80\xA7\xE2\x01\x0B\x0C\x01\x00\x0D\x45\x00\x00\x00\x00\x01\x00\x0F\x45\x00\x41\xA0\xA7\xE2\x01\x0B\x08\x01\x00\x11\x45\x01\x00\x13\x45\x00\x41\xB4\xA7\xE2\x01\x0B\x0C\x01\x00\x15\x45\x01\x00\x17\x45\x01\x00\x19\x45\x00\x41\xD8\xA7\xE2\x01\x0B\x14\x01\x00\x1B\x45\x01\x00\x1D\x45\x01\x00\x1F\x45\x01\x00\x21\x45\x01\x00\x23\x45\x00\x41\x90\xA8"
int main(void) {
    csh x86handle;
    cs_insn *x86insn;
    size_t x86count;
    
    if (cs_open(CS_ARCH_X86, CS_MODE_64, &x86handle) != CS_ERR_OK)
        return -1;
    cs_option(x86handle, CS_OPT_DETAIL, CS_OPT_ON);
    x86count = cs_disasm(x86handle, (uint8_t *)X86, sizeof(X86) - 1, 0x1000, 0, &x86insn);

    if (x86count > 0) {
        size_t j;
        
            printf("x86\n");
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
    
    csh m68khandle;
    cs_insn *m68kinsn;
    size_t m68kcount;
    
    if (cs_open(CS_ARCH_M68K, CS_MODE_M68K_020, &m68khandle) != CS_ERR_OK)
        return -1;
    cs_option(m68khandle, CS_OPT_DETAIL, CS_OPT_ON);
    m68kcount = cs_disasm(m68khandle, (uint8_t *)M68K, sizeof(M68K) - 1, 0x1000, 0, &m68kinsn);
    if (m68kcount > 0) {
        size_t j;
        
            printf("m68k\n");
        for (j = 0; j < m68kcount; j++) {
            cs_detail *detail = m68kinsn[j].detail;
            printf("distance: %ld %d\n", ((char *)&detail->m68k.op_size - (char *)&detail->m68k) / 4, CS_MODE_M68K_020);
            printf("regs_read_count: %d\n", detail->regs_read_count);
            printf("op_type: %d\n", detail->m68k.operands[0].type);
            printf("op_count: %d\n", detail->m68k.op_count);
            printf("op_size type: %d\n", detail->m68k.op_size.type);
            printf("cpu_size: %d\n", detail->m68k.op_size.cpu_size);
            printf("\n\n");
        }
    }
    
    csh mos65xxhandle;
    cs_insn *mos65xxinsn;
    size_t mos65xxcount;
    
    if (cs_open(CS_ARCH_MOS65XX, CS_MODE_MOS65XX_6502, &mos65xxhandle) != CS_ERR_OK)
        return -1;
    cs_option(mos65xxhandle, CS_OPT_DETAIL, CS_OPT_ON);
    mos65xxcount = cs_disasm(mos65xxhandle, (uint8_t *)M68K, sizeof(M68K) - 1, 0x1000, 0, &mos65xxinsn);
    if (mos65xxcount > 0) {
        size_t j;
        
            printf("mos65xx\n");
        for (j = 0; j < mos65xxcount; j++) {
            cs_detail *detail = mos65xxinsn[j].detail;
            printf("op distance: %d\n", ((char *)&detail->mos65xx.operands - (char *)&detail->mos65xx));
            printf("op size: %d\n", sizeof(cs_mos65xx_op));
            printf("\n\n");
        }
    }
    
    csh wasmhandle;
    cs_insn *wasminsn;
    size_t wasmcount;
    
    if (cs_open(CS_ARCH_MOS65XX, CS_MODE_MOS65XX_6502, &wasmhandle) != CS_ERR_OK)
        return -1;
    cs_option(wasmhandle, CS_OPT_DETAIL, CS_OPT_ON);
    wasmcount = cs_disasm(wasmhandle, (uint8_t *)WASM, sizeof(WASM) - 1, 0x1000, 0, &wasminsn);
    if (wasmcount > 0) {
        size_t j;
        
            printf("wasm\n");
        for (j = 0; j < wasmcount; j++) {
            printf("%s %s\n", wasminsn[j].mnemonic, wasminsn[j].op_str);
            cs_detail *detail = wasminsn[j].detail;
            printf("op distance: %d\n", ((char *)&detail->wasm.operands - (char *)&detail->wasm));
            printf("op size: %d\n", sizeof(cs_wasm_op));
            printf("\n\n");
        }
    }
    
    csh bpfhandle;
    cs_insn *bpfinsn;
    size_t bpfcount;
    
    if (cs_open(CS_ARCH_BPF, CS_MODE_BPF_CLASSIC, &bpfhandle) != CS_ERR_OK)
        return -1;
    cs_option(bpfhandle, CS_OPT_DETAIL, CS_OPT_ON);
    bpfcount = cs_disasm(bpfhandle, (uint8_t *)M68K, sizeof(M68K) - 1, 0x1000, 0, &bpfinsn);
    if (bpfcount > 0) {
        size_t j;
        
            printf("bpf\n");
        for (j = 0; j < bpfcount; j++) {
            cs_detail *detail = bpfinsn[j].detail;
            printf("op distance: %d\n", ((char *)&detail->bpf.operands - (char *)&detail->bpf));
            printf("op size: %d\n", sizeof(cs_bpf_op));
            printf("\n\n");
        }
    }
    cs_close(&wasmhandle);
    cs_close(&mos65xxhandle);
    cs_close(&x86handle);
    cs_close(&m68khandle);
    return 0;
}
