#include <emscripten/bind.h>
#include <stddef.h>
#include "../capstone/include/capstone/capstone.h"

using namespace emscripten;

 // cs_insn
const int INSN_SIZE = sizeof(cs_insn);
const int INSN_ID_OFFSET = offsetof(cs_insn, id);
const int INSN_ADDR_OFFSET = offsetof(cs_insn, address);
const int INSN_SIZE_OFFSET = offsetof(cs_insn, size);
const int INSN_MNEMONIC_OFFSET = offsetof(cs_insn, mnemonic);
const int INSN_OP_STR = offsetof(cs_insn, op_str);
const int INSN_BYTES_OFFSET = offsetof(cs_insn, bytes);
const int INSN_DETAIL_OFFSET = offsetof(cs_insn, detail);

 // cs_detail
const int DETAIL_SIZE = sizeof(cs_detail);
const int DETAIL_REGS_READ_OFFSET = offsetof(cs_detail, regs_read);
const int DETAIL_REGS_READ_COUNT_OFFSET = offsetof(cs_detail, regs_read_count);
const int DETAIL_REGS_WRITE_OFFSET = offsetof(cs_detail, regs_write);
const int DETAIL_REGS_WRITE_COUNT_OFFSET = offsetof(cs_detail, regs_write_count);
const int DETAIL_GROUPS_OFFSET = offsetof(cs_detail, groups);
const int DETAIL_GROUPS_COUNT_OFFSET = offsetof(cs_detail, groups_count);
const int DETAIL_WRITEBACK_OFFSET = offsetof(cs_detail, writeback);
const int DETAIL_ARCH_INFO_OFFSET = offsetof(cs_detail, x86);

 // cs_arm
const int ARM_SIZE = sizeof(cs_arm);
const int ARM_USERMODE_OFFSET = offsetof(cs_arm, usermode);
const int ARM_VECTOR_SIZE_OFFSET = offsetof(cs_arm, vector_size);
const int ARM_VECTOR_DATA_OFFSET = offsetof(cs_arm, vector_data);
const int ARM_CPS_MODE_OFFSET = offsetof(cs_arm, cps_mode);
const int ARM_CPS_FLAG_OFFSET = offsetof(cs_arm, cps_flag);
const int ARM_CC_OFFSET = offsetof(cs_arm, cc);
const int ARM_UPDATE_FLAGS_OFFSET = offsetof(cs_arm, update_flags);
const int ARM_WRITEBACK_OFFSET = offsetof(cs_arm, writeback);
const int ARM_POST_INDEX_OFFSET = offsetof(cs_arm, post_index);
const int ARM_MEM_BARRIER_OFFSET = offsetof(cs_arm, mem_barrier);
const int ARM_OP_COUNT_OFFSET = offsetof(cs_arm, op_count);

 // cs_arm_op
const int ARM_OP_SIZE = sizeof(cs_arm_op);
const int ARM_OP_OFFSET = offsetof(cs_arm, operands);
const int ARM_OP_VECTOR_INDEX_OFFSET = offsetof(cs_arm_op, vector_index);
const int ARM_OP_SHIFT_OFFSET = offsetof(cs_arm_op, shift);
const int ARM_OP_SHIFT_TYPE_OFFSET = offsetof(cs_arm_op, shift.type);
const int ARM_OP_SHIFT_VALUE_OFFSET = offsetof(cs_arm_op, shift.value);
const int ARM_OP_TYPE_OFFSET = offsetof(cs_arm_op, type);
const int ARM_OP_SETEND_OFFSET = offsetof(cs_arm_op, setend);
const int ARM_OP_SUBTRACTED_OFFSET = offsetof(cs_arm_op, subtracted);
const int ARM_OP_ACCESS_OFFSET = offsetof(cs_arm_op, access);
const int ARM_OP_NEON_LANE_OFFSET = offsetof(cs_arm_op, neon_lane);

// arm_op_mem
const int ARM_OP_MEM_OFFSET = offsetof(cs_arm_op, mem);
const int ARM_OP_MEM_BASE_OFFSET = offsetof(cs_arm_op, mem.base);
const int ARM_OP_MEM_INDEX_OFFSET = offsetof(cs_arm_op, mem.index);
const int ARM_OP_MEM_SCALE_OFFSET = offsetof(cs_arm_op, mem.scale);
const int ARM_OP_MEM_DISP_OFFSET = offsetof(cs_arm_op, mem.disp);
const int ARM_OP_MEM_LSHIFT_OFFSET = offsetof(cs_arm_op, mem.lshift);

 // cs_arm64
const int ARM64_SIZE = sizeof(cs_arm64);
const int ARM64_CC_OFFSET = offsetof(cs_arm64, cc);
const int ARM64_UPDATE_FLAGS_OFFSET = offsetof(cs_arm64, update_flags);
const int ARM64_WRITEBACK_OFFSET = offsetof(cs_arm64, writeback);
const int ARM64_POST_INDEX_OFFSET = offsetof(cs_arm64, post_index);
const int ARM64_OP_COUNT_OFFSET = offsetof(cs_arm64, op_count);

 // cs_arm64_op
const int ARM64_OP_SIZE = sizeof(cs_arm64_op);
const int ARM64_OP_OFFSET = offsetof(cs_arm64, operands);
const int ARM64_OP_VECTOR_INDEX_OFFSET = offsetof(cs_arm64_op, vector_index);
const int ARM64_VAS_OFFSET = offsetof(cs_arm64_op, vas);
const int ARM64_OP_SHIFT_OFFSET = offsetof(cs_arm64_op, shift);
const int ARM64_OP_SHIFT_VALUE_OFFSET = offsetof(cs_arm64_op, shift.value);
const int ARM64_OP_SHIFT_TYPE_OFFSET = offsetof(cs_arm64_op, shift.type);
const int ARM64_OP_EXT_OFFSET = offsetof(cs_arm64_op, ext);
const int ARM64_OP_TYPE_OFFSET = offsetof(cs_arm64_op, type);
const int ARM64_OP_SVCR_OFFSET = offsetof(cs_arm64_op, svcr);
const int ARM64_OP_REG_OFFSET = offsetof(cs_arm64_op, reg);
const int ARM64_OP_IMM_OFFSET = offsetof(cs_arm64_op, imm);
const int ARM64_OP_FP_OFFSET = offsetof(cs_arm64_op, fp);
const int ARM64_OP_PSTATE_OFFSET = offsetof(cs_arm64_op, pstate);
const int ARM64_OP_SYS_OFFSET = offsetof(cs_arm64_op, sys);
const int ARM64_OP_PREFETCH_OFFSET = offsetof(cs_arm64_op, prefetch);
const int ARM64_OP_BARRIER_OFFSET = offsetof(cs_arm64_op, barrier);
const int ARM64_OP_ACCESS_OFFSET = offsetof(cs_arm64_op, access);

// arm64_op_mem
const int ARM64_OP_MEM_OFFSET = offsetof(cs_arm64_op, mem);
const int ARM64_OP_MEM_BASE_OFFSET = offsetof(cs_arm64_op, mem.base);
const int ARM64_OP_MEM_INDEX_OFFSET = offsetof(cs_arm64_op, mem.index);
const int ARM64_OP_MEM_DISP_OFFSET = offsetof(cs_arm64_op, mem.disp);

// arm64_op_sme_index
const int ARM64_OP_SME_INDEX_OFFSET = offsetof(cs_arm64_op, sme_index);
const int ARM64_OP_SME_INDEX_REG_OFFSET = offsetof(cs_arm64_op, sme_index.reg);
const int ARM64_OP_SME_INDEX_BASE_OFFSET = offsetof(cs_arm64_op, sme_index.base);
const int ARM64_OP_SME_INDEX_DISP_OFFSET = offsetof(cs_arm64_op, sme_index.disp);

 // cs_bpf
const int BPF_SIZE = sizeof(cs_bpf);
const int BPF_OP_COUNT_OFFSET = offsetof(cs_bpf, op_count);

 // cs_bpf_op
const int BPF_OP_SIZE = sizeof(cs_bpf_op);
const int BPF_OP_OFFSET = offsetof(cs_bpf, operands);
const int BPF_OP_TYPE_OFFSET = offsetof(cs_bpf_op, type);
const int BPF_OP_REG_OFFSET = offsetof(cs_bpf_op, reg);
const int BPF_OP_IMM_OFFSET = offsetof(cs_bpf_op, imm);
const int BPF_OP_OFF_OFFSET = offsetof(cs_bpf_op, off);
const int BPF_OP_MMEM_OFFSET = offsetof(cs_bpf_op, mmem);
const int BPF_OP_MSH_OFFSET = offsetof(cs_bpf_op, msh);
const int BPF_OP_EXT_OFFSET = offsetof(cs_bpf_op, ext);
const int BPF_OP_ACCESS_OFFSET = offsetof(cs_bpf_op, access);

// bpf_op_mem
const int BPF_OP_MEM_OFFSET = offsetof(cs_bpf_op, mem);
const int BPF_OP_MEM_BASE_OFFSET = offsetof(cs_bpf_op, mem.base);
const int BPF_OP_MEM_DISP_OFFSET = offsetof(cs_bpf_op, mem.disp);

 // cs_evm
const int EVM_SIZE = sizeof(cs_evm);
const int EVM_POP_OFFSET = offsetof(cs_evm, pop);
const int EVM_PUSH_OFFSET = offsetof(cs_evm, push);
const int EVM_FEE_OFFSET = offsetof(cs_evm, fee);

 // cs_m68k/cs_m68k_op
const int M68K_SIZE = sizeof(cs_m68k);
const int M68K_OP_SIZE = sizeof(cs_m68k_op);
const int M68K_OP_OFFSET = offsetof(cs_m68k, operands);
const int M68K_OP_COUNT_OFFSET = offsetof(cs_m68k, op_count);
const int M68K_OP_IMM_OFFSET = offsetof(cs_m68k_op, imm);
const int M68K_OP_DIMM_OFFSET = offsetof(cs_m68k_op, dimm);
const int M68K_OP_SIMM_OFFSET = offsetof(cs_m68k_op, simm);
const int M68K_OP_REG_OFFSET = offsetof(cs_m68k_op, reg);
const int M68K_OP_REGISTER_BITS_OFFSET = offsetof(cs_m68k_op, register_bits);
const int M68K_OP_TYPE_OFFSET = offsetof(cs_m68k_op, type);
const int M68K_OP_ADDRESS_MODE_OFFSET = offsetof(cs_m68k_op, address_mode);

// m68k_op_size
const int M68K_OP_SIZE_OFFSET = offsetof(cs_m68k, op_size);
const int M68K_OP_SIZE_TYPE_OFFSET = offsetof(cs_m68k, op_size.type);
const int M68K_OP_SIZE_CPU_SIZE_OFFSET = offsetof(cs_m68k, op_size.cpu_size);
const int M68K_OP_SIZE_FPU_SIZE_OFFSET = offsetof(cs_m68k, op_size.fpu_size);

// cs_m68k_op_reg_pair
const int M68K_OP_REG_PAIR_OFFSET = offsetof(cs_m68k_op, reg_pair);
const int M68K_OP_REG_PAIR_REG_0_OFFSET = offsetof(cs_m68k_op, reg_pair.reg_0);
const int M68K_OP_REG_PAIR_REG_1_OFFSET = offsetof(cs_m68k_op, reg_pair.reg_1);

// m68k_op_mem
const int M68K_OP_MEM_OFFSET = offsetof(cs_m68k_op, mem);
const int M68K_OP_MEM_BASE_REG_OFFSET = offsetof(cs_m68k_op, mem.base_reg);
const int M68K_OP_MEM_INDEX_REG_OFFSET = offsetof(cs_m68k_op, mem.index_reg);
const int M68K_OP_MEM_IN_BASE_REG_OFFSET = offsetof(cs_m68k_op, mem.in_base_reg);
const int M68K_OP_MEM_IN_DISP_OFFSET = offsetof(cs_m68k_op, mem.in_disp);
const int M68K_OP_MEM_OUT_DISP_OFFSET = offsetof(cs_m68k_op, mem.out_disp);
const int M68K_OP_MEM_DISP_OFFSET = offsetof(cs_m68k_op, mem.disp);
const int M68K_OP_MEM_SCALE_OFFSET = offsetof(cs_m68k_op, mem.scale);
const int M68K_OP_MEM_BITFIELD_OFFSET = offsetof(cs_m68k_op, mem.bitfield);
const int M68K_OP_MEM_WIDTH_OFFSET = offsetof(cs_m68k_op, mem.width);
const int M68K_OP_MEM_OFFSET_OFFSET = offsetof(cs_m68k_op, mem.offset);
const int M68K_OP_MEM_INDEX_SIZE_OFFSET = offsetof(cs_m68k_op, mem.index_size);

// m68k_op_br_disp
const int M68K_OP_BR_DISP_OFFSET = offsetof(cs_m68k_op, br_disp.disp);
const int M68K_OP_BR_DISP_SIZE_OFFSET = offsetof(cs_m68k_op, br_disp.disp_size);

// cs_m680x
const int M680X_SIZE = sizeof(cs_m680x);
const int M680X_FLAGS_OFFSET = offsetof(cs_m680x, flags);
const int M680X_OP_COUNT_OFFSET = offsetof(cs_m680x, flags);

// cs_m680x_op
const int M680X_OP_SIZE = sizeof (cs_m680x_op);
const int M680X_OP_OFFSET = offsetof(cs_m680x, operands);
const int M680X_OP_TYPE_OFFSET = offsetof(cs_m680x_op, type);
const int M680X_OP_IMM_OFFSET = offsetof(cs_m680x_op, imm);
const int M680X_OP_REG_OFFSET = offsetof(cs_m680x_op, reg);
const int M680X_OP_DIRECT_ADDR_OFFSET = offsetof(cs_m680x_op, direct_addr);
const int M680X_OP_CONST_VAL_OFFSET = offsetof(cs_m680x_op, const_val);
const int M680X_OP_SIZE_OFFSET = offsetof(cs_m680x_op, size);
const int M680X_OP_ACCESS_OFFSET = offsetof(cs_m680x_op, access);

// m680x_op_idx
const int M680X_OP_IDX_OFFSET = offsetof(cs_m680x_op, idx);
const int M680X_OP_IDX_OFFSET_BASE_REG_OFFSET = offsetof(cs_m680x_op, idx.base_reg);
const int M680X_OP_IDX_OFFSET_REG_OFFSET = offsetof(cs_m680x_op, idx.offset_reg);
const int M680X_OP_IDX_OFFSET_OFFSET = offsetof(cs_m680x_op, idx.offset);
const int M680X_OP_IDX_OFFSET_ADDR_OFFSET = offsetof(cs_m680x_op, idx.offset_addr);
const int M680X_OP_IDX_OFFSET_BITS_OFFSET = offsetof(cs_m680x_op, idx.offset_bits);
const int M680X_OP_IDX_INC_DEC_OFFSET = offsetof(cs_m680x_op, idx.inc_dec);
const int M680X_OP_IDX_FLAGS_OFFSET = offsetof(cs_m680x_op, idx.flags);

// m680x_op_rel
const int M680X_OP_REL_OFFSET = offsetof(cs_m680x_op, rel);
const int M680X_OP_REL_ADDRESS_OFFSET = offsetof(cs_m680x_op, rel.address);
const int M680X_OP_REL_OFFSET_OFFSET = offsetof(cs_m680x_op, rel.offset);

// m680x_op_ext
const int M680X_OP_EXT_OFFSET = offsetof(cs_m680x_op, ext);
const int M680X_OP_EXT_ADDRESS_OFFSET = offsetof(cs_m680x_op, ext.address);
const int M680X_OP_EXT_INDIRECT_OFFSET = offsetof(cs_m680x_op, ext.indirect);

// cs_mips
const int MIPS_SIZE = sizeof(cs_mips);
const int MIPS_OP_COUNT_OFFSET = offsetof(cs_mips, op_count);

// cs_mips_op
const int MIPS_OP_SIZE = sizeof(cs_mips_op);
const int MIPS_OP_OFFSET = offsetof(cs_mips, operands);
const int MIPS_OP_TYPE_OFFSET = offsetof(cs_mips_op, type);
const int MIPS_OP_REG_OFFSET = offsetof(cs_mips_op, reg);

// mips_op_mem
const int MIPS_OP_MEM_OFFSET = offsetof(cs_mips_op, mem);
const int MIPS_OP_MEM_BASE_OFFSET = offsetof(cs_mips_op, mem.base);
const int MIPS_OP_MEM_DISP_OFFSET = offsetof(cs_mips_op, mem.disp);

// cs_mos65xx
const int MOS65XX_SIZE = sizeof(cs_mos65xx);
const int MOS65XX_AM_OFFSET = offsetof(cs_mos65xx, am);
const int MOS65XX_MODIFIES_FLAGS_OFFSET = offsetof(cs_mos65xx, modifies_flags);
const int MOS65XX_OP_COUNT_OFFSET = offsetof(cs_mos65xx, op_count);

// cs_mos65xx_op
const int MOS65XX_OP_SIZE = sizeof(cs_mos65xx_op);
const int MOS65XX_OP_OFFSET = offsetof(cs_mos65xx, operands);
const int MOS65XX_OP_TYPE_OFFSET = offsetof(cs_mos65xx_op, type);
const int MOS65XX_OP_REG_OFFSET = offsetof(cs_mos65xx_op, reg);
const int MOS65XX_OP_IMM_OFFSET = offsetof(cs_mos65xx_op, imm);
const int MOS65XX_OP_MEM_OFFSET = offsetof(cs_mos65xx_op, mem);

// cs_ppc
const int PPC_SIZE = sizeof(cs_ppc);
const int PPC_BC_OFFSET = offsetof(cs_ppc, bc);
const int PPC_BH_OFFSET = offsetof(cs_ppc, bh);
const int PPC_UPDATE_CR0_OFFSET = offsetof(cs_ppc, update_cr0);
const int PPC_OP_COUNT_OFFSET = offsetof(cs_ppc, op_count);

// cs_ppc_op
const int PPC_OP_SIZE = sizeof(cs_ppc_op);
const int PPC_OP_OFFSET = offsetof(cs_ppc, operands);
const int PPC_OP_TYPE_OFFSET = offsetof(cs_ppc_op, type);
const int PPC_OP_REG_OFFSET = offsetof(cs_ppc_op, reg);
const int PPC_OP_IMM_OFFSET = offsetof(cs_ppc_op, imm);

// ppc_op_mem
const int PPC_OP_MEM_OFFSET = offsetof(cs_ppc_op, mem);
const int PPC_OP_MEM_BASE_OFFSET = offsetof(cs_ppc_op, mem.base);
const int PPC_OP_MEM_DISP_OFFSET = offsetof(cs_ppc_op, mem.disp);

// ppc_op_crx
const int PPC_OP_CRX_OFFSET = offsetof(cs_ppc_op, crx);
const int PPC_OP_CRX_SCALE_OFFSET = offsetof(cs_ppc_op, crx.scale);
const int PPC_OP_CRX_REG_OFFSET = offsetof(cs_ppc_op, crx.reg);
const int PPC_OP_CRX_COND_OFFSET = offsetof(cs_ppc_op, crx.cond);

// cs_riscv
const int RISCV_SIZE = sizeof(cs_riscv);
const int RISCV_NEED_EFFECTIVE_ADDR_OFFSET = offsetof(cs_riscv, need_effective_addr);
const int RISCV_OP_COUNT_OFFSET = offsetof(cs_riscv, op_count);

// cs_riscv_op
const int RISCV_OP_SIZE = sizeof(cs_riscv_op);
const int RISCV_OP_OFFSET = offsetof(cs_riscv, operands);
const int RISCV_OP_TYPE_OFFSET = offsetof(cs_riscv_op, type);
const int RISCV_OP_REG_OFFSET = offsetof(cs_riscv_op, reg);
const int RISCV_OP_IMM_OFFSET = offsetof(cs_riscv_op, imm);

// riscv_op_mem
const int RISCV_OP_MEM_OFFSET = offsetof(cs_riscv_op, mem);
const int RISCV_OP_MEM_BASE_OFFSET = offsetof(cs_riscv_op, mem.base);
const int RISCV_OP_MEM_DISP_OFFSET = offsetof(cs_riscv_op, mem.disp);

// cs_sh
const int SH_SIZE = sizeof(cs_sh);
const int SH_INSN_OFFSET = offsetof(cs_sh, insn);
const int SH_SIZE_OFFSET = offsetof(cs_sh, size);
const int SH_OP_COUNT_OFFSET = offsetof(cs_sh, op_count);

// cs_sh_op
const int SH_OP_SIZE = sizeof(cs_sh_op);
const int SH_OP_OFFSET = offsetof(cs_sh, operands);
const int SH_OP_TYPE_OFFSET = offsetof(cs_sh_op, type);
const int SH_OP_IMM_OFFSET = offsetof(cs_sh_op, imm);
const int SH_OP_REG_OFFSET = offsetof(cs_sh_op, reg);

// sh_op_mem
const int SH_OP_MEM_OFFSET = offsetof(cs_sh_op, mem);
const int SH_OP_MEM_ADDRESS_OFFSET = offsetof(cs_sh_op, mem.address);
const int SH_OP_MEM_REG_OFFSET = offsetof(cs_sh_op, mem.reg);
const int SH_OP_MEM_DISP_OFFSET = offsetof(cs_sh_op, mem.disp);

// sh_op_dsp
const int SH_OP_DSP_OFFSET = offsetof(cs_sh_op, dsp);
const int SH_OP_DSP_INSN_OFFSET = offsetof(cs_sh_op, dsp.insn);
const int SH_OP_DSP_OPERAND_OFFSET = offsetof(cs_sh_op, dsp.operand);
const int SH_OP_DSP_REG_OFFSET = offsetof(cs_sh_op, dsp.r);
const int SH_OP_DSP_CC_OFFSET = offsetof(cs_sh_op, dsp.cc);
const int SH_OP_DSP_IMM_OFFSET = offsetof(cs_sh_op, dsp.imm);
const int SH_OP_DSP_SIZE_OFFSET = offsetof(cs_sh_op, dsp.size);

// cs_sparc
const int SPARC_SIZE = sizeof(cs_sparc);
const int SPARC_CC_OFFSET = offsetof(cs_sparc, cc);
const int SPARC_HINT_OFFSET = offsetof(cs_sparc, hint);
const int SPARC_OP_COUNT_OFFSET = offsetof(cs_sparc, op_count);

// cs_sparc_op
const int SPARC_OP_SIZE = sizeof(cs_sparc_op);
const int SPARC_OP_OFFSET = offsetof(cs_sparc, operands);
const int SPARC_OP_TYPE_OFFSET = offsetof(cs_sparc_op, type);
const int SPARC_OP_REG_OFFSET = offsetof(cs_sparc_op, reg);
const int SPARC_OP_IMM_OFFSET = offsetof(cs_sparc_op, imm);

// sparc_op_mem
const int SPARC_OP_MEM_OFFSET = offsetof(cs_sparc_op, mem);
const int SPARC_OP_MEM_BASE_OFFSET = offsetof(cs_sparc_op, mem.base);
const int SPARC_OP_MEM_INDEX_OFFSET = offsetof(cs_sparc_op, mem.index);
const int SPARC_OP_MEM_DISP_OFFSET = offsetof(cs_sparc_op, mem.disp);

// cs_sysz
const int SYSZ_SIZE = sizeof(cs_sysz);
const int SYSZ_CC_OFFSET = offsetof(cs_sysz, cc);
const int SYSZ_OP_COUNT_OFFSET = offsetof(cs_sysz, op_count);

// cs_sysz_op
const int SYSZ_OP_SIZE = sizeof(cs_sysz_op);
const int SYSZ_OP_OFFSET = offsetof(cs_sysz, operands);
const int SYSZ_OP_TYPE_OFFSET = offsetof(cs_sysz_op, type);
const int SYSZ_OP_REG_OFFSET = offsetof(cs_sysz_op, reg);
const int SYSZ_OP_IMM_OFFSET = offsetof(cs_sysz_op, imm);

// sysz_op_mem
const int SYSZ_OP_MEM_OFFSET = offsetof(cs_sysz_op, mem);
const int SYSZ_OP_MEM_BASE_OFFSET = offsetof(cs_sysz_op, mem.base);
const int SYSZ_OP_MEM_INDEX_OFFSET = offsetof(cs_sysz_op, mem.index);
const int SYSZ_OP_MEM_LENGTH_OFFSET = offsetof(cs_sysz_op, mem.length);
const int SYSZ_OP_MEM_DISP_OFFSET = offsetof(cs_sysz_op, mem.disp);

// cs_tms320c64x
const int TMS320C64X_SIZE = sizeof(cs_tms320c64x);
const int TMS320C64X_OP_COUNT_OFFSET = offsetof(cs_tms320c64x, op_count);
const int TMS320C64X_CONDITION_OFFSET = offsetof(cs_tms320c64x, condition);
const int TMS320C64X_CONDITION_REG_OFFSET = offsetof(cs_tms320c64x, condition.reg);
const int TMS320C64X_CONDITION_ZERO_OFFSET = offsetof(cs_tms320c64x, condition.zero);
const int TMS320C64X_FUNIT_OFFSET = offsetof(cs_tms320c64x, funit);
const int TMS320C64X_FUNIT_UNIT_OFFSET = offsetof(cs_tms320c64x, funit.unit);
const int TMS320C64X_FUNIT_SIDE_OFFSET = offsetof(cs_tms320c64x, funit.side);
const int TMS320C64X_FUNIT_CROSSPATH_OFFSET = offsetof(cs_tms320c64x, funit.crosspath);
const int TMS320C64X_PARALLEL_OFFSET = offsetof(cs_tms320c64x, parallel);

// cs_tms320c64x_op
const int TMS320C64X_OP_SIZE = sizeof(cs_tms320c64x_op);
const int TMS320C64X_OP_OFFSET = offsetof(cs_tms320c64x, operands);
const int TMS320C64X_OP_TYPE_OFFSET = offsetof(cs_tms320c64x_op, type);
const int TMS320C64X_OP_REG_OFFSET = offsetof(cs_tms320c64x_op, reg);
const int TMS320C64X_OP_IMM_OFFSET = offsetof(cs_tms320c64x_op, imm);

// tms320c64x_op_mem
const int TMS320C64X_OP_MEM_OFFSET = offsetof(cs_tms320c64x_op, mem);
const int TMS320C64X_OP_MEM_BASE_OFFSET = offsetof(cs_tms320c64x_op, mem.base);
const int TMS320C64X_OP_MEM_DISP_OFFSET = offsetof(cs_tms320c64x_op, mem.disp);
const int TMS320C64X_OP_MEM_UNIT_OFFSET = offsetof(cs_tms320c64x_op, mem.unit);
const int TMS320C64X_OP_MEM_SCALED_OFFSET = offsetof(cs_tms320c64x_op, mem.scaled);
const int TMS320C64X_OP_MEM_DISPTYPE_OFFSET = offsetof(cs_tms320c64x_op, mem.disptype);
const int TMS320C64X_OP_MEM_DIRECTION_OFFSET = offsetof(cs_tms320c64x_op, mem.direction);
const int TMS320C64X_OP_MEM_MODIFY_OFFSET = offsetof(cs_tms320c64x_op, mem.modify);

// cs_tricore
const int TRICORE_SIZE = sizeof(cs_tricore);
const int TRICORE_OP_COUNT_OFFSET = offsetof(cs_tricore, op_count);
const int TRICORE_UPDATE_FLAGS_OFFSET = offsetof(cs_tricore, update_flags);

// cs_tricore_op
const int TRICORE_OP_SIZE = sizeof(cs_tricore_op);
const int TRICORE_OP_OFFSET = offsetof(cs_tricore, operands);
const int TRICORE_OP_TYPE_OFFSET = offsetof(cs_tricore_op, type);
const int TRICORE_OP_REG_OFFSET = offsetof(cs_tricore_op, reg);
const int TRICORE_OP_IMM_OFFSET = offsetof(cs_tricore_op, imm);
const int TRICORE_OP_ACCESS_OFFSET = offsetof(cs_tricore_op, access);

// tricore_op_mem
const int TRICORE_OP_MEM_OFFSET = offsetof(cs_tricore_op, mem);
const int TRICORE_OP_MEM_BASE_OFFSET = offsetof(cs_tricore_op, mem.base);
const int TRICORE_OP_MEM_DISP_OFFSET = offsetof(cs_tricore_op, mem.disp);

// cs_wasm
const int WASM_SIZE = sizeof(cs_wasm);
const int WASM_OP_COUNT_OFFSET = offsetof(cs_wasm, op_count);

// cs_wasm_op
const int WASM_OP_SIZE = sizeof(cs_wasm_op);
const int WASM_OP_OFFSET = offsetof(cs_wasm, operands);
const int WASM_OP_TYPE_OFFSET = offsetof(cs_wasm_op, type);
const int WASM_OP_SIZE_OFFSET = offsetof(cs_wasm_op, size);
const int WASM_OP_INT7_OFFSET = offsetof(cs_wasm_op, int7);
const int WASM_OP_VARUINT32_OFFSET = offsetof(cs_wasm_op, varuint32);
const int WASM_OP_VARUINT64_OFFSET = offsetof(cs_wasm_op, varuint64);
const int WASM_OP_UINT32_OFFSET = offsetof(cs_wasm_op, uint32);
const int WASM_OP_UINT64_OFFSET = offsetof(cs_wasm_op, uint64);
const int WASM_OP_IMMEDIATE_OFFSET = offsetof(cs_wasm_op, immediate);

// cs_wasm_brtable
const int WASM_OP_BRTABLE_OFFSET = offsetof(cs_wasm_op, brtable);
const int WASM_OP_BRTABLE_LENGTH_OFFSET = offsetof(cs_wasm_op, brtable.length);	
const int WASM_OP_BRTABLE_ADDRESS_OFFSET = offsetof(cs_wasm_op, brtable.address);
const int WASM_OP_BRTABLE_DEFAULT_TARGET_OFFSET = offsetof(cs_wasm_op, brtable.default_target);

// cs_x86
const int X86_SIZE = sizeof(cs_x86);
const int X86_PREFIX_OFFSET = offsetof(cs_x86, prefix);
const int X86_OPCODE_OFFSET = offsetof(cs_x86, opcode);
const int X86_REX_OFFSET = offsetof(cs_x86, rex);
const int X86_ADDR_SIZE_OFFSET = offsetof(cs_x86, addr_size);
const int X86_MODRM_OFFSET = offsetof(cs_x86, modrm);
const int X86_SIB_OFFSET = offsetof(cs_x86, sib);
const int X86_DISP_OFFSET = offsetof(cs_x86, disp);
const int X86_SIB_INDEX_OFFSET = offsetof(cs_x86, sib_index);
const int X86_SIB_SCALE_OFFSET = offsetof(cs_x86, sib_scale);
const int X86_SIB_BASE_OFFSET = offsetof(cs_x86, sib_base);
const int X86_XOP_CC_OFFSET = offsetof(cs_x86, xop_cc);
const int X86_SSE_CC_OFFSET = offsetof(cs_x86, sse_cc);
const int X86_AVX_CC_OFFSET = offsetof(cs_x86, avx_cc);
const int X86_AVX_SAE_OFFSET = offsetof(cs_x86, avx_sae);
const int X86_AVX_RM_OFFSET = offsetof(cs_x86, avx_rm);
const int X86_EFLAGS_OFFSET = offsetof(cs_x86, eflags);
const int X86_FPU_FLAGS_OFFSET = offsetof(cs_x86, fpu_flags);
const int X86_OP_COUNT_OFFSET = offsetof(cs_x86, op_count);

// cs_x86_encoding
const int X86_ENCODING_SIZE = sizeof(cs_x86_encoding);
const int X86_ENCODING_MODRM_OFFSET_OFFSET = offsetof(cs_x86_encoding, modrm_offset);
const int X86_ENCODING_DISP_OFFSET_OFFSET = offsetof(cs_x86_encoding, disp_offset);
const int X86_ENCODING_DISP_SIZE_OFFSET = offsetof(cs_x86_encoding, disp_size);
const int X86_ENCODING_IMM_OFFSET_OFFSET = offsetof(cs_x86_encoding, imm_offset);
const int X86_ENCODING_IMM_SIZE_OFFSET = offsetof(cs_x86_encoding, imm_size);

// cs_x86_op
const int X86_OP_SIZE = sizeof(cs_x86_op);
const int X86_OP_OFFSET = offsetof(cs_x86, operands);
const int X86_OP_TYPE_OFFSET = offsetof(cs_x86_op, type);
const int X86_OP_REG_OFFSET = offsetof(cs_x86_op, reg);
const int X86_OP_IMM_OFFSET = offsetof(cs_x86_op, imm);
const int X86_OP_SIZE_OFFSET = offsetof(cs_x86_op, size);
const int X86_OP_ACCESS_OFFSET = offsetof(cs_x86_op, access);
const int X86_OP_AVX_BCAST_OFFSET = offsetof(cs_x86_op, avx_bcast);
const int X86_OP_AVX_ZERO_OP_MASK_OFFSET = offsetof(cs_x86_op, avx_zero_opmask);

// x86_op_mem
const int X86_OP_MEM_OFFSET = offsetof(cs_x86_op, mem);
const int X86_OP_MEM_SEGMENT_OFFSET = offsetof(cs_x86_op, mem.segment);
const int X86_OP_MEM_BASE_OFFSET = offsetof(cs_x86_op, mem.base);
const int X86_OP_MEM_INDEX_OFFSET = offsetof(cs_x86_op, mem.index);
const int X86_OP_MEM_SCALE_OFFSET = offsetof(cs_x86_op, mem.scale);
const int X86_OP_MEM_DISP_OFFSET = offsetof(cs_x86_op, mem.disp);

// cs_xcore
const int XCORE_SIZE = sizeof(cs_xcore);
const int XCODE_OP_COUNT_OFFSET = offsetof(cs_xcore, op_count);

// cs_x86_op
const int XCORE_OP_SIZE = sizeof(cs_xcore_op);
const int XCODE_OP_OFFSET = offsetof(cs_xcore, operands);
const int XCODE_OP_TYPE_OFFSET = offsetof(cs_xcore_op, type);
const int XCODE_OP_REG_OFFSET = offsetof(cs_xcore_op, reg);

// xcore_op_mem
const int XCODE_OP_MEM_OFFSET = offsetof(cs_xcore_op, mem);
const int XCODE_OP_MEM_BASE_OFFSET = offsetof(cs_xcore_op, mem.base);
const int XCODE_OP_MEM_INDEX_OFFSET = offsetof(cs_xcore_op, mem.index);
const int XCODE_OP_MEM_DISP_OFFSET = offsetof(cs_xcore_op, mem.disp);
const int XCODE_OP_MEM_DIRECT_OFFSET = offsetof(cs_xcore_op, mem.direct);

EMSCRIPTEN_BINDINGS(constants) {

   // cs_insn
  constant("INSN_SIZE", INSN_SIZE);
  constant("INSN_ID_OFFSET", INSN_ID_OFFSET);
  constant("INSN_ADDR_OFFSET", INSN_ADDR_OFFSET);
  constant("INSN_SIZE_OFFSET", INSN_SIZE_OFFSET);
  constant("INSN_MNEMONIC_OFFSET", INSN_MNEMONIC_OFFSET);
  constant("INSN_OP_STR", INSN_OP_STR);
  constant("INSN_BYTES_OFFSET", INSN_BYTES_OFFSET);
  constant("INSN_DETAIL_OFFSET", INSN_DETAIL_OFFSET);

   // cs_detail
  constant("DETAIL_SIZE", DETAIL_SIZE);
  constant("DETAIL_REGS_READ_OFFSET", DETAIL_REGS_READ_OFFSET);
  constant("DETAIL_REGS_READ_COUNT_OFFSET", DETAIL_REGS_READ_COUNT_OFFSET);
  constant("DETAIL_REGS_WRITE_OFFSET", DETAIL_REGS_WRITE_OFFSET);
  constant("DETAIL_REGS_WRITE_COUNT_OFFSET", DETAIL_REGS_WRITE_COUNT_OFFSET);
  constant("DETAIL_GROUPS_OFFSET", DETAIL_GROUPS_OFFSET);
  constant("DETAIL_GROUPS_COUNT_OFFSET", DETAIL_GROUPS_COUNT_OFFSET);
  constant("DETAIL_WRITEBACK_OFFSET", DETAIL_WRITEBACK_OFFSET);
  constant("DETAIL_ARCH_INFO_OFFSET", DETAIL_ARCH_INFO_OFFSET);

   // cs_arm
  constant("ARM_SIZE", ARM_SIZE);
  constant("ARM_USERMODE_OFFSET", ARM_USERMODE_OFFSET);
  constant("ARM_VECTOR_SIZE_OFFSET", ARM_VECTOR_SIZE_OFFSET);
  constant("ARM_VECTOR_DATA_OFFSET", ARM_VECTOR_DATA_OFFSET);
  constant("ARM_CPS_MODE_OFFSET", ARM_CPS_MODE_OFFSET);
  constant("ARM_CPS_FLAG_OFFSET", ARM_CPS_FLAG_OFFSET);
  constant("ARM_CC_OFFSET", ARM_CC_OFFSET);
  constant("ARM_UPDATE_FLAGS_OFFSET", ARM_UPDATE_FLAGS_OFFSET);
  constant("ARM_WRITEBACK_OFFSET", ARM_WRITEBACK_OFFSET);
  constant("ARM_POST_INDEX_OFFSET", ARM_POST_INDEX_OFFSET);
  constant("ARM_MEM_BARRIER_OFFSET", ARM_MEM_BARRIER_OFFSET);
  constant("ARM_OP_COUNT_OFFSET", ARM_OP_COUNT_OFFSET);

   // cs_arm_op
  constant("ARM_OP_SIZE", ARM_OP_SIZE);
  constant("ARM_OP_OFFSET", ARM_OP_OFFSET);
  constant("ARM_OP_VECTOR_INDEX_OFFSET", ARM_OP_VECTOR_INDEX_OFFSET);
  constant("ARM_OP_SHIFT_OFFSET", ARM_OP_SHIFT_OFFSET);
  constant("ARM_OP_SHIFT_TYPE_OFFSET", ARM_OP_SHIFT_TYPE_OFFSET);
  constant("ARM_OP_SHIFT_VALUE_OFFSET", ARM_OP_SHIFT_VALUE_OFFSET);
  constant("ARM_OP_TYPE_OFFSET", ARM_OP_TYPE_OFFSET);
  constant("ARM_OP_SETEND_OFFSET", ARM_OP_SETEND_OFFSET);
  constant("ARM_OP_SUBTRACTED_OFFSET", ARM_OP_SUBTRACTED_OFFSET);
  constant("ARM_OP_ACCESS_OFFSET", ARM_OP_ACCESS_OFFSET);
  constant("ARM_OP_NEON_LANE_OFFSET", ARM_OP_NEON_LANE_OFFSET);

  // arm_op_mem
  constant("ARM_OP_MEM_OFFSET", ARM_OP_MEM_OFFSET);
  constant("ARM_OP_MEM_BASE_OFFSET", ARM_OP_MEM_BASE_OFFSET);
  constant("ARM_OP_MEM_INDEX_OFFSET", ARM_OP_MEM_INDEX_OFFSET);
  constant("ARM_OP_MEM_SCALE_OFFSET", ARM_OP_MEM_SCALE_OFFSET);
  constant("ARM_OP_MEM_DISP_OFFSET", ARM_OP_MEM_DISP_OFFSET);
  constant("ARM_OP_MEM_LSHIFT_OFFSET", ARM_OP_MEM_LSHIFT_OFFSET);

   // cs_arm64
  constant("ARM64_SIZE", ARM64_SIZE);
  constant("ARM64_CC_OFFSET", ARM64_CC_OFFSET);
  constant("ARM64_UPDATE_FLAGS_OFFSET", ARM64_UPDATE_FLAGS_OFFSET);
  constant("ARM64_WRITEBACK_OFFSET", ARM64_WRITEBACK_OFFSET);
  constant("ARM64_POST_INDEX_OFFSET", ARM64_POST_INDEX_OFFSET);
  constant("ARM64_OP_COUNT_OFFSET", ARM64_OP_COUNT_OFFSET);

   // cs_arm64_op
  constant("ARM64_OP_SIZE", ARM64_OP_SIZE);
  constant("ARM64_OP_OFFSET", ARM64_OP_OFFSET);
  constant("ARM64_OP_VECTOR_INDEX_OFFSET", ARM64_OP_VECTOR_INDEX_OFFSET);
  constant("ARM64_VAS_OFFSET", ARM64_VAS_OFFSET);
  constant("ARM64_OP_SHIFT_OFFSET", ARM64_OP_SHIFT_OFFSET);
  constant("ARM64_OP_SHIFT_VALUE_OFFSET", ARM64_OP_SHIFT_VALUE_OFFSET);
  constant("ARM64_OP_SHIFT_TYPE_OFFSET", ARM64_OP_SHIFT_TYPE_OFFSET);
  constant("ARM64_OP_EXT_OFFSET", ARM64_OP_EXT_OFFSET);
  constant("ARM64_OP_TYPE_OFFSET", ARM64_OP_TYPE_OFFSET);
  constant("ARM64_OP_SVCR_OFFSET", ARM64_OP_SVCR_OFFSET);
  constant("ARM64_OP_REG_OFFSET", ARM64_OP_REG_OFFSET);
  constant("ARM64_OP_IMM_OFFSET", ARM64_OP_IMM_OFFSET);
  constant("ARM64_OP_FP_OFFSET", ARM64_OP_FP_OFFSET);
  constant("ARM64_OP_PSTATE_OFFSET", ARM64_OP_PSTATE_OFFSET);
  constant("ARM64_OP_SYS_OFFSET", ARM64_OP_SYS_OFFSET);
  constant("ARM64_OP_PREFETCH_OFFSET", ARM64_OP_PREFETCH_OFFSET);
  constant("ARM64_OP_BARRIER_OFFSET", ARM64_OP_BARRIER_OFFSET);
  constant("ARM64_OP_ACCESS_OFFSET", ARM64_OP_ACCESS_OFFSET);

  // arm64_op_mem
  constant("ARM64_OP_MEM_OFFSET", ARM64_OP_MEM_OFFSET);
  constant("ARM64_OP_MEM_BASE_OFFSET", ARM64_OP_MEM_BASE_OFFSET);
  constant("ARM64_OP_MEM_INDEX_OFFSET", ARM64_OP_MEM_INDEX_OFFSET);
  constant("ARM64_OP_MEM_DISP_OFFSET", ARM64_OP_MEM_DISP_OFFSET);

  // arm64_op_sme_index
  constant("ARM64_OP_SME_INDEX_OFFSET", ARM64_OP_SME_INDEX_OFFSET);
  constant("ARM64_OP_SME_INDEX_REG_OFFSET", ARM64_OP_SME_INDEX_REG_OFFSET);
  constant("ARM64_OP_SME_INDEX_BASE_OFFSET", ARM64_OP_SME_INDEX_BASE_OFFSET);
  constant("ARM64_OP_SME_INDEX_DISP_OFFSET", ARM64_OP_SME_INDEX_DISP_OFFSET);

   // cs_bpf
  constant("BPF_SIZE", BPF_SIZE);
  constant("BPF_OP_COUNT_OFFSET", BPF_OP_COUNT_OFFSET);

   // cs_bpf_op
  constant("BPF_OP_SIZE", BPF_OP_SIZE);
  constant("BPF_OP_OFFSET", BPF_OP_OFFSET);
  constant("BPF_OP_TYPE_OFFSET", BPF_OP_TYPE_OFFSET);
  constant("BPF_OP_REG_OFFSET", BPF_OP_REG_OFFSET);
  constant("BPF_OP_IMM_OFFSET", BPF_OP_IMM_OFFSET);
  constant("BPF_OP_OFF_OFFSET", BPF_OP_OFF_OFFSET);
  constant("BPF_OP_MMEM_OFFSET", BPF_OP_MMEM_OFFSET);
  constant("BPF_OP_MSH_OFFSET", BPF_OP_MSH_OFFSET);
  constant("BPF_OP_EXT_OFFSET", BPF_OP_EXT_OFFSET);
  constant("BPF_OP_ACCESS_OFFSET", BPF_OP_ACCESS_OFFSET);

  // bpf_op_mem
  constant("BPF_OP_MEM_OFFSET", BPF_OP_MEM_OFFSET);
  constant("BPF_OP_MEM_BASE_OFFSET", BPF_OP_MEM_BASE_OFFSET);
  constant("BPF_OP_MEM_DISP_OFFSET", BPF_OP_MEM_DISP_OFFSET);

   // cs_evm
  constant("EVM_SIZE", EVM_SIZE);
  constant("EVM_POP_OFFSET", EVM_POP_OFFSET);
  constant("EVM_PUSH_OFFSET", EVM_PUSH_OFFSET);
  constant("EVM_FEE_OFFSET", EVM_FEE_OFFSET);

   // cs_m68k/cs_m68k_op
  constant("M68K_SIZE", M68K_SIZE);
  constant("M68K_OP_SIZE", M68K_OP_SIZE);
  constant("M68K_OP_OFFSET", M68K_OP_OFFSET);
  constant("M68K_OP_COUNT_OFFSET", M68K_OP_COUNT_OFFSET);
  constant("M68K_OP_IMM_OFFSET", M68K_OP_IMM_OFFSET);
  constant("M68K_OP_DIMM_OFFSET", M68K_OP_DIMM_OFFSET);
  constant("M68K_OP_SIMM_OFFSET", M68K_OP_SIMM_OFFSET);
  constant("M68K_OP_REG_OFFSET", M68K_OP_REG_OFFSET);
  constant("M68K_OP_REGISTER_BITS_OFFSET", M68K_OP_REGISTER_BITS_OFFSET);
  constant("M68K_OP_TYPE_OFFSET", M68K_OP_TYPE_OFFSET);
  constant("M68K_OP_ADDRESS_MODE_OFFSET", M68K_OP_ADDRESS_MODE_OFFSET);

  // m68k_op_size
  constant("M68K_OP_SIZE_OFFSET", M68K_OP_SIZE_OFFSET);
  constant("M68K_OP_SIZE_TYPE_OFFSET", M68K_OP_SIZE_TYPE_OFFSET);
  constant("M68K_OP_SIZE_CPU_SIZE_OFFSET", M68K_OP_SIZE_CPU_SIZE_OFFSET);
  constant("M68K_OP_SIZE_FPU_SIZE_OFFSET", M68K_OP_SIZE_FPU_SIZE_OFFSET);

  // cs_m68k_op_reg_pair
  constant("M68K_OP_REG_PAIR_OFFSET", M68K_OP_REG_PAIR_OFFSET);
  constant("M68K_OP_REG_PAIR_REG_0_OFFSET", M68K_OP_REG_PAIR_REG_0_OFFSET);
  constant("M68K_OP_REG_PAIR_REG_1_OFFSET", M68K_OP_REG_PAIR_REG_1_OFFSET);

  // m68k_op_mem
  constant("M68K_OP_MEM_OFFSET", M68K_OP_MEM_OFFSET);
  constant("M68K_OP_MEM_BASE_REG_OFFSET", M68K_OP_MEM_BASE_REG_OFFSET);
  constant("M68K_OP_MEM_INDEX_REG_OFFSET", M68K_OP_MEM_INDEX_REG_OFFSET);
  constant("M68K_OP_MEM_IN_BASE_REG_OFFSET", M68K_OP_MEM_IN_BASE_REG_OFFSET);
  constant("M68K_OP_MEM_IN_DISP_OFFSET", M68K_OP_MEM_IN_DISP_OFFSET);
  constant("M68K_OP_MEM_OUT_DISP_OFFSET", M68K_OP_MEM_OUT_DISP_OFFSET);
  constant("M68K_OP_MEM_DISP_OFFSET", M68K_OP_MEM_DISP_OFFSET);
  constant("M68K_OP_MEM_SCALE_OFFSET", M68K_OP_MEM_SCALE_OFFSET);
  constant("M68K_OP_MEM_BITFIELD_OFFSET", M68K_OP_MEM_BITFIELD_OFFSET);
  constant("M68K_OP_MEM_WIDTH_OFFSET", M68K_OP_MEM_WIDTH_OFFSET);
  constant("M68K_OP_MEM_OFFSET_OFFSET", M68K_OP_MEM_OFFSET_OFFSET);
  constant("M68K_OP_MEM_INDEX_SIZE_OFFSET", M68K_OP_MEM_INDEX_SIZE_OFFSET);

  // m68k_op_br_disp
  constant("M68K_OP_BR_DISP_OFFSET", M68K_OP_BR_DISP_OFFSET);
  constant("M68K_OP_BR_DISP_SIZE_OFFSET", M68K_OP_BR_DISP_SIZE_OFFSET);

  // cs_m680x
  constant("M680X_SIZE", M680X_SIZE);
  constant("M680X_FLAGS_OFFSET", M680X_FLAGS_OFFSET);
  constant("M680X_OP_COUNT_OFFSET", M680X_OP_COUNT_OFFSET);

  // cs_m680x_op
  constant("M680X_OP_SIZE", M680X_OP_SIZE);
  constant("M680X_OP_OFFSET", M680X_OP_OFFSET);
  constant("M680X_OP_TYPE_OFFSET", M680X_OP_TYPE_OFFSET);
  constant("M680X_OP_IMM_OFFSET", M680X_OP_IMM_OFFSET);
  constant("M680X_OP_REG_OFFSET", M680X_OP_REG_OFFSET);
  constant("M680X_OP_DIRECT_ADDR_OFFSET", M680X_OP_DIRECT_ADDR_OFFSET);
  constant("M680X_OP_CONST_VAL_OFFSET", M680X_OP_CONST_VAL_OFFSET);
  constant("M680X_OP_SIZE_OFFSET", M680X_OP_SIZE_OFFSET);
  constant("M680X_OP_ACCESS_OFFSET", M680X_OP_ACCESS_OFFSET);

  // m680x_op_idx
  constant("M680X_OP_IDX_OFFSET", M680X_OP_IDX_OFFSET);
  constant("M680X_OP_IDX_OFFSET_BASE_REG_OFFSET", M680X_OP_IDX_OFFSET_BASE_REG_OFFSET);
  constant("M680X_OP_IDX_OFFSET_REG_OFFSET", M680X_OP_IDX_OFFSET_REG_OFFSET);
  constant("M680X_OP_IDX_OFFSET_OFFSET", M680X_OP_IDX_OFFSET_OFFSET);
  constant("M680X_OP_IDX_OFFSET_ADDR_OFFSET", M680X_OP_IDX_OFFSET_ADDR_OFFSET);
  constant("M680X_OP_IDX_OFFSET_BITS_OFFSET", M680X_OP_IDX_OFFSET_BITS_OFFSET);
  constant("M680X_OP_IDX_INC_DEC_OFFSET", M680X_OP_IDX_INC_DEC_OFFSET);
  constant("M680X_OP_IDX_FLAGS_OFFSET", M680X_OP_IDX_FLAGS_OFFSET);

  // m680x_op_rel
  constant("M680X_OP_REL_OFFSET", M680X_OP_REL_OFFSET);
  constant("M680X_OP_REL_ADDRESS_OFFSET", M680X_OP_REL_ADDRESS_OFFSET);
  constant("M680X_OP_REL_OFFSET_OFFSET", M680X_OP_REL_OFFSET_OFFSET);

  // m680x_op_ext
  constant("M680X_OP_EXT_OFFSET", M680X_OP_EXT_OFFSET);
  constant("M680X_OP_EXT_ADDRESS_OFFSET", M680X_OP_EXT_ADDRESS_OFFSET);
  constant("M680X_OP_EXT_INDIRECT_OFFSET", M680X_OP_EXT_INDIRECT_OFFSET);

  // cs_mips
  constant("MIPS_SIZE", MIPS_SIZE);
  constant("MIPS_OP_COUNT_OFFSET", MIPS_OP_COUNT_OFFSET);

  // cs_mips_op
  constant("MIPS_OP_SIZE", MIPS_OP_SIZE);
  constant("MIPS_OP_OFFSET", MIPS_OP_OFFSET);
  constant("MIPS_OP_TYPE_OFFSET", MIPS_OP_TYPE_OFFSET);
  constant("MIPS_OP_REG_OFFSET", MIPS_OP_REG_OFFSET);

  // mips_op_mem
  constant("MIPS_OP_MEM_OFFSET", MIPS_OP_MEM_OFFSET);
  constant("MIPS_OP_MEM_BASE_OFFSET", MIPS_OP_MEM_BASE_OFFSET);
  constant("MIPS_OP_MEM_DISP_OFFSET", MIPS_OP_MEM_DISP_OFFSET);

  // cs_mos65xx
  constant("MOS65XX_SIZE", MOS65XX_SIZE);
  constant("MOS65XX_AM_OFFSET", MOS65XX_AM_OFFSET);
  constant("MOS65XX_MODIFIES_FLAGS_OFFSET", MOS65XX_MODIFIES_FLAGS_OFFSET);
  constant("MOS65XX_OP_COUNT_OFFSET", MOS65XX_OP_COUNT_OFFSET);

  // cs_mos65xx_op
  constant("MOS65XX_OP_SIZE", MOS65XX_OP_SIZE);
  constant("MOS65XX_OP_OFFSET", MOS65XX_OP_OFFSET);
  constant("MOS65XX_OP_TYPE_OFFSET", MOS65XX_OP_TYPE_OFFSET);
  constant("MOS65XX_OP_REG_OFFSET", MOS65XX_OP_REG_OFFSET);
  constant("MOS65XX_OP_IMM_OFFSET", MOS65XX_OP_IMM_OFFSET);
  constant("MOS65XX_OP_MEM_OFFSET", MOS65XX_OP_MEM_OFFSET);

  // cs_ppc
  constant("PPC_SIZE", PPC_SIZE);
  constant("PPC_BC_OFFSET", PPC_BC_OFFSET);
  constant("PPC_BH_OFFSET", PPC_BH_OFFSET);
  constant("PPC_UPDATE_CR0_OFFSET", PPC_UPDATE_CR0_OFFSET);
  constant("PPC_OP_COUNT_OFFSET", PPC_OP_COUNT_OFFSET);

  // cs_ppc_op
  constant("PPC_OP_SIZE", PPC_OP_SIZE);
  constant("PPC_OP_OFFSET", PPC_OP_OFFSET);
  constant("PPC_OP_TYPE_OFFSET", PPC_OP_TYPE_OFFSET);
  constant("PPC_OP_REG_OFFSET", PPC_OP_REG_OFFSET);
  constant("PPC_OP_IMM_OFFSET", PPC_OP_IMM_OFFSET);

  // ppc_op_mem
  constant("PPC_OP_MEM_OFFSET", PPC_OP_MEM_OFFSET);
  constant("PPC_OP_MEM_BASE_OFFSET", PPC_OP_MEM_BASE_OFFSET);
  constant("PPC_OP_MEM_DISP_OFFSET", PPC_OP_MEM_DISP_OFFSET);

  // ppc_op_crx
  constant("PPC_OP_CRX_OFFSET", PPC_OP_CRX_OFFSET);
  constant("PPC_OP_CRX_SCALE_OFFSET", PPC_OP_CRX_SCALE_OFFSET);
  constant("PPC_OP_CRX_REG_OFFSET", PPC_OP_CRX_REG_OFFSET);
  constant("PPC_OP_CRX_COND_OFFSET", PPC_OP_CRX_COND_OFFSET);

  // cs_riscv
  constant("RISCV_SIZE", RISCV_SIZE);
  constant("RISCV_NEED_EFFECTIVE_ADDR_OFFSET", RISCV_NEED_EFFECTIVE_ADDR_OFFSET);
  constant("RISCV_OP_COUNT_OFFSET", RISCV_OP_COUNT_OFFSET);

  // cs_riscv_op
  constant("RISCV_OP_SIZE", RISCV_OP_SIZE);
  constant("RISCV_OP_OFFSET", RISCV_OP_OFFSET);
  constant("RISCV_OP_TYPE_OFFSET", RISCV_OP_TYPE_OFFSET);
  constant("RISCV_OP_REG_OFFSET", RISCV_OP_REG_OFFSET);
  constant("RISCV_OP_IMM_OFFSET", RISCV_OP_IMM_OFFSET);

  // riscv_op_mem
  constant("RISCV_OP_MEM_OFFSET", RISCV_OP_MEM_OFFSET);
  constant("RISCV_OP_MEM_BASE_OFFSET", RISCV_OP_MEM_BASE_OFFSET);
  constant("RISCV_OP_MEM_DISP_OFFSET", RISCV_OP_MEM_DISP_OFFSET);

  // cs_sh
  constant("SH_SIZE", SH_SIZE);
  constant("SH_INSN_OFFSET", SH_INSN_OFFSET);
  constant("SH_SIZE_OFFSET", SH_SIZE_OFFSET);
  constant("SH_OP_COUNT_OFFSET", SH_OP_COUNT_OFFSET);

  // cs_sh_op
  constant("SH_OP_SIZE", SH_OP_SIZE);
  constant("SH_OP_OFFSET", SH_OP_OFFSET);
  constant("SH_OP_TYPE_OFFSET", SH_OP_TYPE_OFFSET);
  constant("SH_OP_IMM_OFFSET", SH_OP_IMM_OFFSET);
  constant("SH_OP_REG_OFFSET", SH_OP_REG_OFFSET);

  // sh_op_mem
  constant("SH_OP_MEM_OFFSET", SH_OP_MEM_OFFSET);
  constant("SH_OP_MEM_ADDRESS_OFFSET", SH_OP_MEM_ADDRESS_OFFSET);
  constant("SH_OP_MEM_REG_OFFSET", SH_OP_MEM_REG_OFFSET);
  constant("SH_OP_MEM_DISP_OFFSET", SH_OP_MEM_DISP_OFFSET);

  // sh_op_dsp
  constant("SH_OP_DSP_OFFSET", SH_OP_DSP_OFFSET);
  constant("SH_OP_DSP_INSN_OFFSET", SH_OP_DSP_INSN_OFFSET);
  constant("SH_OP_DSP_OPERAND_OFFSET", SH_OP_DSP_OPERAND_OFFSET);
  constant("SH_OP_DSP_REG_OFFSET", SH_OP_DSP_REG_OFFSET);
  constant("SH_OP_DSP_CC_OFFSET", SH_OP_DSP_CC_OFFSET);
  constant("SH_OP_DSP_IMM_OFFSET", SH_OP_DSP_IMM_OFFSET);
  constant("SH_OP_DSP_SIZE_OFFSET", SH_OP_DSP_SIZE_OFFSET);

  // cs_sparc
  constant("SPARC_SIZE", SPARC_SIZE);
  constant("SPARC_CC_OFFSET", SPARC_CC_OFFSET);
  constant("SPARC_HINT_OFFSET", SPARC_HINT_OFFSET);
  constant("SPARC_OP_COUNT_OFFSET", SPARC_OP_COUNT_OFFSET);

  // cs_sparc_op
  constant("SPARC_OP_SIZE", SPARC_OP_SIZE);
  constant("SPARC_OP_OFFSET", SPARC_OP_OFFSET);
  constant("SPARC_OP_TYPE_OFFSET", SPARC_OP_TYPE_OFFSET);
  constant("SPARC_OP_REG_OFFSET", SPARC_OP_REG_OFFSET);
  constant("SPARC_OP_IMM_OFFSET", SPARC_OP_IMM_OFFSET);

  // sparc_op_mem
  constant("SPARC_OP_MEM_OFFSET", SPARC_OP_MEM_OFFSET);
  constant("SPARC_OP_MEM_BASE_OFFSET", SPARC_OP_MEM_BASE_OFFSET);
  constant("SPARC_OP_MEM_INDEX_OFFSET", SPARC_OP_MEM_INDEX_OFFSET);
  constant("SPARC_OP_MEM_DISP_OFFSET", SPARC_OP_MEM_DISP_OFFSET);

  // cs_sysz
  constant("SYSZ_SIZE", SYSZ_SIZE);
  constant("SYSZ_CC_OFFSET", SYSZ_CC_OFFSET);
  constant("SYSZ_OP_COUNT_OFFSET", SYSZ_OP_COUNT_OFFSET);

  // cs_sysz_op
  constant("SYSZ_OP_SIZE", SYSZ_OP_SIZE);
  constant("SYSZ_OP_OFFSET", SYSZ_OP_OFFSET);
  constant("SYSZ_OP_TYPE_OFFSET", SYSZ_OP_TYPE_OFFSET);
  constant("SYSZ_OP_REG_OFFSET", SYSZ_OP_REG_OFFSET);
  constant("SYSZ_OP_IMM_OFFSET", SYSZ_OP_IMM_OFFSET);

  // sysz_op_mem
  constant("SYSZ_OP_MEM_OFFSET", SYSZ_OP_MEM_OFFSET);
  constant("SYSZ_OP_MEM_BASE_OFFSET", SYSZ_OP_MEM_BASE_OFFSET);
  constant("SYSZ_OP_MEM_INDEX_OFFSET", SYSZ_OP_MEM_INDEX_OFFSET);
  constant("SYSZ_OP_MEM_LENGTH_OFFSET", SYSZ_OP_MEM_LENGTH_OFFSET);
  constant("SYSZ_OP_MEM_DISP_OFFSET", SYSZ_OP_MEM_DISP_OFFSET);

  // cs_tms320c64x
  constant("TMS320C64X_SIZE", TMS320C64X_SIZE);
  constant("TMS320C64X_OP_COUNT_OFFSET", TMS320C64X_OP_COUNT_OFFSET);
  constant("TMS320C64X_CONDITION_OFFSET", TMS320C64X_CONDITION_OFFSET);
  constant("TMS320C64X_CONDITION_REG_OFFSET", TMS320C64X_CONDITION_REG_OFFSET);
  constant("TMS320C64X_CONDITION_ZERO_OFFSET", TMS320C64X_CONDITION_ZERO_OFFSET);
  constant("TMS320C64X_FUNIT_OFFSET", TMS320C64X_FUNIT_OFFSET);
  constant("TMS320C64X_FUNIT_UNIT_OFFSET", TMS320C64X_FUNIT_UNIT_OFFSET);
  constant("TMS320C64X_FUNIT_SIDE_OFFSET", TMS320C64X_FUNIT_SIDE_OFFSET);
  constant("TMS320C64X_FUNIT_CROSSPATH_OFFSET", TMS320C64X_FUNIT_CROSSPATH_OFFSET);
  constant("TMS320C64X_PARALLEL_OFFSET", TMS320C64X_PARALLEL_OFFSET);

  // cs_tms320c64x_op
  constant("TMS320C64X_OP_SIZE", TMS320C64X_OP_SIZE);
  constant("TMS320C64X_OP_OFFSET", TMS320C64X_OP_OFFSET);
  constant("TMS320C64X_OP_TYPE_OFFSET", TMS320C64X_OP_TYPE_OFFSET);
  constant("TMS320C64X_OP_REG_OFFSET", TMS320C64X_OP_REG_OFFSET);
  constant("TMS320C64X_OP_IMM_OFFSET", TMS320C64X_OP_IMM_OFFSET);

  // tms320c64x_op_mem
  constant("TMS320C64X_OP_MEM_OFFSET", TMS320C64X_OP_MEM_OFFSET);
  constant("TMS320C64X_OP_MEM_BASE_OFFSET", TMS320C64X_OP_MEM_BASE_OFFSET);
  constant("TMS320C64X_OP_MEM_DISP_OFFSET", TMS320C64X_OP_MEM_DISP_OFFSET);
  constant("TMS320C64X_OP_MEM_UNIT_OFFSET", TMS320C64X_OP_MEM_UNIT_OFFSET);
  constant("TMS320C64X_OP_MEM_SCALED_OFFSET", TMS320C64X_OP_MEM_SCALED_OFFSET);
  constant("TMS320C64X_OP_MEM_DISPTYPE_OFFSET", TMS320C64X_OP_MEM_DISPTYPE_OFFSET);
  constant("TMS320C64X_OP_MEM_DIRECTION_OFFSET", TMS320C64X_OP_MEM_DIRECTION_OFFSET);
  constant("TMS320C64X_OP_MEM_MODIFY_OFFSET", TMS320C64X_OP_MEM_MODIFY_OFFSET);

  // cs_tricore
  constant("TRICORE_SIZE", TRICORE_SIZE);
  constant("TRICORE_OP_COUNT_OFFSET", TRICORE_OP_COUNT_OFFSET);
  constant("TRICORE_UPDATE_FLAGS_OFFSET", TRICORE_UPDATE_FLAGS_OFFSET);

  // cs_tricore_op
  constant("TRICORE_OP_SIZE", TRICORE_OP_SIZE);
  constant("TRICORE_OP_OFFSET", TRICORE_OP_OFFSET);
  constant("TRICORE_OP_TYPE_OFFSET", TRICORE_OP_TYPE_OFFSET);
  constant("TRICORE_OP_REG_OFFSET", TRICORE_OP_REG_OFFSET);
  constant("TRICORE_OP_IMM_OFFSET", TRICORE_OP_IMM_OFFSET);
  constant("TRICORE_OP_ACCESS_OFFSET", TRICORE_OP_ACCESS_OFFSET);

  // tricore_op_mem
  constant("TRICORE_OP_MEM_OFFSET", TRICORE_OP_MEM_OFFSET);
  constant("TRICORE_OP_MEM_BASE_OFFSET", TRICORE_OP_MEM_BASE_OFFSET);
  constant("TRICORE_OP_MEM_DISP_OFFSET", TRICORE_OP_MEM_DISP_OFFSET);

  // cs_wasm
  constant("WASM_SIZE", WASM_SIZE);
  constant("WASM_OP_COUNT_OFFSET", WASM_OP_COUNT_OFFSET);

  // cs_wasm_op
  constant("WASM_OP_SIZE", WASM_OP_SIZE);
  constant("WASM_OP_OFFSET", WASM_OP_OFFSET);
  constant("WASM_OP_TYPE_OFFSET", WASM_OP_TYPE_OFFSET);
  constant("WASM_OP_SIZE_OFFSET", WASM_OP_SIZE_OFFSET);
  constant("WASM_OP_INT7_OFFSET", WASM_OP_INT7_OFFSET);
  constant("WASM_OP_VARUINT32_OFFSET", WASM_OP_VARUINT32_OFFSET);
  constant("WASM_OP_VARUINT64_OFFSET", WASM_OP_VARUINT64_OFFSET);
  constant("WASM_OP_UINT32_OFFSET", WASM_OP_UINT32_OFFSET);
  constant("WASM_OP_UINT64_OFFSET", WASM_OP_UINT64_OFFSET);
  constant("WASM_OP_IMMEDIATE_OFFSET", WASM_OP_IMMEDIATE_OFFSET);

  // cs_wasm_brtable
  constant("WASM_OP_BRTABLE_OFFSET", WASM_OP_BRTABLE_OFFSET);
  constant("WASM_OP_BRTABLE_LENGTH_OFFSET", WASM_OP_BRTABLE_LENGTH_OFFSET);
  constant("WASM_OP_BRTABLE_ADDRESS_OFFSET", WASM_OP_BRTABLE_ADDRESS_OFFSET);
  constant("WASM_OP_BRTABLE_DEFAULT_TARGET_OFFSET", WASM_OP_BRTABLE_DEFAULT_TARGET_OFFSET);

  // cs_x86
  constant("X86_SIZE", X86_SIZE);
  constant("X86_PREFIX_OFFSET", X86_PREFIX_OFFSET);
  constant("X86_OPCODE_OFFSET", X86_OPCODE_OFFSET);
  constant("X86_REX_OFFSET", X86_REX_OFFSET);
  constant("X86_ADDR_SIZE_OFFSET", X86_ADDR_SIZE_OFFSET);
  constant("X86_MODRM_OFFSET", X86_MODRM_OFFSET);
  constant("X86_SIB_OFFSET", X86_SIB_OFFSET);
  constant("X86_DISP_OFFSET", X86_DISP_OFFSET);
  constant("X86_SIB_INDEX_OFFSET", X86_SIB_INDEX_OFFSET);
  constant("X86_SIB_SCALE_OFFSET", X86_SIB_SCALE_OFFSET);
  constant("X86_SIB_BASE_OFFSET", X86_SIB_BASE_OFFSET);
  constant("X86_XOP_CC_OFFSET", X86_XOP_CC_OFFSET);
  constant("X86_SSE_CC_OFFSET", X86_SSE_CC_OFFSET);
  constant("X86_AVX_CC_OFFSET", X86_AVX_CC_OFFSET);
  constant("X86_AVX_SAE_OFFSET", X86_AVX_SAE_OFFSET);
  constant("X86_AVX_RM_OFFSET", X86_AVX_RM_OFFSET);
  constant("X86_EFLAGS_OFFSET", X86_EFLAGS_OFFSET);
  constant("X86_FPU_FLAGS_OFFSET", X86_FPU_FLAGS_OFFSET);
  constant("X86_OP_COUNT_OFFSET", X86_OP_COUNT_OFFSET);

  // cs_x86_encoding
  constant("X86_ENCODING_SIZE", X86_ENCODING_SIZE);
  constant("X86_ENCODING_MODRM_OFFSET_OFFSET", X86_ENCODING_MODRM_OFFSET_OFFSET);
  constant("X86_ENCODING_DISP_OFFSET_OFFSET", X86_ENCODING_DISP_OFFSET_OFFSET);
  constant("X86_ENCODING_DISP_SIZE_OFFSET", X86_ENCODING_DISP_SIZE_OFFSET);
  constant("X86_ENCODING_IMM_OFFSET_OFFSET", X86_ENCODING_IMM_OFFSET_OFFSET);
  constant("X86_ENCODING_IMM_SIZE_OFFSET", X86_ENCODING_IMM_SIZE_OFFSET);

  // cs_x86_op
  constant("X86_OP_SIZE", X86_OP_SIZE);
  constant("X86_OP_OFFSET", X86_OP_OFFSET);
  constant("X86_OP_TYPE_OFFSET", X86_OP_TYPE_OFFSET);
  constant("X86_OP_REG_OFFSET", X86_OP_REG_OFFSET);
  constant("X86_OP_IMM_OFFSET", X86_OP_IMM_OFFSET);
  constant("X86_OP_SIZE_OFFSET", X86_OP_SIZE_OFFSET);
  constant("X86_OP_ACCESS_OFFSET", X86_OP_ACCESS_OFFSET);
  constant("X86_OP_AVX_BCAST_OFFSET", X86_OP_AVX_BCAST_OFFSET);
  constant("X86_OP_AVX_ZERO_OP_MASK_OFFSET", X86_OP_AVX_ZERO_OP_MASK_OFFSET);

  // x86_op_mem
  constant("X86_OP_MEM_OFFSET", X86_OP_MEM_OFFSET);
  constant("X86_OP_MEM_SEGMENT_OFFSET", X86_OP_MEM_SEGMENT_OFFSET);
  constant("X86_OP_MEM_BASE_OFFSET", X86_OP_MEM_BASE_OFFSET);
  constant("X86_OP_MEM_INDEX_OFFSET", X86_OP_MEM_INDEX_OFFSET);
  constant("X86_OP_MEM_SCALE_OFFSET", X86_OP_MEM_SCALE_OFFSET);
  constant("X86_OP_MEM_DISP_OFFSET", X86_OP_MEM_DISP_OFFSET);

  // cs_xcore
  constant("XCORE_SIZE", XCORE_SIZE);
  constant("XCODE_OP_COUNT_OFFSET", XCODE_OP_COUNT_OFFSET);

  // cs_x86_op
  constant("XCORE_OP_SIZE", XCORE_OP_SIZE);
  constant("XCODE_OP_OFFSET", XCODE_OP_OFFSET);
  constant("XCODE_OP_TYPE_OFFSET", XCODE_OP_TYPE_OFFSET);
  constant("XCODE_OP_REG_OFFSET", XCODE_OP_REG_OFFSET);

  // xcore_op_mem
  constant("XCODE_OP_MEM_OFFSET", XCODE_OP_MEM_OFFSET);
  constant("XCODE_OP_MEM_BASE_OFFSET", XCODE_OP_MEM_BASE_OFFSET);
  constant("XCODE_OP_MEM_INDEX_OFFSET", XCODE_OP_MEM_INDEX_OFFSET);
  constant("XCODE_OP_MEM_DISP_OFFSET", XCODE_OP_MEM_DISP_OFFSET);
  constant("XCODE_OP_MEM_DIRECT_OFFSET", XCODE_OP_MEM_DIRECT_OFFSET);

}