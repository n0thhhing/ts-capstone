import { expect, test, afterAll } from 'bun:test';
import CS, { X86 } from '../capstone';
const cs = new CS.CAPSTONE(CS.ARCH_X86, CS.MODE_16);
const insns = [
  {
    id: 332,
    address: 4096,
    size: 3,
    mnemonic: 'lea',
    op_str: 'cx, [si + 0x32]',
    bytes: [141, 76, 50],
    detail: {
      regs_write: [],
      groups: [],
      regs_read: [],
      regs_read_count: 0,
      regs_write_count: 0,
      groups_count: 0,
      writeback: false,
      x86: {
        prefix: [0, 0, 0, 0],
        opcode: [141, 0, 0, 0],
        rex: 0,
        addr_size: 2,
        modrm: 76,
        sib: 0,
        disp: 50,
        sib_index: 0,
        sib_scale: 0,
        sib_base: 0,
        xop_cc: 0,
        sse_cc: 0,
        avx_cc: 0,
        avx_sae: false,
        avx_rm: 0,
        eflags: 0,
        fpu_flags: 0,
        op_count: 2,
        operands: [
          {
            size: 2,
            access: 2,
            avx_bcast: 0,
            avx_zero_opmask: false,
            type: 1,
            reg: 12,
          },
          {
            size: 2,
            access: 1,
            avx_bcast: 0,
            avx_zero_opmask: false,
            type: 3,
            mem: { segment: 0, base: 45, index: 0, scale: 1, disp: 50 },
          },
        ],
        encoding: {
          modrm_offset: 1,
          disp_offset: 2,
          disp_size: 1,
          imm_offset: 0,
          imm_size: 0,
        },
      },
    },
  },
  {
    id: 512,
    address: 4099,
    size: 2,
    mnemonic: 'or',
    op_str: 'byte ptr [bx + di], al',
    bytes: [8, 1],
    detail: {
      regs_write: [25],
      groups: [],
      regs_read: [],
      regs_read_count: 0,
      regs_write_count: 1,
      groups_count: 0,
      writeback: false,
      x86: {
        prefix: [0, 0, 0, 0],
        opcode: [8, 0, 0, 0],
        rex: 0,
        addr_size: 2,
        modrm: 1,
        sib: 0,
        disp: 0,
        sib_index: 0,
        sib_scale: 0,
        sib_base: 0,
        xop_cc: 0,
        sse_cc: 0,
        avx_cc: 0,
        avx_sae: false,
        avx_rm: 0,
        eflags: 0,
        fpu_flags: 6291484,
        op_count: 2,
        operands: [
          {
            size: 1,
            access: 3,
            avx_bcast: 0,
            avx_zero_opmask: false,
            type: 3,
            mem: { segment: 0, base: 8, index: 14, scale: 1, disp: 0 },
          },
          {
            size: 1,
            access: 1,
            avx_bcast: 0,
            avx_zero_opmask: false,
            type: 1,
            reg: 2,
          },
        ],
        encoding: {
          modrm_offset: 1,
          disp_offset: 0,
          disp_size: 0,
          imm_offset: 0,
          imm_size: 0,
        },
      },
    },
  },
  {
    id: 15,
    address: 4101,
    size: 4,
    mnemonic: 'fadd',
    op_str: 'dword ptr [bx + di + 0x34c6]',
    bytes: [216, 129, 198, 52],
    detail: {
      regs_write: [31],
      groups: [169],
      regs_read: [],
      regs_read_count: 0,
      regs_write_count: 1,
      groups_count: 1,
      writeback: false,
      x86: {
        prefix: [0, 0, 0, 0],
        opcode: [216, 0, 0, 0],
        rex: 0,
        addr_size: 2,
        modrm: 129,
        sib: 0,
        disp: 13510,
        sib_index: 0,
        sib_scale: 0,
        sib_base: 0,
        xop_cc: 0,
        sse_cc: 0,
        avx_cc: 0,
        avx_sae: false,
        avx_rm: 0,
        eflags: 0,
        fpu_flags: 53250,
        op_count: 1,
        operands: [
          {
            size: 4,
            access: 1,
            avx_bcast: 0,
            avx_zero_opmask: false,
            type: 3,
            mem: { segment: 0, base: 8, index: 14, scale: 1, disp: 13510 },
          },
        ],
        encoding: {
          modrm_offset: 1,
          disp_offset: 2,
          disp_size: 2,
          imm_offset: 0,
          imm_size: 0,
        },
      },
    },
  },
];

test('X86.REL_ADDR', () => {
  const addr_4149 = X86.REL_ADDR(insns[0]);
  const addr_4101 = X86.REL_ADDR(insns[1]);
  expect(addr_4149).toBe(4149);
  expect(addr_4101).toBe(4101);
});

test('CS.INSN_OFFSET', () => {
  const idx_1 = CS.INSN_OFFSET(insns, 1);
  const idx_2 = CS.INSN_OFFSET(insns, 2);
  expect(idx_1).toBe(0);
  expect(idx_2).toBe(3);
});

afterAll(() => {
  cs.close();
});
