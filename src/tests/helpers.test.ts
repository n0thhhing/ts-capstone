import { expect, test, afterAll } from 'bun:test';
import CS, { ARM64 } from '../capstone';

const disassembler = new CS.CAPSTONE(CS.ARCH_ARM64, CS.MODE_ARM);
disassembler.option(CS.OPT_DETAIL, true);

test('reg_write', () => {
  const insn = {
    id: 664,
    address: 4100,
    size: 4,
    mnemonic: 'msr',
    op_str: 'spsel, #0',
    bytes: [191, 64, 0, 213],
    detail: {
      regs_write: [4],
      groups: [6],
      regs_read: [],
      regs_read_count: 0,
      regs_write_count: 1,
      groups_count: 1,
      writeback: false,
      arm64: {
        operands: [
          {
            vector_index: -1,
            vas: 0,
            shift: { type: 0, value: 0 },
            ext: 0,
            access: 2,
            type: 1,
            reg: 218,
          },
          {
            vector_index: -1,
            vas: 0,
            shift: { type: 0, value: 0 },
            ext: 0,
            access: 1,
            type: 1,
            reg: 219,
          },
        ],
        cc: 2,
        update_flags: false,
        writeback: false,
        post_index: false,
        op_count: 2,
      },
    },
  };
  const valid_reg = disassembler.reg_write(insn, 4);
  const invalid_reg = disassembler.reg_write(insn, 20);

  expect(valid_reg).toBe(true);
  expect(invalid_reg).toBe(false);
});

test('reg_read', () => {
  const insn = {
    id: 149,
    address: 4152,
    size: 4,
    mnemonic: 'cneg',
    op_str: 'x0, x1, ne',
    bytes: [32, 4, 129, 218],
    detail: {
      regs_write: [],
      groups: [],
      regs_read: [4],
      regs_read_count: 1,
      regs_write_count: 0,
      groups_count: 0,
      writeback: false,
      arm64: {
        operands: [
          {
            vector_index: -1,
            vas: 0,
            shift: { type: 0, value: 0 },
            ext: 0,
            access: 2,
            type: 1,
            reg: 218,
          },
          {
            vector_index: -1,
            vas: 0,
            shift: { type: 0, value: 0 },
            ext: 0,
            access: 1,
            type: 1,
            reg: 219,
          },
        ],
        cc: 2,
        update_flags: false,
        writeback: false,
        post_index: false,
        op_count: 2,
      },
    },
  };
  const valid_reg = disassembler.reg_read(insn, 4);
  const invalid_reg = disassembler.reg_read(insn, 20);

  expect(valid_reg).toBe(true);
  expect(invalid_reg).toBe(false);
});

test('insn_group', () => {
  const insn = {
    id: 785,
    address: 4112,
    size: 4,
    mnemonic: 'scvtf',
    op_str: 'v0.2s, v1.2s, #3',
    bytes: [32, 228, 61, 15],
    detail: {
      regs_write: [],
      groups: [130],
      regs_read: [],
      regs_read_count: 0,
      regs_write_count: 0,
      groups_count: 1,
      writeback: false,
      arm64: {
        operands: [
          {
            vector_index: -1,
            vas: 0,
            shift: { type: 0, value: 0 },
            ext: 0,
            access: 2,
            type: 1,
            reg: 218,
          },
          {
            vector_index: -1,
            vas: 0,
            shift: { type: 0, value: 0 },
            ext: 0,
            access: 1,
            type: 1,
            reg: 219,
          },
        ],
        cc: 2,
        update_flags: false,
        writeback: false,
        post_index: false,
        op_count: 2,
      },
    },
  };
  const valid_reg = disassembler.insn_group(insn, 130);
  const invalid_reg = disassembler.insn_group(insn, 2);

  expect(valid_reg).toBe(true);
  expect(invalid_reg).toBe(false);
});

test('regs_access', () => {
  const insn = {
    id: 664,
    address: 4100,
    size: 4,
    mnemonic: 'msr',
    op_str: 'spsel, #0',
    bytes: [191, 64, 0, 213],
    detail: {
      regs_write: [4, 10, 11],
      groups: [6],
      regs_read: [],
      regs_read_count: 0,
      regs_write_count: 3,
      groups_count: 1,
      writeback: false,
      arm64: {
        operands: [
          {
            vector_index: -1,
            vas: 0,
            shift: { type: 0, value: 0 },
            ext: 0,
            access: 2,
            type: 1,
            reg: 218,
          },
          {
            vector_index: -1,
            vas: 0,
            shift: { type: 0, value: 0 },
            ext: 0,
            access: 1,
            type: 1,
            reg: 219,
          },
        ],
        cc: 2,
        update_flags: false,
        writeback: false,
        post_index: false,
        op_count: 2,
      },
    },
  };
  const regs = disassembler.regs_access(insn);
  expect(regs).toEqual({
    regs_read: [],
    regs_read_count: 0,
    regs_write: [10, 10, 11],
    regs_write_count: 3,
  });
});

test('op_count', () => {
  const insn = {
    id: 664,
    address: 4100,
    size: 4,
    mnemonic: 'msr',
    op_str: 'spsel, #0',
    bytes: [191, 64, 0, 213],
    detail: {
      regs_write: [4, 10, 11],
      groups: [6],
      regs_read: [],
      regs_read_count: 0,
      regs_write_count: 3,
      groups_count: 1,
      writeback: false,
      arm64: {
        operands: [
          {
            vector_index: -1,
            vas: 0,
            shift: { type: 0, value: 0 },
            ext: 0,
            access: 2,
            type: 1,
            reg: 218,
          },
          {
            vector_index: -1,
            vas: 0,
            shift: { type: 0, value: 0 },
            ext: 0,
            access: 1,
            type: 1,
            reg: 219,
          },
        ],
        cc: 2,
        update_flags: false,
        writeback: false,
        post_index: false,
        op_count: 2,
      },
    },
  };
  const op2 = disassembler.op_count(insn, 1);
  const op0 = disassembler.op_count(insn, 0);
  expect(op2).toBe(2);
  expect(op0).toBe(0);
});

test('op_index', () => {
  const insn = {
    id: 664,
    address: 4104,
    size: 4,
    mnemonic: 'msr',
    op_str: 'dbgdtrtx_el0, x12',
    bytes: [12, 5, 19, 213],
    detail: {
      regs_write: [],
      groups: [6],
      regs_read: [],
      regs_read_count: 0,
      regs_write_count: 0,
      groups_count: 1,
      writeback: false,
      arm64: {
        operands: [
          {
            vector_index: -1,
            vas: 0,
            shift: { type: 0, value: 0 },
            ext: 0,
            access: 2,
            type: 68,
            sys: 38952,
          },
          {
            vector_index: -1,
            vas: 0,
            shift: { type: 0, value: 0 },
            ext: 0,
            access: 1,
            type: 1,
            reg: 230,
          },
        ],
        cc: 0,
        update_flags: false,
        writeback: false,
        post_index: false,
        op_count: 2,
      },
    },
  };

  const failure = disassembler.op_index(insn, ARM64.OP_REG, 2);
  const success = disassembler.op_index(insn, ARM64.OP_REG, 1);
  expect(failure).toBe(-1);
  expect(success).toBe(1);
});

test('name ids', () => {
  expect(disassembler.group_name(2)).toBe('call');
  expect(disassembler.reg_name(183)).toBe('s28');
  expect(disassembler.insn_name(191)).toBe('cpyfm');
});

afterAll(() => {
  disassembler.close();
});
