import { expect, test } from 'bun:test';
import cs from '../../capstone';

test('cs.ARCH_ARM64(AARCH64)', () => {
  const buffer = new Uint8Array([
    0x09, 0x00, 0x38, 0xd5, 0xbf, 0x40, 0x00, 0xd5, 0x0c, 0x05, 0x13, 0xd5,
    0x20, 0x50, 0x02, 0x0e, 0x20, 0xe4, 0x3d, 0x0f, 0x00, 0x18, 0xa0, 0x5f,
    0xa2, 0x00, 0xae, 0x9e, 0x9f, 0x37, 0x03, 0xd5, 0xbf, 0x33, 0x03, 0xd5,
    0xdf, 0x3f, 0x03, 0xd5, 0x21, 0x7c, 0x02, 0x9b, 0x21, 0x7c, 0x00, 0x53,
    0x00, 0x40, 0x21, 0x4b, 0xe1, 0x0b, 0x40, 0xb9, 0x20, 0x04, 0x81, 0xda,
    0x20, 0x08, 0x02, 0x8b, 0x10, 0x5b, 0xe8, 0x3c, 0xfd, 0x7b, 0xba, 0xa9,
    0xfd, 0xc7, 0x43, 0xf8,
  ]);

  const disassembler = new cs.Capstone(cs.ARCH_ARM64, cs.MODE_ARM);
  disassembler.option(cs.OPT_DETAIL, true);
  const insns = disassembler.disasm(buffer, 0x1000);

  expect(
    insns.map(({ id, address, size, mnemonic, op_str, bytes }) => ({
      id,
      address,
      size,
      mnemonic,
      op_str,
      bytes,
    })),
  ).toEqual([
    {
      id: 662,
      address: 4096,
      size: 4,
      mnemonic: 'mrs',
      op_str: 'x9, midr_el1',
      bytes: [9, 0, 56, 213],
    },
    {
      id: 664,
      address: 4100,
      size: 4,
      mnemonic: 'msr',
      op_str: 'spsel, #0',
      bytes: [191, 64, 0, 213],
    },
    {
      id: 664,
      address: 4104,
      size: 4,
      mnemonic: 'msr',
      op_str: 'dbgdtrtx_el0, x12',
      bytes: [12, 5, 19, 213],
    },
    {
      id: 1120,
      address: 4108,
      size: 4,
      mnemonic: 'tbx',
      op_str: 'v0.8b, {v1.16b, v2.16b, v3.16b}, v2.8b',
      bytes: [32, 80, 2, 14],
    },
    {
      id: 785,
      address: 4112,
      size: 4,
      mnemonic: 'scvtf',
      op_str: 'v0.2s, v1.2s, #3',
      bytes: [32, 228, 61, 15],
    },
    {
      id: 366,
      address: 4116,
      size: 4,
      mnemonic: 'fmla',
      op_str: 's0, s0, v0.s[3]',
      bytes: [0, 24, 160, 95],
    },
    {
      id: 379,
      address: 4120,
      size: 4,
      mnemonic: 'fmov',
      op_str: 'x2, v5.d[1]',
      bytes: [162, 0, 174, 158],
    },
    {
      id: 284,
      address: 4124,
      size: 4,
      mnemonic: 'dsb',
      op_str: 'nsh',
      bytes: [159, 55, 3, 213],
    },
    {
      id: 282,
      address: 4128,
      size: 4,
      mnemonic: 'dmb',
      op_str: 'osh',
      bytes: [191, 51, 3, 213],
    },
    {
      id: 430,
      address: 4132,
      size: 4,
      mnemonic: 'isb',
      op_str: '',
      bytes: [223, 63, 3, 213],
    },
    {
      id: 666,
      address: 4136,
      size: 4,
      mnemonic: 'mul',
      op_str: 'x1, x1, x2',
      bytes: [33, 124, 2, 155],
    },
    {
      id: 645,
      address: 4140,
      size: 4,
      mnemonic: 'lsr',
      op_str: 'w1, w1, #0',
      bytes: [33, 124, 0, 83],
    },
    {
      id: 1082,
      address: 4144,
      size: 4,
      mnemonic: 'sub',
      op_str: 'w0, w0, w1, uxtw',
      bytes: [0, 64, 33, 75],
    },
    {
      id: 558,
      address: 4148,
      size: 4,
      mnemonic: 'ldr',
      op_str: 'w1, [sp, #8]',
      bytes: [225, 11, 64, 185],
    },
    {
      id: 149,
      address: 4152,
      size: 4,
      mnemonic: 'cneg',
      op_str: 'x0, x1, ne',
      bytes: [32, 4, 129, 218],
    },
    {
      id: 6,
      address: 4156,
      size: 4,
      mnemonic: 'add',
      op_str: 'x0, x1, x2, lsl #2',
      bytes: [32, 8, 2, 139],
    },
    {
      id: 558,
      address: 4160,
      size: 4,
      mnemonic: 'ldr',
      op_str: 'q16, [x24, w8, uxtw #4]',
      bytes: [16, 91, 232, 60],
    },
    {
      id: 1035,
      address: 4164,
      size: 4,
      mnemonic: 'stp',
      op_str: 'x29, x30, [sp, #-0x60]!',
      bytes: [253, 123, 186, 169],
    },
    {
      id: 558,
      address: 4168,
      size: 4,
      mnemonic: 'ldr',
      op_str: 'x29, [sp], #0x3c',
      bytes: [253, 199, 67, 248],
    },
  ]);

  disassembler.close();
});
