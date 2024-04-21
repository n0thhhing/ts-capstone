import { expect, test } from 'bun:test';
import cs from '../../wrapper';

test('cs.ARCH_XCORE', () => {
  const buffer = new Uint8Array([
    0xfe, 0x0f, 0xfe, 0x17, 0x13, 0x17, 0xc6, 0xfe, 0xec, 0x17, 0x97, 0xf8,
    0xec, 0x4f, 0x1f, 0xfd, 0xec, 0x37, 0x07, 0xf2, 0x45, 0x5b, 0xf9, 0xfa,
    0x02, 0x06, 0x1b, 0x10, 0x09, 0xfd, 0xec, 0xa7,
  ]);
  const disassembler = new cs.Capstone(cs.ARCH_XCORE, cs.MODE_BIG_ENDIAN);
  const insns = disassembler.disasm(buffer, 0x1000);

  expect(insns).toEqual([
    {
      id: 43,
      address: 4096,
      size: 2,
      mnemonic: 'get',
      op_str: 'r11, ed',
      bytes: [254, 15],
    },
    {
      id: 66,
      address: 4098,
      size: 2,
      mnemonic: 'ldw',
      op_str: 'et, sp[4]',
      bytes: [254, 23],
    },
    {
      id: 93,
      address: 4100,
      size: 2,
      mnemonic: 'setd',
      op_str: 'res[r3], r4',
      bytes: [19, 23],
    },
    {
      id: 50,
      address: 4102,
      size: 4,
      mnemonic: 'init',
      op_str: 't[r2]:lr, r1',
      bytes: [198, 254, 236, 23],
    },
    {
      id: 26,
      address: 4106,
      size: 4,
      mnemonic: 'divu',
      op_str: 'r9, r1, r3',
      bytes: [151, 248, 236, 79],
    },
    {
      id: 62,
      address: 4110,
      size: 4,
      mnemonic: 'lda16',
      op_str: 'r9, r3[-r11]',
      bytes: [31, 253, 236, 55],
    },
    {
      id: 66,
      address: 4114,
      size: 4,
      mnemonic: 'ldw',
      op_str: 'dp, dp[0x81c5]',
      bytes: [7, 242, 69, 91],
    },
    {
      id: 68,
      address: 4118,
      size: 4,
      mnemonic: 'lmul',
      op_str: 'r11, r0, r2, r5, r8, r10',
      bytes: [249, 250, 2, 6],
    },
    {
      id: 1,
      address: 4122,
      size: 2,
      mnemonic: 'add',
      op_str: 'r1, r2, r3',
      bytes: [27, 16],
    },
    {
      id: 64,
      address: 4124,
      size: 4,
      mnemonic: 'ldaw',
      op_str: 'r8, r2[-9]',
      bytes: [9, 253, 236, 167],
    },
  ]);

  disassembler.close();
});
