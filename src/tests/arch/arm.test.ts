import { expect, test } from 'bun:test';
import cs from '../../wrapper';

test('cs.ARCH_ARM', () => {
  const buffer = new Uint8Array([
    0x86, 0x48, 0x60, 0xf4, 0x4d, 0x0f, 0xe2, 0xf4, 0xed, 0xff, 0xff, 0xeb,
    0x04, 0xe0, 0x2d, 0xe5, 0x00, 0x00, 0x00, 0x00, 0xe0, 0x83, 0x22, 0xe5,
    0xf1, 0x02, 0x03, 0x0e, 0x00, 0x00, 0xa0, 0xe3, 0x02, 0x30, 0xc1, 0xe7,
    0x00, 0x00, 0x53, 0xe3, 0x00, 0x02, 0x01, 0xf1, 0x05, 0x40, 0xd0, 0xe8,
    0xf4, 0x80, 0x00, 0x00,
  ]);

  const disassembler = new cs.Capstone(cs.ARCH_ARM, 0);
  const insns = disassembler.disasm(buffer, 0x1000);

  expect(insns).toEqual([
    {
      id: 358,
      address: 4096,
      size: 4,
      mnemonic: 'vld2.32',
      op_str: '{d20, d21}, [r0], r6',
      bytes: [134, 72, 96, 244],
    },
    {
      id: 360,
      address: 4100,
      size: 4,
      mnemonic: 'vld4.16',
      op_str: '{d16[], d17[], d18[], d19[]}, [r2]!',
      bytes: [77, 15, 226, 244],
    },
    {
      id: 16,
      address: 4104,
      size: 4,
      mnemonic: 'bl',
      op_str: '#0xfc4',
      bytes: [237, 255, 255, 235],
    },
    {
      id: 240,
      address: 4108,
      size: 4,
      mnemonic: 'str',
      op_str: 'lr, [sp, #-4]!',
      bytes: [4, 224, 45, 229],
    },
    {
      id: 9,
      address: 4112,
      size: 4,
      mnemonic: 'andeq',
      op_str: 'r0, r0, r0',
      bytes: [0, 0, 0, 0],
    },
    {
      id: 240,
      address: 4116,
      size: 4,
      mnemonic: 'str',
      op_str: 'r8, [r2, #-0x3e0]!',
      bytes: [224, 131, 34, 229],
    },
    {
      id: 100,
      address: 4120,
      size: 4,
      mnemonic: 'mcreq',
      op_str: 'p2, #0, r0, c3, c1, #7',
      bytes: [241, 2, 3, 14],
    },
    {
      id: 106,
      address: 4124,
      size: 4,
      mnemonic: 'mov',
      op_str: 'r0, #0',
      bytes: [0, 0, 160, 227],
    },
    {
      id: 241,
      address: 4128,
      size: 4,
      mnemonic: 'strb',
      op_str: 'r3, [r1, r2]',
      bytes: [2, 48, 193, 231],
    },
    {
      id: 29,
      address: 4132,
      size: 4,
      mnemonic: 'cmp',
      op_str: 'r3, #0',
      bytes: [0, 0, 83, 227],
    },
    {
      id: 158,
      address: 4136,
      size: 4,
      mnemonic: 'setend',
      op_str: 'be',
      bytes: [0, 2, 1, 241],
    },
    {
      id: 79,
      address: 4140,
      size: 4,
      mnemonic: 'ldm',
      op_str: 'r0, {r0, r2, lr} ^',
      bytes: [5, 64, 208, 232],
    },
    {
      id: 243,
      address: 4144,
      size: 4,
      mnemonic: 'strdeq',
      op_str: 'r8, sb, [r0], -r4',
      bytes: [244, 128, 0, 0],
    },
  ]);

  disassembler.close();
});
