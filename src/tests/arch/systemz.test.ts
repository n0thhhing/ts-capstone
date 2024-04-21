import { expect, test } from 'bun:test';
import cs from '../../wrapper';

test('cs.ARCH_SYSZ', () => {
  const buffer = new Uint8Array([
    0xed, 0x00, 0x00, 0x00, 0x00, 0x1a, 0x5a, 0x0f, 0x1f, 0xff, 0xc2, 0x09,
    0x80, 0x00, 0x00, 0x00, 0x07, 0xf7, 0xeb, 0x2a, 0xff, 0xff, 0x7f, 0x57,
    0xe3, 0x01, 0xff, 0xff, 0x7f, 0x57, 0xeb, 0x00, 0xf0, 0x00, 0x00, 0x24,
    0xb2, 0x4f, 0x00, 0x78, 0xec, 0x18, 0x00, 0x00, 0xc1, 0x7f,
  ]);
  const disassembler = new cs.Capstone(cs.ARCH_SYSZ, cs.MODE_BIG_ENDIAN);
  const insns = disassembler.disasm(buffer, 0x1000);

  expect(insns).toEqual([
    {
      id: 2,
      address: 4096,
      size: 6,
      mnemonic: 'adb',
      op_str: '%f0, 0',
      bytes: [237, 0, 0, 0, 0, 26],
    },
    {
      id: 1,
      address: 4102,
      size: 4,
      mnemonic: 'a',
      op_str: '%r0, 0xfff(%r15, %r1)',
      bytes: [90, 15, 31, 255],
    },
    {
      id: 6,
      address: 4106,
      size: 6,
      mnemonic: 'afi',
      op_str: '%r0, -0x80000000',
      bytes: [194, 9, 128, 0, 0, 0],
    },
    {
      id: 283,
      address: 4112,
      size: 2,
      mnemonic: 'br',
      op_str: '%r7',
      bytes: [7, 247],
    },
    {
      id: 678,
      address: 4114,
      size: 6,
      mnemonic: 'xiy',
      op_str: '0x7ffff(%r15), 0x2a',
      bytes: [235, 42, 255, 255, 127, 87],
    },
    {
      id: 681,
      address: 4120,
      size: 6,
      mnemonic: 'xy',
      op_str: '%r0, 0x7ffff(%r1, %r15)',
      bytes: [227, 1, 255, 255, 127, 87],
    },
    {
      id: 657,
      address: 4126,
      size: 6,
      mnemonic: 'stmg',
      op_str: '%r0, %r0, 0(%r15)',
      bytes: [235, 0, 240, 0, 0, 36],
    },
    {
      id: 383,
      address: 4132,
      size: 4,
      mnemonic: 'ear',
      op_str: '%r7, %a8',
      bytes: [178, 79, 0, 120],
    },
    {
      id: 94,
      address: 4136,
      size: 6,
      mnemonic: 'clije',
      op_str: '%r1, 0xc1, 0x1028',
      bytes: [236, 24, 0, 0, 193, 127],
    },
  ]);

  disassembler.close();
});
