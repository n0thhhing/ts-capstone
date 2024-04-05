import cs from '../wrapper';
import { expect, test } from 'bun:test';

test('disasm ARM64', () => {
  // prettier-ignore
  const buffer = new Uint8Array([
    0x00, 0x00, 0x80, 0xd2, // 0x1000: movz x0, #0
    0xfd, 0xfb, 0xff, 0x17, // 0x1004: b #0xfffffffffffffff8
    0x88, 0x02, 0x40, 0xb9, // 0x1008: ldr w8, [x20]
    0x20, 0x00, 0x02, 0x8b, // 0x100c: add x0, x1, x2
    0x20, 0x00, 0x00, 0xf9, // 0x1010: str x0, [x1]
    0x20, 0x00, 0x42, 0xf8, // 0x1014: ldur x0, [x1, #0x20]
    0x20, 0x88, 0x82, 0x4f, // 0x1018: mul v0.4s, v1.4s, v2.s[2]
  ]);

  const disassembler = new cs.Capstone(cs.ARCH_ARM64, cs.MODE_ARM);
  //disassembler.option(cs.OPT_DETAIL, true);
  const insns = disassembler.disasm(buffer, 0x1000);
  const expectedInstructions = [
    {
      address: 0x1000,
      mnemonic: 'mov',
      op_str: 'x0, #0',
      bytes: [0x00, 0x00, 0x80, 0xd2],
    },
    {
      address: 0x1004,
      mnemonic: 'b',
      op_str: '#0xfffffffffffffff8',
      bytes: [0xfd, 0xfb, 0xff, 0x17],
    },
    {
      address: 0x1008,
      mnemonic: 'ldr',
      op_str: 'w8, [x20]',
      bytes: [0x88, 0x02, 0x40, 0xb9],
    },
    {
      address: 0x100c,
      mnemonic: 'add',
      op_str: 'x0, x1, x2',
      bytes: [0x20, 0x00, 0x02, 0x8b],
    },
    {
      address: 0x1010,
      mnemonic: 'str',
      op_str: 'x0, [x1]',
      bytes: [0x20, 0x00, 0x00, 0xf9],
    },
    {
      address: 0x1014,
      mnemonic: 'ldur',
      op_str: 'x0, [x1, #0x20]',
      bytes: [0x20, 0x00, 0x42, 0xf8],
    },
    {
      address: 0x1018,
      mnemonic: 'mul',
      op_str: 'v0.4s, v1.4s, v2.s[2]',
      bytes: [0x20, 0x88, 0x82, 0x4f],
    },
  ];

  let index = 0;
  for (const insn of insns) {
    const expected = expectedInstructions[index++];
    expect(insn.address).toBe(expected.address);
    expect(insn.mnemonic).toBe(expected.mnemonic);
    expect(insn.op_str).toBe(expected.op_str);
    expect(insn.bytes).toEqual(expected.bytes);
  }

  disassembler.close();
});
