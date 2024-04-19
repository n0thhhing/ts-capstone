import cs from '../wrapper';
import { expect, test } from 'bun:test';

test('OPT_MNEMONIC', () => {
  const buffer = new Uint8Array([
    0x88,
    0x02,
    0x40,
    0xb9, // 0x1008: ldr w8, [x20]
  ]);

  const disassembler = new cs.Capstone(cs.ARCH_ARM64, cs.MODE_ARM);
  disassembler.option(cs.OPT_MNEMONIC, { id: 558, mnemonic: 'load_register' });
  const insns = disassembler.disasm(buffer, 0x1000);

  expect(insns[0]).not.toBe(undefined);
  if (insns[0] && insns[0].mnemonic)
    expect(insns[0].mnemonic).toBe('load_register');
  disassembler.close();
});
