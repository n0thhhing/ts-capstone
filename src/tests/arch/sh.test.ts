import { expect, test } from 'bun:test';
import cs from '../../wrapper';

test('cs.ARCH_SH', () => {
  const buffer = new Uint8Array([0x32, 0x11, 0x92, 0x0, 0x32, 0x49, 0x31, 0x0]);

  const disassembler = new cs.Capstone(cs.ARCH_SH, cs.MODE_SH2A);
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
      id: 89,
      address: 4096,
      size: 2,
      mnemonic: 'mov.l',
      op_str: 'r3,@(8,r1)',
      bytes: [50, 17],
    },
  ]);

  disassembler.close();
});
