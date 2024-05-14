import { expect, test } from 'bun:test';
import CS from '../../capstone';

test('CS.ARCH_SH', () => {
  const buffer = new Uint8Array([0x32, 0x11, 0x92, 0x0, 0x32, 0x49, 0x31, 0x0]);

  const disassembler = new CS.CAPSTONE(CS.ARCH_SH, CS.MODE_SH2A);
  disassembler.option(CS.OPT_DETAIL, true);
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
      bytes: new Uint8Array([50, 17]),
    },
  ]);

  disassembler.close();
});
