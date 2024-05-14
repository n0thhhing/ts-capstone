import { expect, test } from 'bun:test';
import CS from '../../capstone';

test('CS.ARCH_BPF', () => {
  const buffer = new Uint8Array([
    0x97, 0x09, 0x00, 0x00, 0x37, 0x13, 0x03, 0x00, 0xdc, 0x02, 0x00, 0x00,
    0x20, 0x00, 0x00, 0x00, 0x30, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0xdb, 0x3a, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x84, 0x02, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x6d, 0x33, 0x17, 0x02, 0x00, 0x00, 0x00, 0x00,
  ]);
  const disassembler = new CS.CAPSTONE(CS.ARCH_BPF, CS.MODE_BPF_EXTENDED);
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
      id: 23,
      address: 4096,
      size: 8,
      mnemonic: 'mod64',
      op_str: 'r9, 0x31337',
      bytes: new Uint8Array([151, 9, 0, 0, 55, 19, 3, 0]),
    },
    {
      id: 31,
      address: 4104,
      size: 8,
      mnemonic: 'be32',
      op_str: 'r2',
      bytes: new Uint8Array([220, 2, 0, 0, 32, 0, 0, 0]),
    },
    {
      id: 35,
      address: 4112,
      size: 8,
      mnemonic: 'ldb',
      op_str: '[0x0]',
      bytes: new Uint8Array([48, 0, 0, 0, 0, 0, 0, 0]),
    },
    {
      id: 50,
      address: 4120,
      size: 8,
      mnemonic: 'xadddw',
      op_str: '[r10+0x100], r3',
      bytes: new Uint8Array([219, 58, 0, 1, 0, 0, 0, 0]),
    },
    {
      id: 9,
      address: 4128,
      size: 8,
      mnemonic: 'neg',
      op_str: 'r2',
      bytes: new Uint8Array([132, 2, 0, 0, 0, 0, 0, 0]),
    },
    {
      id: 57,
      address: 4136,
      size: 8,
      mnemonic: 'jsgt',
      op_str: 'r3, r3, +0x217',
      bytes: new Uint8Array([109, 51, 23, 2, 0, 0, 0, 0]),
    },
  ]);

  disassembler.close();
});
