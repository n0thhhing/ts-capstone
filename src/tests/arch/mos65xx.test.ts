import { expect, test } from 'bun:test';
import CS from '../../capstone';

test('CS.ARCH_MOS65XX', () => {
  const buffer = new Uint8Array([
    0x07, 0x12, 0x27, 0x12, 0x47, 0x12, 0x67, 0x12, 0x87, 0x12, 0xa7, 0x12,
    0xc7, 0x12, 0xe7, 0x12,
  ]);
  const disassembler = new CS.CAPSTONE(CS.ARCH_MOS65XX, CS.MODE_MOS65XX_W65C02);
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
      id: 62,
      address: 4096,
      size: 2,
      mnemonic: 'rmb0',
      op_str: '0x12',
      bytes: new Uint8Array([7, 18]),
    },
    {
      id: 62,
      address: 4098,
      size: 2,
      mnemonic: 'rmb2',
      op_str: '0x12',
      bytes: new Uint8Array([39, 18]),
    },
    {
      id: 62,
      address: 4100,
      size: 2,
      mnemonic: 'rmb4',
      op_str: '0x12',
      bytes: new Uint8Array([71, 18]),
    },
    {
      id: 62,
      address: 4102,
      size: 2,
      mnemonic: 'rmb6',
      op_str: '0x12',
      bytes: new Uint8Array([103, 18]),
    },
    {
      id: 73,
      address: 4104,
      size: 2,
      mnemonic: 'smb0',
      op_str: '0x12',
      bytes: new Uint8Array([135, 18]),
    },
    {
      id: 73,
      address: 4106,
      size: 2,
      mnemonic: 'smb2',
      op_str: '0x12',
      bytes: new Uint8Array([167, 18]),
    },
    {
      id: 73,
      address: 4108,
      size: 2,
      mnemonic: 'smb4',
      op_str: '0x12',
      bytes: new Uint8Array([199, 18]),
    },
    {
      id: 73,
      address: 4110,
      size: 2,
      mnemonic: 'smb6',
      op_str: '0x12',
      bytes: new Uint8Array([231, 18]),
    },
  ]);

  disassembler.close();
});
