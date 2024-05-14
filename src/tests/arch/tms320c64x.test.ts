import { expect, test } from 'bun:test';
import CS from '../../capstone';

test('CS.ARCH_TMS320C64X', () => {
  const buffer = new Uint8Array([
    0x01, 0xac, 0x88, 0x40, 0x81, 0xac, 0x88, 0x43, 0x00, 0x00, 0x00, 0x00,
    0x02, 0x90, 0x32, 0x96, 0x02, 0x80, 0x46, 0x9e, 0x05, 0x3c, 0x83, 0xe6,
    0x0b, 0x0c, 0x8b, 0x24,
  ]);
  const disassembler = new CS.CAPSTONE(CS.ARCH_TMS320C64X, 2147483648);
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
      id: 3,
      address: 4096,
      size: 4,
      mnemonic: 'add.D1',
      op_str: 'a11, a4, a3',
      bytes: new Uint8Array([1, 172, 136, 64]),
    },
    {
      id: 3,
      address: 4100,
      size: 4,
      mnemonic: '[ a1] add.D2',
      op_str: 'b11, b4, b3\t||',
      bytes: new Uint8Array([129, 172, 136, 67]),
    },
    {
      id: 83,
      address: 4104,
      size: 4,
      mnemonic: 'NOP',
      op_str: '',
      bytes: new Uint8Array([0, 0, 0, 0]),
    },
    {
      id: 43,
      address: 4108,
      size: 4,
      mnemonic: 'ldbu.D1T2',
      op_str: '*++a4[1], b5',
      bytes: new Uint8Array([2, 144, 50, 150]),
    },
    {
      id: 43,
      address: 4112,
      size: 4,
      mnemonic: 'ldbu.D2T2',
      op_str: '*+b15[0x46], b5',
      bytes: new Uint8Array([2, 128, 70, 158]),
    },
    {
      id: 44,
      address: 4116,
      size: 4,
      mnemonic: 'lddw.D1T2',
      op_str: '*+a15[4], b11:b10',
      bytes: new Uint8Array([5, 60, 131, 230]),
    },
    {
      id: 47,
      address: 4120,
      size: 4,
      mnemonic: 'ldndw.D1T1',
      op_str: '*+a3(a4), a23:a22',
      bytes: new Uint8Array([11, 12, 139, 36]),
    },
  ]);

  disassembler.close();
});
