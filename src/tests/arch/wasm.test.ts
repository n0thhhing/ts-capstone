import { expect, test } from 'bun:test';
import CS from '../../capstone';

test('CS.ARCH_WASM', () => {
  const buffer = new Uint8Array([
    0x20, 0x00, 0x20, 0x01, 0x41, 0x20, 0x10, 0xc9, 0x01, 0x45, 0x0b,
  ]);
  const disassembler = new CS.CAPSTONE(CS.ARCH_WASM, 0);
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
      id: 32,
      address: 4096,
      size: 2,
      mnemonic: 'get_local',
      op_str: '0x0',
      bytes: new Uint8Array([32, 0]),
    },
    {
      id: 32,
      address: 4098,
      size: 2,
      mnemonic: 'get_local',
      op_str: '0x1',
      bytes: new Uint8Array([32, 1]),
    },
    {
      id: 65,
      address: 4100,
      size: 2,
      mnemonic: 'i32.const',
      op_str: '0x20',
      bytes: new Uint8Array([65, 32]),
    },
    {
      id: 16,
      address: 4102,
      size: 3,
      mnemonic: 'call',
      op_str: '0xc9',
      bytes: new Uint8Array([16, 201, 1]),
    },
    {
      id: 69,
      address: 4105,
      size: 1,
      mnemonic: 'i32.eqz',
      op_str: '',
      bytes: new Uint8Array([69]),
    },
    {
      id: 11,
      address: 4106,
      size: 1,
      mnemonic: 'end',
      op_str: '',
      bytes: new Uint8Array([11]),
    },
  ]);

  disassembler.close();
});
