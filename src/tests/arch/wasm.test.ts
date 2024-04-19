import { expect, test } from 'bun:test';
import cs from '../../wrapper';

test('cs.ARCH_WASM', () => {
  const buffer = new Uint8Array([
    0x20, 0x00, 0x20, 0x01, 0x41, 0x20, 0x10, 0xc9, 0x01, 0x45, 0x0b,
  ]);
  const disassembler = new cs.Capstone(cs.ARCH_WASM, 0);
  const insns = disassembler.disasm(buffer, 0x1000);

  expect(insns).toEqual([
    {
      id: 32,
      address: 4096,
      size: 2,
      mnemonic: 'get_local',
      op_str: '0x0',
      bytes: [32, 0],
    },
    {
      id: 32,
      address: 4098,
      size: 2,
      mnemonic: 'get_local',
      op_str: '0x1',
      bytes: [32, 1],
    },
    {
      id: 65,
      address: 4100,
      size: 2,
      mnemonic: 'i32.const',
      op_str: '0x20',
      bytes: [65, 32],
    },
    {
      id: 16,
      address: 4102,
      size: 3,
      mnemonic: 'call',
      op_str: '0xc9',
      bytes: [16, 201, 1],
    },
    {
      id: 69,
      address: 4105,
      size: 1,
      mnemonic: 'i32.eqz',
      op_str: '',
      bytes: [69],
    },
    {
      id: 11,
      address: 4106,
      size: 1,
      mnemonic: 'end',
      op_str: '',
      bytes: [11],
    },
  ]);

  disassembler.close();
});
