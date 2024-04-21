import { expect, test } from 'bun:test';
import cs from '../../wrapper';

test('cs.ARCH_X86', () => {
  const buffer = new Uint8Array([
    0x8d, 0x4c, 0x32, 0x08, 0x01, 0xd8, 0x81, 0xc6, 0x34, 0x12, 0x00, 0x00,
    0x05, 0x23, 0x01, 0x00, 0x00, 0x36, 0x8b, 0x84, 0x91, 0x23, 0x01, 0x00,
    0x00, 0x41, 0x8d, 0x84, 0x39, 0x89, 0x67, 0x00, 0x00, 0x8d, 0x87, 0x89,
    0x67, 0x00, 0x00, 0xb4, 0xc6, 0x66, 0xe9, 0xb8, 0x00, 0x00, 0x00, 0x67,
    0xff, 0xa0, 0x23, 0x01, 0x00, 0x00, 0x66, 0xe8, 0xcb, 0x00, 0x00, 0x00,
    0x74, 0xfc,
  ]);
  const disassembler = new cs.Capstone(cs.ARCH_X86, cs.MODE_16);
  const insns = disassembler.disasm(buffer, 0x1000);

  let index = 0;
  expect(insns).toEqual([
    {
      id: 332,
      address: 4096,
      size: 3,
      mnemonic: 'lea',
      op_str: 'cx, [si + 0x32]',
      bytes: [141, 76, 50],
    },
    {
      id: 512,
      address: 4099,
      size: 2,
      mnemonic: 'or',
      op_str: 'byte ptr [bx + di], al',
      bytes: [8, 1],
    },
    {
      id: 15,
      address: 4101,
      size: 4,
      mnemonic: 'fadd',
      op_str: 'dword ptr [bx + di + 0x34c6]',
      bytes: [216, 129, 198, 52],
    },
    {
      id: 6,
      address: 4105,
      size: 2,
      mnemonic: 'adc',
      op_str: 'al, byte ptr [bx + si]',
      bytes: [18, 0],
    },
    {
      id: 8,
      address: 4107,
      size: 2,
      mnemonic: 'add',
      op_str: 'byte ptr [di], al',
      bytes: [0, 5],
    },
    {
      id: 24,
      address: 4109,
      size: 2,
      mnemonic: 'and',
      op_str: 'ax, word ptr [bx + di]',
      bytes: [35, 1],
    },
    {
      id: 8,
      address: 4111,
      size: 2,
      mnemonic: 'add',
      op_str: 'byte ptr [bx + si], al',
      bytes: [0, 0],
    },
    {
      id: 460,
      address: 4113,
      size: 5,
      mnemonic: 'mov',
      op_str: 'ax, word ptr ss:[si + 0x2391]',
      bytes: [54, 139, 132, 145, 35],
    },
    {
      id: 8,
      address: 4118,
      size: 2,
      mnemonic: 'add',
      op_str: 'word ptr [bx + si], ax',
      bytes: [1, 0],
    },
    {
      id: 8,
      address: 4120,
      size: 3,
      mnemonic: 'add',
      op_str: 'byte ptr [bx + di - 0x73], al',
      bytes: [0, 65, 141],
    },
    {
      id: 734,
      address: 4123,
      size: 2,
      mnemonic: 'test',
      op_str: 'byte ptr [bx + di], bh',
      bytes: [132, 57],
    },
    {
      id: 460,
      address: 4125,
      size: 3,
      mnemonic: 'mov',
      op_str: 'word ptr [bx], sp',
      bytes: [137, 103, 0],
    },
    {
      id: 8,
      address: 4128,
      size: 4,
      mnemonic: 'add',
      op_str: 'byte ptr [di - 0x7679], cl',
      bytes: [0, 141, 135, 137],
    },
    {
      id: 8,
      address: 4132,
      size: 3,
      mnemonic: 'add',
      op_str: 'byte ptr [eax], al',
      bytes: [103, 0, 0],
    },
    {
      id: 460,
      address: 4135,
      size: 2,
      mnemonic: 'mov',
      op_str: 'ah, 0xc6',
      bytes: [180, 198],
    },
    {
      id: 172,
      address: 4137,
      size: 6,
      mnemonic: 'jmp',
      op_str: '0x10e7',
      bytes: [102, 233, 184, 0, 0, 0],
    },
    {
      id: 172,
      address: 4143,
      size: 7,
      mnemonic: 'jmp',
      op_str: 'word ptr [eax + 0x123]',
      bytes: [103, 255, 160, 35, 1, 0, 0],
    },
    {
      id: 62,
      address: 4150,
      size: 6,
      mnemonic: 'call',
      op_str: '0x1107',
      bytes: [102, 232, 203, 0, 0, 0],
    },
    {
      id: 260,
      address: 4156,
      size: 2,
      mnemonic: 'je',
      op_str: '0x103a',
      bytes: [116, 252],
    },
  ]);

  disassembler.close();
});
