import { expect, test } from 'bun:test';
import CS from '../../capstone';

test('CS.ARCH_RISCV', () => {
  const buffer = new Uint8Array([
    0x37, 0x34, 0x00, 0x00, 0x97, 0x82, 0x00, 0x00, 0xef, 0x00, 0x80, 0x00,
    0xef, 0xf0, 0x1f, 0xff, 0xe7, 0x00, 0x45, 0x00, 0xe7, 0x00, 0xc0, 0xff,
    0x63, 0x05, 0x41, 0x00, 0xe3, 0x9d, 0x61, 0xfe, 0x63, 0xca, 0x93, 0x00,
    0x63, 0x53, 0xb5, 0x00, 0x63, 0x65, 0xd6, 0x00, 0x63, 0x76, 0xf7, 0x00,
    0x03, 0x88, 0x18, 0x00, 0x03, 0x99, 0x49, 0x00, 0x03, 0xaa, 0x6a, 0x00,
    0x03, 0xcb, 0x2b, 0x01, 0x03, 0xdc, 0x8c, 0x01, 0x23, 0x86, 0xad, 0x03,
    0x23, 0x9a, 0xce, 0x03, 0x23, 0x8f, 0xef, 0x01, 0x93, 0x00, 0xe0, 0x00,
    0x13, 0xa1, 0x01, 0x01, 0x13, 0xb2, 0x02, 0x7d, 0x13, 0xc3, 0x03, 0xdd,
    0x13, 0xe4, 0xc4, 0x12, 0x13, 0xf5, 0x85, 0x0c, 0x13, 0x96, 0xe6, 0x01,
    0x13, 0xd7, 0x97, 0x01, 0x13, 0xd8, 0xf8, 0x40, 0x33, 0x89, 0x49, 0x01,
    0xb3, 0x0a, 0x7b, 0x41, 0x33, 0xac, 0xac, 0x01, 0xb3, 0x3d, 0xde, 0x01,
    0x33, 0xd2, 0x62, 0x40, 0xb3, 0x43, 0x94, 0x00, 0x33, 0xe5, 0xc5, 0x00,
    0xb3, 0x76, 0xf7, 0x00, 0xb3, 0x54, 0x39, 0x01, 0xb3, 0x50, 0x31, 0x00,
    0x33, 0x9f, 0x0f, 0x00,
  ]);

  const disassembler = new CS.CAPSTONE(CS.ARCH_RISCV, CS.MODE_RISCV32);
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
      id: 221,
      address: 4096,
      size: 4,
      mnemonic: 'lui',
      op_str: 's0, 3',
      bytes: new Uint8Array([55, 52, 0, 0]),
    },
    {
      id: 79,
      address: 4100,
      size: 4,
      mnemonic: 'auipc',
      op_str: 't0, 8',
      bytes: new Uint8Array([151, 130, 0, 0]),
    },
    {
      id: 206,
      address: 4104,
      size: 4,
      mnemonic: 'jal',
      op_str: '8',
      bytes: new Uint8Array([239, 0, 128, 0]),
    },
    {
      id: 206,
      address: 4108,
      size: 4,
      mnemonic: 'jal',
      op_str: '-0x10',
      bytes: new Uint8Array([239, 240, 31, 255]),
    },
    {
      id: 207,
      address: 4112,
      size: 4,
      mnemonic: 'jalr',
      op_str: 'ra, a0, 4',
      bytes: new Uint8Array([231, 0, 69, 0]),
    },
    {
      id: 207,
      address: 4116,
      size: 4,
      mnemonic: 'jalr',
      op_str: 'ra, zero, -4',
      bytes: new Uint8Array([231, 0, 192, 255]),
    },
    {
      id: 80,
      address: 4120,
      size: 4,
      mnemonic: 'beq',
      op_str: 'sp, tp, 0xa',
      bytes: new Uint8Array([99, 5, 65, 0]),
    },
    {
      id: 85,
      address: 4124,
      size: 4,
      mnemonic: 'bne',
      op_str: 'gp, t1, -6',
      bytes: new Uint8Array([227, 157, 97, 254]),
    },
    {
      id: 83,
      address: 4128,
      size: 4,
      mnemonic: 'blt',
      op_str: 't2, s1, 0x14',
      bytes: new Uint8Array([99, 202, 147, 0]),
    },
    {
      id: 81,
      address: 4132,
      size: 4,
      mnemonic: 'bge',
      op_str: 'a0, a1, 6',
      bytes: new Uint8Array([99, 83, 181, 0]),
    },
    {
      id: 84,
      address: 4136,
      size: 4,
      mnemonic: 'bltu',
      op_str: 'a2, a3, 0xa',
      bytes: new Uint8Array([99, 101, 214, 0]),
    },
    {
      id: 82,
      address: 4140,
      size: 4,
      mnemonic: 'bgeu',
      op_str: 'a4, a5, 0xc',
      bytes: new Uint8Array([99, 118, 247, 0]),
    },
    {
      id: 208,
      address: 4144,
      size: 4,
      mnemonic: 'lb',
      op_str: 'a6, 1(a7)',
      bytes: new Uint8Array([3, 136, 24, 0]),
    },
    {
      id: 211,
      address: 4148,
      size: 4,
      mnemonic: 'lh',
      op_str: 's2, 4(s3)',
      bytes: new Uint8Array([3, 153, 73, 0]),
    },
    {
      id: 222,
      address: 4152,
      size: 4,
      mnemonic: 'lw',
      op_str: 's4, 6(s5)',
      bytes: new Uint8Array([3, 170, 106, 0]),
    },
    {
      id: 209,
      address: 4156,
      size: 4,
      mnemonic: 'lbu',
      op_str: 's6, 0x12(s7)',
      bytes: new Uint8Array([3, 203, 43, 1]),
    },
    {
      id: 212,
      address: 4160,
      size: 4,
      mnemonic: 'lhu',
      op_str: 's8, 0x18(s9)',
      bytes: new Uint8Array([3, 220, 140, 1]),
    },
    {
      id: 236,
      address: 4164,
      size: 4,
      mnemonic: 'sb',
      op_str: 's10, 0x2c(s11)',
      bytes: new Uint8Array([35, 134, 173, 3]),
    },
    {
      id: 247,
      address: 4168,
      size: 4,
      mnemonic: 'sh',
      op_str: 't3, 0x34(t4)',
      bytes: new Uint8Array([35, 154, 206, 3]),
    },
    {
      id: 236,
      address: 4172,
      size: 4,
      mnemonic: 'sb',
      op_str: 't5, 0x1e(t6)',
      bytes: new Uint8Array([35, 143, 239, 1]),
    },
    {
      id: 2,
      address: 4176,
      size: 4,
      mnemonic: 'addi',
      op_str: 'ra, zero, 0xe',
      bytes: new Uint8Array([147, 0, 224, 0]),
    },
    {
      id: 253,
      address: 4180,
      size: 4,
      mnemonic: 'slti',
      op_str: 'sp, gp, 0x10',
      bytes: new Uint8Array([19, 161, 1, 1]),
    },
    {
      id: 254,
      address: 4184,
      size: 4,
      mnemonic: 'sltiu',
      op_str: 'tp, t0, 0x7d0',
      bytes: new Uint8Array([19, 178, 2, 125]),
    },
    {
      id: 272,
      address: 4188,
      size: 4,
      mnemonic: 'xori',
      op_str: 't1, t2, -0x230',
      bytes: new Uint8Array([19, 195, 3, 221]),
    },
    {
      id: 231,
      address: 4192,
      size: 4,
      mnemonic: 'ori',
      op_str: 's0, s1, 0x12c',
      bytes: new Uint8Array([19, 228, 196, 18]),
    },
    {
      id: 78,
      address: 4196,
      size: 4,
      mnemonic: 'andi',
      op_str: 'a0, a1, 0xc8',
      bytes: new Uint8Array([19, 245, 133, 12]),
    },
    {
      id: 249,
      address: 4200,
      size: 4,
      mnemonic: 'slli',
      op_str: 'a2, a3, 0x1e',
      bytes: new Uint8Array([19, 150, 230, 1]),
    },
    {
      id: 262,
      address: 4204,
      size: 4,
      mnemonic: 'srli',
      op_str: 'a4, a5, 0x19',
      bytes: new Uint8Array([19, 215, 151, 1]),
    },
    {
      id: 257,
      address: 4208,
      size: 4,
      mnemonic: 'srai',
      op_str: 'a6, a7, 0xf',
      bytes: new Uint8Array([19, 216, 248, 64]),
    },
    {
      id: 1,
      address: 4212,
      size: 4,
      mnemonic: 'add',
      op_str: 's2, s3, s4',
      bytes: new Uint8Array([51, 137, 73, 1]),
    },
    {
      id: 265,
      address: 4216,
      size: 4,
      mnemonic: 'sub',
      op_str: 's5, s6, s7',
      bytes: new Uint8Array([179, 10, 123, 65]),
    },
    {
      id: 252,
      address: 4220,
      size: 4,
      mnemonic: 'slt',
      op_str: 's8, s9, s10',
      bytes: new Uint8Array([51, 172, 172, 1]),
    },
    {
      id: 255,
      address: 4224,
      size: 4,
      mnemonic: 'sltu',
      op_str: 's11, t3, t4',
      bytes: new Uint8Array([179, 61, 222, 1]),
    },
    {
      id: 256,
      address: 4228,
      size: 4,
      mnemonic: 'sra',
      op_str: 'tp, t0, t1',
      bytes: new Uint8Array([51, 210, 98, 64]),
    },
    {
      id: 271,
      address: 4232,
      size: 4,
      mnemonic: 'xor',
      op_str: 't2, s0, s1',
      bytes: new Uint8Array([179, 67, 148, 0]),
    },
    {
      id: 230,
      address: 4236,
      size: 4,
      mnemonic: 'or',
      op_str: 'a0, a1, a2',
      bytes: new Uint8Array([51, 229, 197, 0]),
    },
    {
      id: 77,
      address: 4240,
      size: 4,
      mnemonic: 'and',
      op_str: 'a3, a4, a5',
      bytes: new Uint8Array([179, 118, 247, 0]),
    },
    {
      id: 261,
      address: 4244,
      size: 4,
      mnemonic: 'srl',
      op_str: 's1, s2, s3',
      bytes: new Uint8Array([179, 84, 57, 1]),
    },
    {
      id: 261,
      address: 4248,
      size: 4,
      mnemonic: 'srl',
      op_str: 'ra, sp, gp',
      bytes: new Uint8Array([179, 80, 49, 0]),
    },
    {
      id: 248,
      address: 4252,
      size: 4,
      mnemonic: 'sll',
      op_str: 't5, t6, zero',
      bytes: new Uint8Array([51, 159, 15, 0]),
    },
  ]);

  disassembler.close();
});
