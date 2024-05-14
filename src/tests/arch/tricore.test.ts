import { expect, test } from 'bun:test';
import CS from '../../capstone';

test('CS.ARCH_TRICORE', () => {
  const buffer = new Uint8Array([
    0x09, 0xcf, 0xbc, 0xf5, 0x09, 0xf4, 0x01, 0x00, 0x89, 0xfb, 0x8f, 0x74,
    0x89, 0xfe, 0x48, 0x01, 0x29, 0x00, 0x19, 0x25, 0x29, 0x03, 0x09, 0xf4,
    0x85, 0xf9, 0x68, 0x0f, 0x16, 0x01,
  ]);

  const disassembler = new CS.CAPSTONE(CS.ARCH_TRICORE, CS.MODE_TRICORE_162);
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
      id: 165,
      address: 4096,
      size: 4,
      mnemonic: 'ld.a',
      op_str: 'a15, [+a12]#-4',
      bytes: new Uint8Array([9, 207, 188, 245]),
    },
    {
      id: 167,
      address: 4100,
      size: 4,
      mnemonic: 'ld.b',
      op_str: 'd4, [a15+]#1',
      bytes: new Uint8Array([9, 244, 1, 0]),
    },
    {
      id: 347,
      address: 4104,
      size: 4,
      mnemonic: 'st.h',
      op_str: '[+a15]#0x1cf, d11',
      bytes: new Uint8Array([137, 251, 143, 116]),
    },
    {
      id: 346,
      address: 4108,
      size: 4,
      mnemonic: 'st.d',
      op_str: '[a15+]#8, e14',
      bytes: new Uint8Array([137, 254, 72, 1]),
    },
    {
      id: 173,
      address: 4112,
      size: 4,
      mnemonic: 'ld.w',
      op_str: 'd0, [p0+c]#0x99',
      bytes: new Uint8Array([41, 0, 25, 37]),
    },
    {
      id: 167,
      address: 4116,
      size: 4,
      mnemonic: 'ld.b',
      op_str: 'd3, [p0+c]#-0x37',
      bytes: new Uint8Array([41, 3, 9, 244]),
    },
    {
      id: 168,
      address: 4120,
      size: 4,
      mnemonic: 'ld.da',
      op_str: 'p8, #0xf0003428',
      bytes: new Uint8Array([133, 249, 104, 15]),
    },
    {
      id: 45,
      address: 4124,
      size: 2,
      mnemonic: 'and',
      op_str: 'd15, #1',
      bytes: new Uint8Array([22, 1]),
    },
  ]);

  disassembler.close();
});
