import { expect, test } from 'bun:test';
import CS from '../../capstone';

test('CS.ARCH_SPARC', () => {
  const buffer = new Uint8Array([
    0x80, 0xa0, 0x40, 0x02, 0x85, 0xc2, 0x60, 0x08, 0x85, 0xe8, 0x20, 0x01,
    0x81, 0xe8, 0x00, 0x00, 0x90, 0x10, 0x20, 0x01, 0xd5, 0xf6, 0x10, 0x16,
    0x21, 0x00, 0x00, 0x0a, 0x86, 0x00, 0x40, 0x02, 0x01, 0x00, 0x00, 0x00,
    0x12, 0xbf, 0xff, 0xff, 0x10, 0xbf, 0xff, 0xff, 0xa0, 0x02, 0x00, 0x09,
    0x0d, 0xbf, 0xff, 0xff, 0xd4, 0x20, 0x60, 0x00, 0xd4, 0x4e, 0x00, 0x16,
    0x2a, 0xc2, 0x80, 0x03,
  ]);
  const disassembler = new CS.CAPSTONE(
    CS.ARCH_SPARC,
    CS.MODE_BIG_ENDIAN + CS.MODE_V9,
  );
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
      id: 33,
      address: 4096,
      size: 4,
      mnemonic: 'cmp',
      op_str: '%g1, %g2',
      bytes: new Uint8Array([128, 160, 64, 2]),
    },
    {
      id: 194,
      address: 4100,
      size: 4,
      mnemonic: 'jmpl',
      op_str: '%o1+8, %g2',
      bytes: new Uint8Array([133, 194, 96, 8]),
    },
    {
      id: 226,
      address: 4104,
      size: 4,
      mnemonic: 'restore',
      op_str: '%g0, 1, %g2',
      bytes: new Uint8Array([133, 232, 32, 1]),
    },
    {
      id: 226,
      address: 4108,
      size: 4,
      mnemonic: 'restore',
      op_str: '',
      bytes: new Uint8Array([129, 232, 0, 0]),
    },
    {
      id: 221,
      address: 4112,
      size: 4,
      mnemonic: 'mov',
      op_str: '1, %o0',
      bytes: new Uint8Array([144, 16, 32, 1]),
    },
    {
      id: 28,
      address: 4116,
      size: 4,
      mnemonic: 'casx',
      op_str: '[%i0], %l6, %o2',
      bytes: new Uint8Array([213, 246, 16, 22]),
    },
    {
      id: 232,
      address: 4120,
      size: 4,
      mnemonic: 'sethi',
      op_str: '0xa, %l0',
      bytes: new Uint8Array([33, 0, 0, 10]),
    },
    {
      id: 6,
      address: 4124,
      size: 4,
      mnemonic: 'add',
      op_str: '%g1, %g2, %g3',
      bytes: new Uint8Array([134, 0, 64, 2]),
    },
    {
      id: 217,
      address: 4128,
      size: 4,
      mnemonic: 'nop',
      op_str: '',
      bytes: new Uint8Array([1, 0, 0, 0]),
    },
    {
      id: 16,
      address: 4132,
      size: 4,
      mnemonic: 'bne',
      op_str: '0x1020',
      bytes: new Uint8Array([18, 191, 255, 255]),
    },
    {
      id: 16,
      address: 4136,
      size: 4,
      mnemonic: 'ba',
      op_str: '0x1024',
      bytes: new Uint8Array([16, 191, 255, 255]),
    },
    {
      id: 6,
      address: 4140,
      size: 4,
      mnemonic: 'add',
      op_str: '%o0, %o1, %l0',
      bytes: new Uint8Array([160, 2, 0, 9]),
    },
    {
      id: 19,
      address: 4144,
      size: 4,
      mnemonic: 'fbg',
      op_str: '0x102c',
      bytes: new Uint8Array([13, 191, 255, 255]),
    },
    {
      id: 246,
      address: 4148,
      size: 4,
      mnemonic: 'st',
      op_str: '%o2, [%g1]',
      bytes: new Uint8Array([212, 32, 96, 0]),
    },
    {
      id: 198,
      address: 4152,
      size: 4,
      mnemonic: 'ldsb',
      op_str: '[%i0+%l6], %o2',
      bytes: new Uint8Array([212, 78, 0, 22]),
    },
    {
      id: 24,
      address: 4156,
      size: 4,
      mnemonic: 'brnz,a,pn',
      op_str: '%o2, 0x1048',
      bytes: new Uint8Array([42, 194, 128, 3]),
    },
  ]);

  disassembler.close();
});
