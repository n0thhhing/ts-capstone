import CS from '../capstone';
import { expect, test } from 'bun:test';

test('disasm_iter ARM', () => {
  const arm = new CS.CAPSTONE(CS.ARCH_ARM, CS.MODE_THUMB);
  // prettier-ignore
  const armBuffer = [
    0x4f, 0xf0, 0x00, 0x01, // 0x1000 mov.w r1, #0
    0xbd, 0xe8, 0x00, 0x88, // 0x1004 pop.w {fp, pc}
    0xd1, 0xe8, 0x00, 0xf0, // 0x1008 tbb [r1, r0]
    0x18, 0xbf,             // 0x100c it ne
    0xad, 0xbf,             // 0x100e iteet ge
    0xf3, 0xff, 0x0b, 0x0c, // 0x1010 vdupne.8 d16, d11[1]
    0x86, 0xf3, 0x00, 0x89, // 0x1014 msr cpsr_fc, r6
    0x80, 0xf3, 0x00, 0x8c, // 0x1018 msr apsr_nzcvqg, r0
    0x4f, 0xfa, 0x99, 0xf6, // 0x101c sxtb.w r6, sb, ror #8
    0xd0, 0xff, 0xa2, 0x01, // 0x1020 vaddw.u16 q8, q8, d18
  ];

  const arm_ret = {
    buffer: armBuffer,
    addr: 0x1000,
    insn: {},
  };

  const expectedInstructions = [
    {
      address: 0x1000,
      mnemonic: 'mov.w',
      op_str: 'r1, #0',
      bytes: new Uint8Array([0x4f, 0xf0, 0x00, 0x01]),
    },
    {
      address: 0x1004,
      mnemonic: 'pop.w',
      op_str: '{fp, pc}',
      bytes: new Uint8Array([0xbd, 0xe8, 0x00, 0x88]),
    },
    {
      address: 0x1008,
      mnemonic: 'tbb',
      op_str: '[r1, r0]',
      bytes: new Uint8Array([0xd1, 0xe8, 0x00, 0xf0]),
    },
    {
      address: 0x100c,
      mnemonic: 'it',
      op_str: 'ne',
      bytes: new Uint8Array([0x18, 0xbf]),
    },
    {
      address: 0x100e,
      mnemonic: 'iteet',
      op_str: 'ge',
      bytes: new Uint8Array([0xad, 0xbf]),
    },
    {
      address: 0x1010,
      mnemonic: 'vdupne.8',
      op_str: 'd16, d11[1]',
      bytes: new Uint8Array([0xf3, 0xff, 0x0b, 0x0c]),
    },
    {
      address: 0x1014,
      mnemonic: 'msr',
      op_str: 'cpsr_fc, r6',
      bytes: new Uint8Array([0x86, 0xf3, 0x00, 0x89]),
    },
    {
      address: 0x1018,
      mnemonic: 'msr',
      op_str: 'apsr_nzcvqg, r0',
      bytes: new Uint8Array([0x80, 0xf3, 0x00, 0x8c]),
    },
    {
      address: 0x101c,
      mnemonic: 'sxtb.w',
      op_str: 'r6, sb, ror #8',
      bytes: new Uint8Array([0x4f, 0xfa, 0x99, 0xf6]),
    },
    {
      address: 0x1020,
      mnemonic: 'vaddw.u16',
      op_str: 'q8, q8, d18',
      bytes: new Uint8Array([0xd0, 0xff, 0xa2, 0x01]),
    },
  ];

  let index = 0;
  while (arm.disasm_iter(arm_ret)) {
    const expected = expectedInstructions[index++];
    expect(arm_ret.insn.address).toBe(expected.address);
    expect(arm_ret.insn.mnemonic).toBe(expected.mnemonic);
    expect(arm_ret.insn.op_str).toBe(expected.op_str);
    expect(arm_ret.insn.bytes).toEqual(expected.bytes);
  }

  arm.close();
});

test('disasm_iter ARM64', () => {
  const arm64 = new CS.CAPSTONE(1, 0);
  // prettier-ignore
  const arm64Buffer = [  
    0xf5, 0x53, 0xbe, 0xa9, // 0x4db43dc stp x21, x20, [sp, #-0x20]!
    0xf3, 0x7b, 0x01, 0xa9, // 0x4db43e0 stp x19, x30, [sp, #0x10]
    0x35, 0xac, 0x01, 0xb0, // 0x4db43e4 adrp x21, #0x8339000
    0xa8, 0x1a, 0x58, 0x39, // 0x4db43e8 ldrb w8, [x21, #0x606]
    0xf3, 0x03, 0x01, 0x2a, // 0x4db43ec mov w19, w1
    0xf4, 0x03, 0x00, 0xaa, // 0x4db43f0 mov x20, x0
    0x28, 0x01, 0x00, 0x37, // 0x4db43f4 tbnz w8, #0, #0x4db4418
    0x40, 0x80, 0x01, 0xb0, // 0x4db43f8 adrp x0, #0x7dbd000
    0x00, 0x20, 0x41, 0xf9, // 0x4db43fc ldr x0, [x0, #0x240]
    0x9f, 0x48, 0x27, 0x97, // 0x4db4400 bl #0x178667c
    0x40, 0x80, 0x01, 0xd0, // 0x4db4404 adrp x0, #0x7dbe000
    0x00, 0x58, 0x45, 0xf9, // 0x4db4408 ldr x0, [x0, #0xab0]
    0x9c, 0x48, 0x27, 0x97, // 0x4db440c bl #0x178667c
    0x28, 0x00, 0x80, 0x52, // 0x4db4410 movz w8, #0x1
    0xa8, 0x1a, 0x18, 0x39, // 0x4db4414 strb w8, [x21, #0x606]
    0xe0, 0x03, 0x14, 0xaa, // 0x4db4418 mov x0, x20
  ];

  const arm64_ret = {
    buffer: arm64Buffer,
    addr: 0x4db43dc,
    insn: {},
  };

  const expectedInstructions = [
    {
      address: 0x4db43dc,
      mnemonic: 'stp',
      op_str: 'x21, x20, [sp, #-0x20]!',
      bytes: new Uint8Array([0xf5, 0x53, 0xbe, 0xa9]),
    },
    {
      address: 0x4db43e0,
      mnemonic: 'stp',
      op_str: 'x19, x30, [sp, #0x10]',
      bytes: new Uint8Array([0xf3, 0x7b, 0x01, 0xa9]),
    },
    {
      address: 0x4db43e4,
      mnemonic: 'adrp',
      op_str: 'x21, #0x8339000',
      bytes: new Uint8Array([0x35, 0xac, 0x01, 0xb0]),
    },
    {
      address: 0x4db43e8,
      mnemonic: 'ldrb',
      op_str: 'w8, [x21, #0x606]',
      bytes: new Uint8Array([0xa8, 0x1a, 0x58, 0x39]),
    },
    {
      address: 0x4db43ec,
      mnemonic: 'mov',
      op_str: 'w19, w1',
      bytes: new Uint8Array([0xf3, 0x03, 0x01, 0x2a]),
    },
    {
      address: 0x4db43f0,
      mnemonic: 'mov',
      op_str: 'x20, x0',
      bytes: new Uint8Array([0xf4, 0x03, 0x00, 0xaa]),
    },
    {
      address: 0x4db43f4,
      mnemonic: 'tbnz',
      op_str: 'w8, #0, #0x4db4418',
      bytes: new Uint8Array([0x28, 0x01, 0x00, 0x37]),
    },
    {
      address: 0x4db43f8,
      mnemonic: 'adrp',
      op_str: 'x0, #0x7dbd000',
      bytes: new Uint8Array([0x40, 0x80, 0x01, 0xb0]),
    },
    {
      address: 0x4db43fc,
      mnemonic: 'ldr',
      op_str: 'x0, [x0, #0x240]',
      bytes: new Uint8Array([0x00, 0x20, 0x41, 0xf9]),
    },
    {
      address: 0x4db4400,
      mnemonic: 'bl',
      op_str: '#0x178667c',
      bytes: new Uint8Array([0x9f, 0x48, 0x27, 0x97]),
    },
    {
      address: 0x4db4404,
      mnemonic: 'adrp',
      op_str: 'x0, #0x7dbe000',
      bytes: new Uint8Array([0x40, 0x80, 0x01, 0xd0]),
    },
    {
      address: 0x4db4408,
      mnemonic: 'ldr',
      op_str: 'x0, [x0, #0xab0]',
      bytes: new Uint8Array([0x00, 0x58, 0x45, 0xf9]),
    },
    {
      address: 0x4db440c,
      mnemonic: 'bl',
      op_str: '#0x178667c',
      bytes: new Uint8Array([0x9c, 0x48, 0x27, 0x97]),
    },
    {
      address: 0x4db4410,
      mnemonic: 'mov',
      op_str: 'w8, #1',
      bytes: new Uint8Array([0x28, 0x00, 0x80, 0x52]),
    },
    {
      address: 0x4db4414,
      mnemonic: 'strb',
      op_str: 'w8, [x21, #0x606]',
      bytes: new Uint8Array([0xa8, 0x1a, 0x18, 0x39]),
    },
    {
      address: 0x4db4418,
      mnemonic: 'mov',
      op_str: 'x0, x20',
      bytes: new Uint8Array([0xe0, 0x03, 0x14, 0xaa]),
    },
  ];

  let index = 0;
  while (arm64.disasm_iter(arm64_ret)) {
    const expected = expectedInstructions[index++];
    expect(arm64_ret.insn.address).toBe(expected.address);
    expect(arm64_ret.insn.mnemonic).toBe(expected.mnemonic);
    expect(arm64_ret.insn.op_str).toBe(expected.op_str);
    expect(arm64_ret.insn.bytes).toEqual(expected.bytes);
  }

  arm64.close();
});
