import cs from '../wrapper';
import { expect, test } from 'bun:test';

test('OPT_BUFFER', () => {
  const buffer = new Uint8Array([
    0x88,
    0x02,
    0x40,
    0xb9, // 0x1008: ldr w8, [x20]
  ]);

  const disassembler = new cs.Capstone(cs.ARCH_ARM64, cs.MODE_ARM);
  disassembler.option(cs.OPT_BUFFER, true);

  const insn = disassembler.disasm(buffer, 0x1000)[0];
  const decoder = new TextDecoder('utf-8');
  const buf = new Int8Array(insn.buffer);
  const dv = new DataView(buf.buffer);

  const id = dv.getUint32(0, true);
  const addr = parseInt(dv.getBigUint64(8, true));
  const size = dv.getUint16(16, true);

  let mn_bytes = buf.slice(42, 42 + 32);
  let mn_null_index = mn_bytes.indexOf(0);
  let truncated_mn =
    mn_null_index !== -1 ? mn_bytes.subarray(0, mn_null_index) : mn_bytes;

  let op_bytes = buf.slice(66 + 8, 66 + 8 + 160);
  let op_null_index = op_bytes.indexOf(0);
  let truncated_op =
    op_null_index !== -1 ? op_bytes.subarray(0, op_null_index) : op_bytes;

  const mnemonic = decoder.decode(truncated_mn);
  const op_str = decoder.decode(truncated_op);
  const bytes = [];
  for (let i = 0; i < size; i++) bytes.push(dv.getUint8(18 + i));

  expect(id).toBe(insn.id);
  expect(addr).toBe(insn.address);
  expect(size).toBe(insn.size);
  expect(mnemonic).toBe(insn.mnemonic);
  expect(op_str).toBe(insn.op_str);
  expect(bytes).toEqual(insn.bytes);

  disassembler.close();
});
