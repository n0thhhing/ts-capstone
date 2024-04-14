import cs from '../wrapper';
import { test, expect } from 'bun:test';

const d = new cs.Capstone(1, 0);
test('name ids', () => {
  expect(d.group_name(2)).toBe('call');
  expect(d.reg_name(183)).toBe('s28');
  expect(d.insn_name(191)).toBe('cpyfm');
});
