import { expect, test } from 'bun:test';
import cs from '../../wrapper';

const CODE: Array<number> = [
  0x86, 0x48, 0x60, 0xf4, 0x4d, 0x0f, 0xe2, 0xf4, 0xed, 0xff, 0xff, 0xeb, 0x04,
  0xe0, 0x2d, 0xe5, 0x00, 0x00, 0x00, 0x00, 0xe0, 0x83, 0x22, 0xe5, 0xf1, 0x02,
  0x03, 0x0e, 0x00, 0x00, 0xa0, 0xe3, 0x02, 0x30, 0xc1, 0xe7, 0x00, 0x00, 0x53,
  0xe3, 0x00, 0x02, 0x01, 0xf1, 0x05, 0x40, 0xd0, 0xe8, 0xf4, 0x80, 0x00, 0x00,
];