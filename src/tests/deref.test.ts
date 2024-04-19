import { Memory } from '../memory';
import { Wrapper } from '../wrapper';

const s = Memory;

const dummy_struct = Wrapper._malloc(666);
const value1_ptr = dummy_struct;
const value2_ptr = dummy_struct + 4;
const value3_ptr = dummy_struct + 8;
const value4_ptr = dummy_struct + 16;
const value5_ptr = dummy_struct + 24;
const value6_ptr = Wrapper._malloc(8);

Wrapper.setValue(value1_ptr, 2, 'i32');
Wrapper.setValue(value2_ptr, 5, 'i32');
Memory.write(value3_ptr, 1000, 'i64');
Memory.write(value4_ptr, 2000, 'i64');
for (let i = 0; i < 6; i++) Memory.write(value5_ptr + i, i, 'i8');
Memory.write(value6_ptr, 323, 'i64');

const struct_types = {
  value1: 'int',
  value2: 'int',
  value3: 'i64',
  value4: 'i64',
  value5: 'ubyte[6]',
  value6: {
    value: (pointer: number, struct: any) => {
      const value = Memory.read(value6_ptr, 'i64');
      return {
        offset: 0,
        entry: value,
      };
    },
  },
};

const dereferenced_struct = Memory.deref(dummy_struct, struct_types);
console.log(dereferenced_struct);
