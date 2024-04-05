import { Memory } from '../memory';
import { Wrapper } from '../wrapper';

const s = Memory;

const dummyStruct = Wrapper._malloc(666);
const value1Ptr = dummyStruct;
const value2Ptr = dummyStruct + 4;
const value3Ptr = dummyStruct + 8;
const value4Ptr = dummyStruct + 16;
const value5Ptr = dummyStruct + 24;
const value6Ptr = Wrapper._malloc(8);

Wrapper.setValue(value1Ptr, 2, 'i32');
Wrapper.setValue(value2Ptr, 5, 'i32');
s.setValue(value3Ptr, 1000, 'i64');
s.setValue(value4Ptr, 2000, 'i64');
for (let i = 0; i < 6; i++) s.setValue(value5Ptr + i, i, 'i8');
s.setValue(value6Ptr, 323, 'i64');

const structTypes = {
  value1: 'int',
  value2: 'int',
  value3: 'i64',
  value4: 'i64',
  value5: 'ubyte[6]',
  value6: {
    value: (pointer: number, struct: any) => {
      const value = s.getValue(value6Ptr, 'i64');
      return {
        offset: 0,
        entry: value,
      };
    },
  },
};

const dereferencedObject = Memory.dereferencePointer(dummyStruct, structTypes);
console.log(dereferencedObject);
