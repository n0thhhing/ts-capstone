import { Wrapper } from './capstone';

type native_t =
  | 'i8'
  | 'int8_t'
  | 'i16'
  | 'int16_t'
  | 'i32'
  | 'int32_t'
  | 'i64'
  | 'int64_t'
  | 'byte'
  | 'short'
  | 'long'
  | 'int'
  | 'double'
  | 'u8'
  | 'uint8_t'
  | 'u16'
  | 'uint16_t'
  | 'u32'
  | 'uint32_t'
  | 'u64'
  | 'uint64_t'
  | 'ubyte'
  | 'ushort'
  | 'ulong'
  | 'uint'
  | 'float'
  | 'f32'
  | 'f64'
  | '*'
  | 'ptr'
  | 'void*'
  | 'i8*'
  | 'bool'
  | 'char'
  | 'char*'
  | 'boolean';
type arr_t<T extends native_t> = `${T}[${number}]`;
type ptr = number;

export namespace Memory {
  export const allocations: Set<ptr> = new Set<ptr>();
  export const nullptr: ptr = 0;

  export function malloc(size: number): ptr {
    const pointer: ptr = Wrapper._malloc(size);
    allocations.add(pointer);
    return pointer;
  }

  export function free(mem: ptr | Set<ptr> | Array<ptr>): void {
    if (mem instanceof Set || Array.isArray(mem)) {
      for (const pointer of mem) {
        allocations.delete(pointer);
        Wrapper._free(pointer);
      }
    } else {
      allocations.delete(mem);
      Wrapper._free(mem);
    }
  }

  export function clean(): void {
    free(allocations);
  }

  export function write(
    pointer: ptr,
    value: any,
    type: native_t | arr_t<native_t>,
  ): void {
    switch (type) {
      case 'char*':
        const utf8_bytes = [];
        if (!/\0/.test(value)) value += '\0';
        for (let i = 0; i < value.length; ++i) {
          const charCode = value.charCodeAt(i);
          if (charCode < 128) {
            utf8_bytes.push(charCode);
          } else if (charCode < 2048) {
            utf8_bytes.push((charCode >> 6) | 192);
            utf8_bytes.push((charCode & 63) | 128);
          } else {
            utf8_bytes.push((charCode >> 12) | 224);
            utf8_bytes.push(((charCode >> 6) & 63) | 128);
            utf8_bytes.push((charCode & 63) | 128);
          }
        }

        for (let i = 0; i < utf8_bytes.length; ++i) {
          Wrapper.setValue(pointer + i, utf8_bytes[i], 'i8');
        }
        break;
      case 'bool':
      case 'boolean':
        Wrapper.setValue(pointer, +value, 'i8');
        break;
      case 'u8':
      case 'uint8_t':
      case 'int8_t':
      case 'ubyte':
      case 'i8':
      case 'byte':
        Wrapper.setValue(pointer, value, 'i8');
        break;
      case 'u16':
      case 'uint16_t':
      case 'int16_t':
      case 'ushort':
      case 'i16':
      case 'short':
        Wrapper.setValue(pointer, value, 'i16');
        break;
      case 'u32':
      case 'uint32_t':
      case 'int32_t':
      case 'uint':
      case 'i32':
      case 'int':
        Wrapper.setValue(pointer, value, 'i32');
        break;
      case 'i64':
      case 'u64':
      case 'uint64_t':
      case 'int64_t':
      case 'long':
      case 'ulong':
        /*Wrapper.HEAP32[pointer >> 2] = value; // Low 32 bits
        Wrapper.HEAP32[(pointer + 4) >> 2] = Math.floor(value / 4294967296); // High 32 bits
        */
        let tmp_double, tmp_i64;
        (tmp_i64 = [
          value >>> 0,
          ((tmp_double = value),
          +Math.abs(tmp_double) >= +1
            ? tmp_double > +0
              ? (Math.min(+Math.floor(tmp_double / +4294967296), +4294967295) |
                  0) >>>
                0
              : ~~+Math.ceil(
                  (tmp_double - +(~~tmp_double >>> 0)) / +4294967296,
                ) >>> 0
            : 0),
        ]),
          (Wrapper.HEAP32[pointer >> 2] = tmp_i64[0]),
          (Wrapper.HEAP32[(pointer + 4) >> 2] = tmp_i64[1]);
        break;
      case 'float':
        Wrapper.HEAPF32[pointer >> 2] = value;
        break;
      case 'i8*':
      case '*':
      case 'float':
      case 'double':
        Wrapper.setValue(pointer, value, type);
        break;
      default:
        throw new Error(`Unknown type: ${type}`);
    }
  }

  export function read(pointer: ptr, type: native_t): any {
    let value;
    switch (type) {
      case 'char':
      case 'char*':
        value = Wrapper.UTF8ToString(pointer);
        break;
      case 'bool':
      case 'boolean':
        value = Boolean(Wrapper.getValue(pointer, 'i8'));
        break;
      case 'u8':
      case 'ubyte':
      case 'i8':
      case 'byte':
        value = Wrapper.getValue(pointer, 'i8');
        if (type.startsWith('u')) value = value & 0xff;
        break;
      case 'u16':
      case 'ushort':
      case 'i16':
      case 'short':
        value = Wrapper.getValue(pointer, 'i16');
        break;
      case 'u32':
      case 'uint':
      case 'i32':
      case 'int':
        value = Wrapper.getValue(pointer, 'i32');
        break;
      case 'i64':
      case 'u64':
      case 'long':
      case 'ulong':
        /*const low = Wrapper.HEAP32[pointer >> 2]; // Low 32 bits
        const high = Wrapper.HEAP32[(pointer + 4) >> 2]; // High 32 bits
        value = low + high * 4294967296; // Combine high and low bits*/
        value = Wrapper.HEAP32[pointer >> 2];
        break;
      case 'i8*':
      case '*':
      case 'float':
      case 'double':
        value = Wrapper.getValue(pointer, type);
        break;
      default:
        throw new Error(`Unknown type: ${type}`);
    }

    return value;
  }
}
