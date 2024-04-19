import { Wrapper } from './wrapper';

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
type depend_t = `${arr_t<native_t>}->${string}`;
type ptr = number;
type wasm_t = 'void' | 'int' | 'long' | 'float' | 'double';

interface js_callback {
  pointer: ptr;
  free: () => void;
}

interface struct_t {
  [key: string]:
    | `padding[${number}]`
    | native_t
    | arr_t<native_t>
    | depend_t
    | struct_t
    | ((pointer: number, struct: any) => { offset: number; entry: any });
}

const fn_cache: Map<Function, { offset: number; entry: any }> = new Map();

export namespace Memory {
  export const allocations: Set<ptr> = new Set<ptr>();

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
  ) {
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

  export function deref(pointer: ptr, types: struct_t): any {
    const deref_struct: any = {};
    const dep_stack: any = {};
    for (const key in types) {
      if (types.hasOwnProperty(key)) {
        const type = types[key];
        if (typeof type === 'function') {
          let fn_type_info = fn_cache.get(type);
          if (!fn_type_info) {
            fn_type_info = type(pointer, deref_struct);
            fn_cache.set(type, fn_type_info);
          }
          const { offset, entry } = fn_type_info;
          pointer += offset;
          deref_struct[key] = entry;
        } else if (typeof type === 'object') {
          deref_struct[key] = deref(pointer, type);
          pointer += get_struct_size(type);
          delete types[
            Object.keys(types).find((key) => key === 'padding') ?? 0
          ];
        } else if (type.includes('padding')) {
          pointer += parseInt(/\[(\d*)\]/.exec(type)?.[1] ?? '0');
        } else if (type.includes('[')) {
          const [base_t, rest] = type.split('[');
          const [typed_size] = rest.split(']');
          const mem_size =
            get_type_size(base_t as native_t) * parseInt(typed_size);
          let dependancy;
          if (type.includes('?->')) {
            const [, name] = type.split('->');
            dep_stack[name] = {
              dep_ptr: pointer,
              dep_key: key,
              dep_t: base_t,
            };
            deref_struct[key] = null;
            pointer += mem_size;
            continue;
          } else if (type.includes('->')) {
            [, dependancy] = type.split('->');
          }
          if (type.includes('char')) {
            deref_struct[key] = Memory.read(pointer, 'char');
            pointer += mem_size;
          } else {
            const arr_size = dependancy ? deref_struct[dependancy] : typed_size;
            if (isNaN(arr_size)) {
              throw new Error(`Invalid array size: ${arr_size}`);
            }
            const arr_values: Array<any> = [];
            for (let i = 0; i < arr_size; i++) {
              arr_values[i] = Memory.read(pointer, base_t as native_t);
              pointer += get_type_size(base_t as native_t);
            }
            if (dependancy) {
              pointer +=
                (parseInt(typed_size) - deref_struct[dependancy]) *
                get_type_size(base_t as native_t);
            }
            deref_struct[key] = arr_values;
          }
        } else {
          deref_struct[key] = Memory.read(pointer, type as native_t);
          pointer += get_type_size(type as native_t);
        }

        if (dep_stack.hasOwnProperty(key)) {
          const dep_arr = [];
          let { dep_t, dep_ptr, dep_key } = dep_stack[key];
          for (let i = 0; i < deref_struct[key]; i++) {
            dep_arr.push(Memory.read(dep_ptr, dep_t as native_t));
            dep_ptr += get_type_size(dep_t as native_t);
          }
          deref_struct[dep_key] = dep_arr;
        }
      }
    }

    return deref_struct;
  }

  export function get_struct_size(struct: struct_t): number {
    let size = 0;
    if (typeof struct === 'function') throw 'unreachable';
    for (const key in struct) {
      if (struct.hasOwnProperty(key)) {
        const type = struct[key];
        if (typeof type === 'function') {
          let fn_type_info = fn_cache.get(type);
          if (!fn_type_info) {
            fn_type_info = type(0, {});
            fn_cache.set(type, fn_type_info);
          }
          const { offset } = fn_type_info;
          size += offset;
        } else if (typeof type === 'object') {
          size += get_struct_size(type);
        } else if ((type as string).includes('padding')) {
          size += parseInt(/\[(\d*)\]/.exec(type as string)?.[1] ?? '0');
        } else if ((type as string).includes('[')) {
          const [base_t, arr_size_str] = (type as string).split('[');
          const arr_size = parseInt(arr_size_str.slice(0, -1), 10);
          if (isNaN(arr_size)) {
            throw new Error(`Invalid array size: ${arr_size_str}`);
          }
          size += get_type_size(base_t as native_t) * arr_size;
        } else {
          size += get_type_size(type as native_t);
        }
      }
    }
    return size;
  }

  export function get_type_size(type: native_t): number {
    switch (type) {
      case 'char':
      case 'i8':
      case 'byte':
      case 'u8':
      case 'ubyte':
      case 'bool':
        return 1;
      case 'i16':
      case 'short':
      case 'u16':
      case 'ushort':
        return 2;
      case 'i32':
      case 'int':
      case 'u32':
      case 'uint':
      case 'float':
      case 'f32':
        return 4;
      case 'i64':
      case 'long':
      case 'u64':
      case 'ulong':
      case 'double':
      case 'f64':
        return 8;
      case '*':
      case 'void*':
      case 'ptr':
      case '*':
        return 4;
      default:
        throw new Error(`Unsupported type: ${type}`);
    }
  }

  export function new_callback(
    func: Function,
    ret_t: wasm_t,
    arg_types: Array<wasm_t>,
  ): js_callback {
    const type_map: Record<wasm_t, string> = {
      void: 'v',
      int: 'i',
      long: 'j',
      float: 'f',
      double: 'd',
    };

    const return_sig: string = type_map[ret_t];
    const wasm_args: Array<string> = arg_types.map((type) => type_map[type]);

    const signature: string = return_sig + wasm_args.join('');
    const function_ptr: ptr = Wrapper.addFunction(func, signature);

    return {
      pointer: function_ptr,
      free: () => Wrapper._free(function_ptr),
    };
  }
}
