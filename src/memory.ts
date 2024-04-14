import { Wrapper } from './wrapper';

type CTypes =
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
type CArrType<T extends CTypes> = `${T}[${number}]`;
type DependantType = `${CArrType<CTypes>}->${string}`;
type ptr = number;
type WasmSigType = 'void' | 'int' | 'long' | 'float' | 'double';

interface JsCallback {
  pointer: ptr;
  free: () => void;
}

interface StructTypes {
  [key: string]:
    | `padding[${number}]`
    | CTypes
    | CArrType<CTypes>
    | DependantType
    | StructTypes
    | ((pointer: number, struct: any) => { offset: number; entry: any });
}

const functionTypeCache: Map<Function, { offset: number; entry: any }> =
  new Map();

export namespace Memory {
  export const allocatedMemory: Set<ptr> = new Set<ptr>();

  export function malloc(size: number): ptr {
    const pointer: ptr = Wrapper._malloc(size);
    allocatedMemory.add(pointer);
    return pointer;
  }

  export function free(mem: ptr | Set<ptr> | Array<ptr>): void {
    if (mem instanceof Set || Array.isArray(mem)) {
      for (const pointer of mem) {
        allocatedMemory.delete(pointer);
        Wrapper._free(pointer);
      }
    } else {
      allocatedMemory.delete(mem);
      Wrapper._free(mem);
    }
  }

  export function setValue(
    pointer: ptr,
    value: any,
    type: CTypes | CArrType<CTypes>,
  ) {
    switch (type) {
      case 'char*':
        const utf8Bytes = [];
        if (!/\0/.test(value)) value += '\0';
        for (let i = 0; i < value.length; ++i) {
          const charCode = value.charCodeAt(i);
          if (charCode < 128) {
            utf8Bytes.push(charCode);
          } else if (charCode < 2048) {
            utf8Bytes.push((charCode >> 6) | 192);
            utf8Bytes.push((charCode & 63) | 128);
          } else {
            utf8Bytes.push((charCode >> 12) | 224);
            utf8Bytes.push(((charCode >> 6) & 63) | 128);
            utf8Bytes.push((charCode & 63) | 128);
          }
        }

        for (let i = 0; i < utf8Bytes.length; ++i) {
          Wrapper.setValue(pointer + i, utf8Bytes[i], 'i8');
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
        Wrapper.HEAP32[pointer >> 2] = value; // Low 32 bits
        Wrapper.HEAP32[(pointer + 4) >> 2] = Math.floor(value / 4294967296); // High 32 bits
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

  export function getValue(pointer: ptr, type: CTypes): any {
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
        const low = Wrapper.HEAP32[pointer >> 2]; // Low 32 bits
        const high = Wrapper.HEAP32[(pointer + 4) >> 2]; // High 32 bits
        value = low + high * 4294967296; // Combine high and low bits
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

  export function dereferencePointer(pointer: ptr, types: StructTypes): any {
    const dereferencedStruct: any = {};
    const dependancyStack: any = {};
    for (const key in types) {
      if (types.hasOwnProperty(key)) {
        const type = types[key];
        if (typeof type === 'function') {
          let functionTypeInfo = functionTypeCache.get(type);
          if (!functionTypeInfo) {
            functionTypeInfo = type(pointer, dereferencedStruct);
            functionTypeCache.set(type, functionTypeInfo);
          }
          const { offset, entry } = functionTypeInfo;
          pointer += offset;
          dereferencedStruct[key] = entry;
        } else if (typeof type === 'object') {
          dereferencedStruct[key] = dereferencePointer(pointer, type);
          pointer += getStructSize(type);
          delete types[
            Object.keys(types).find((key) => key === 'padding') ?? 0
          ];
        } else if (type.includes('padding')) {
          pointer += parseInt(/\[(\d*)\]/.exec(type)?.[1] ?? '0');
        } else if (type.includes('[')) {
          const [baseType, rest] = type.split('[');
          const [typedSize] = rest.split(']');
          const memorySize =
            getTypeSize(baseType as CTypes) * parseInt(typedSize);
          let dependancy;
          if (type.includes('?->')) {
            const [, name] = type.split('->');
            dependancyStack[name] = {
              depPointer: pointer,
              depKey: key,
              depType: baseType,
            };
            dereferencedStruct[key] = null;
            pointer += memorySize;
            continue;
          } else if (type.includes('->')) {
            [, dependancy] = type.split('->');
          }
          if (type.includes('char')) {
            dereferencedStruct[key] = Memory.getValue(pointer, 'char');
            pointer += memorySize;
          } else {
            const arraySize = dependancy
              ? dereferencedStruct[dependancy]
              : typedSize;
            if (isNaN(arraySize)) {
              throw new Error(`Invalid array size: ${arraySize}`);
            }
            const arrayValues: Array<any> = [];
            for (let i = 0; i < arraySize; i++) {
              arrayValues[i] = Memory.getValue(pointer, baseType as CTypes);
              pointer += getTypeSize(baseType as CTypes);
            }
            if (dependancy) {
              pointer +=
                (parseInt(typedSize) - dereferencedStruct[dependancy]) *
                getTypeSize(baseType as CTypes);
            }
            dereferencedStruct[key] = arrayValues;
          }
        } else {
          dereferencedStruct[key] = Memory.getValue(pointer, type as CTypes);
          pointer += getTypeSize(type as CTypes);
        }

        if (dependancyStack.hasOwnProperty(key)) {
          const depArray = [];
          let { depType, depPointer, depKey } = dependancyStack[key];
          for (let i = 0; i < dereferencedStruct[key]; i++) {
            depArray.push(Memory.getValue(depPointer, depType as CTypes));
            depPointer += getTypeSize(depType as CTypes);
          }
          dereferencedStruct[depKey] = depArray;
        }
      }
    }

    return dereferencedStruct;
  }

  export function getStructSize(struct: StructTypes): number {
    let size = 0;
    if (typeof struct === 'function') throw 'unreachable';
    for (const key in struct) {
      if (struct.hasOwnProperty(key)) {
        const type = struct[key];
        if (typeof type === 'function') {
          let functionTypeInfo = functionTypeCache.get(type);
          if (!functionTypeInfo) {
            functionTypeInfo = type(0, {});
            functionTypeCache.set(type, functionTypeInfo);
          }
          const { offset } = functionTypeInfo;
          size += offset;
        } else if (typeof type === 'object') {
          size += getStructSize(type);
        } else if ((type as string).includes('padding')) {
          size += parseInt(/\[(\d*)\]/.exec(type as string)?.[1] ?? '0');
        } else if ((type as string).includes('[')) {
          const [baseType, arraySizeStr] = (type as string).split('[');
          const arraySize = parseInt(arraySizeStr.slice(0, -1), 10);
          if (isNaN(arraySize)) {
            throw new Error(`Invalid array size: ${arraySizeStr}`);
          }
          size += getTypeSize(baseType as CTypes) * arraySize;
        } else {
          size += getTypeSize(type as CTypes);
        }
      }
    }
    return size;
  }

  export function getTypeSize(type: CTypes): number {
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

  export function createCallback(
    func: Function,
    returnType: WasmSigType,
    argumentTypes: Array<WasmSigType>,
  ): JsCallback {
    const typeMap: Record<WasmSigType, string> = {
      void: 'v',
      int: 'i',
      long: 'j',
      float: 'f',
      double: 'd',
    };

    const returnSignature: string = typeMap[returnType];
    const argSignatures: Array<string> = argumentTypes.map(
      (type) => typeMap[type],
    );

    const signature: string = returnSignature + argSignatures.join('');
    const funcPtr: ptr = Wrapper.addFunction(func, signature);

    return {
      pointer: funcPtr,
      free: () => Wrapper.removeFunction(funcPtr),
    };
  }
}
