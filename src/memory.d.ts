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
    | ((
        pointer: number,
        struct: any,
      ) => {
        offset: number;
        entry: any;
      });
}
export declare namespace Memory {
  const allocatedMemory: Set<ptr>;
  function malloc(size: number): ptr;
  function free(mem: ptr | Set<ptr> | Array<ptr>): void;
  function setValue(
    pointer: ptr,
    value: any,
    type: CTypes | CArrType<CTypes>,
  ): void;
  function getValue(pointer: ptr, type: CTypes): any;
  function dereferencePointer(pointer: ptr, types: StructTypes): any;
  function getStructSize(struct: StructTypes): number;
  function getTypeSize(type: CTypes): number;
  function createCallback(
    func: Function,
    returnType: WasmSigType,
    argumentTypes: Array<WasmSigType>,
  ): JsCallback;
}
export {};
