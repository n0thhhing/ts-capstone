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
type pointer_t<T extends any> = number;
export declare namespace Memory {
  const allocations: Set<pointer_t<any>>;
  const nullptr: pointer_t<0>;
  function malloc(size: number): pointer_t<any>;
  function free(
    mem: pointer_t<any> | Set<pointer_t<any>> | pointer_t<any>[],
  ): void;
  function clean(): void;
  function write(
    pointer: pointer_t<any>,
    value: any,
    type: native_t | arr_t<native_t>,
  ): void;
  function read(pointer: pointer_t<any>, type: native_t): any;
}
export {};
