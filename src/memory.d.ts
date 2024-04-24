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
    | ((
        pointer: number,
        struct: any,
      ) => {
        offset: number;
        entry: any;
      });
}
export declare namespace Memory {
  const allocations: Set<ptr>;
  function malloc(size: number): ptr;
  function free(mem: ptr | Set<ptr> | Array<ptr>): void;
  function clean(): void;
  function write(
    pointer: ptr,
    value: any,
    type: native_t | arr_t<native_t>,
  ): void;
  function read(pointer: ptr, type: native_t): any;
  function deref(pointer: ptr, types: struct_t): any;
  function get_struct_size(struct: struct_t): number;
  function get_type_size(type: native_t): number;
  function new_callback(
    func: Function,
    ret_t: wasm_t,
    arg_types: Array<wasm_t>,
  ): js_callback;
}
export {};
