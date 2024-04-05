const cs_x86: object = {
  prefix: 'ubyte[4]',
  opcode: 'ubyte[4]',
  rex: 'ubyte',
  addr_size: 'ubyte',
  modrm: 'ubyte',
  sib: 'ubyte',
  padding: 'padding[4]',
  disp: 'long',
  sib_index: 'i32',
  sib_scale: 'byte',
  sib_base: 'i32',
  xop_cc: 'i32',
  sse_cc: 'i32',
  avx_cc: 'i32',
  avx_sae: 'bool',
  avx_rm: 'i32',
  flags: {
    eflags: 'ulong',
    fpu_flags: 'ulong',
  },
  operands: 'todo',
};

const cs_x86_encoding = {
  modrm_offset: 'ubyte',
  disp_offset: 'ubyte',
  disp_size: 'ubyte',
  imm_offset: 'ubyte',
  imm_size: 'ubyte',
};

export { cs_x86, cs_x86_encoding };
