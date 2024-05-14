This module provides bindings for the Capstone disassembly framework.

```bash
# soon this will be a npm package
git clone https://github.com/n0thhhing/capstone-wrapper
```

## Example

```typescript
import CS, { cs_arch, cs_mode, cs_insn, ARM64 } from './path/to/capstone.ts'; // soon this will be a package to import via npm, bun, yarn ect ...

const arch: cs_arch = CS.ARCH_ARM64; // or CS.ARCH_AARCH64.
const mode: cs_mode = CS.MODE_ARCH;

const code: Array<number> = [
  0x00, 0x00, 0x80, 0xd2, // 0x1000: mov x0, #0
  0xfd, 0xfb, 0xff, 0x17, // 0x1004: b #0xfffffffffffffff8
  0x88, 0x02, 0x40, 0xb9, // 0x1008: ldr w8, [x20]
  0x20, 0x00, 0x02, 0x8b, // 0x100c: add x0, x1, x2
  0x20, 0x00, 0x00, 0xf9, // 0x1010: str x0, [x1]
  0x20, 0x00, 0x42, 0xf8, // 0x1014: ldur x0, [x1, #0x20]
  0x20, 0x88, 0x82, 0x4f, // 0x1018: mul v0.4s, v1.4s, v2.s[2]
];

const cs = new CS.CAPSTONE(arch, mode);

const instructions: Array<cs_insn> = cs.disasm(
  code,
  0x1000 /* optional length */,
);

// An instruction can be found in this basic format
const example_insn: cs_insn = {
  id: 664, // Instruction ID (a numeric ID for the instruction mnemonic)
  address: 4104, // Address (EIP) of this instruction
  size: 4, // Size of this instruction
  mnemonic: 'msr', // Ascii text of instruction mnemonic
  op_str: 'dbgdtrtx_el0, x12', // Ascii text of instruction operands
  bytes: [12, 5, 19, 213], // Machine bytes of this instruction, with number of bytes indicated by size above
  // If you have detail enabled you will have
  // a object called detail, most of it depends on
  // the chosen architecture or the instruction
  detail: {
    regs_write: [], // list of implicit registers modified by this insn
    groups: [6], // list of group this instruction belong to
    regs_read: [], // list of implicit registers read by this insn
    regs_read_count: 0, // number of implicit registers read by this insn
    regs_write_count: 0, // number of implicit registers modified by this insn
    groups_count: 1, // number of groups this insn belongs to
    writeback: false, // Instruction has writeback operands.
    // The detail object will have information
    // specific to your chosen architecture, this
    // contains things like operands, registers,
    // and other details involving the instruction.
    // So... Anything in the object is specific
    // to cs_arch and the instruction itself.
    arm64: {
      operands: [
        {
          vector_index: -1,
          vas: 0,
          shift: { type: 0, value: 0 },
          ext: 0,
          access: 2,
          type: 68, // ARM64.OP_SYS
          sys: 38952,
        },
        {
          vector_index: -1,
          vas: 0,
          shift: { type: 0, value: 0 },
          ext: 0,
          access: 1,
          type: 1, // ARM64.OP_REG
          reg: 230,
        },
      ],
      cc: 0,
      update_flags: false,
      writeback: false,
      post_index: false,
      op_count: 2,
    },
  },
};

for (const insn of instructions)
  console.log(
    `0x${insn.address.toString(16)}\t${insn.mnemonic}\t${insn.op_str}`,
  );

// if you want to iterate one at a time
// you can use the disasm_iter method,
// this is actually faster than using
// cs.disasm() due to set memory allocation.
const data = {
  // the input will have to be an object
  // because primitive values like booleans,
  // Numbers, strings, ect, are read only
  // (The function copies the value).
  buffer: code,
  addr: 0x1000,
  insn: {}, // or null, this will be filled once you call disasm_iter.
};

// this returns a boolean, which will become
// false either when it is done iterating,
// or if it comes upon an invalid instruction.
while (cs.disasm_iter(data)) {
  // every iteration this function goes through,
  // it will edit the data object with the new
  // instruction. also if the current instruction
  // is valid and there are still instructions
  // to go through, the data object will be
  // updated with the next iterations bytes
  // and address, so after the first loop,
  // the buffer will be changed to the next set
  // of bytes and the address will be iterated as well.
  const insn: cs_insn = data.insn;
  console.log(
    `0x${insn.address.toString(16)}\t${insn.mnemonic}\t${insn.op_str}`,
  );
}

// options

// OPT_MNEMONIC

// every time disasm (or disasm_iter) comes across
// a movz instruction in the span of your
// cs instance, movz will be aliased to
// foo, the id will still remain the same as movz.
// To reset the mnemonic, recall this with the same
// id, but with mnemonic set to null(JavaScript null)
const mnObj = {
  id: 191, // the id returned in the insn object, in this case, its movz, you can also find more in the Typescript file corresponding to your arch (arch/<arch>.ts)
  mnemonic: 'foo', // the new name of the mnemonic, or null
};
cs.option(CS.OPT_MNEMONIC, mnObj);

// OPT_MODE

// after using this, your cs mode
// will be MODE_LITTLE_ENDIAN until the
// instance is closed or changed again.
cs.option(CS.OPT_MODE, CS.MODE_LITTLE_ENDIAN);

// OPT_SYNTAX

cs.option(CS.OPT_SYNTAX, CS.OPT_SYNTAX_INTEL); // Default assembly syntax of all platforms (CS_OPT_SYNTAX).

// OPT_SKIPDATA

// When disassembling binary code, there are
// often sections that contain non-executable
// data, such as ASCII strings, data structures,
// or other non-instruction bytes. By using
// CS.OPT_SKIPDATA, you can instruct Capstone
// to skip over these non-instruction bytes
// and only disassemble the actual instructions.
cs.option(
  CS.OPT_SKIPDATA,
  true, // true/false/CS.OPT_ON/CS.OPT_OFF
);

// OPT_DETAIL

// This option adds instructions/architecture
// specific detail, like operands, opcodes,
// reg_ids, groups, and in this case, a sub
// arm64 object with detailed info specific
// to the instruction and architecture.
cs.option(CS.OPT_DETAIL, true);

// OPT_BUFFER

// When enabled, this option instructs Capstone
// to include the raw instruction bytes and detail
// bytes in the disassembled output. These buffers
// contain the original bytes of the instruction
// and any associated detail information,
// respectively. Enabling this option can be
// useful when needing access to the raw
// binary data of disassembled instructions for
// further analysis or processing.
cs.option(CS.OPT_BUFFER, true);

// To access data from the buffer in JavaScript,
// use DataView. For types other than `int32`,
// little-endianness is required due to the nature
// of the underlying buffer being a Uint8Array.
// Use DataView to read the buffer as follows:

// For `int32`: Use `getInt32()` method of DataView
// directly. For other types (e.g., `uint64`),
// specify `littleEndian` as `true` in DataView
// constructor to correctly interpret the bytes.
let buffer = /* Raw buffer received from the insn object */;
let view = new DataView(buffer.buffer);
let id = view.getUint32(0); // Read the 32-bit integer id from the buffer
let address = view.getBigUint64(8, true); // Read a 64-bit integer address with little-endian

// Also for things like strings(cstrings in this case),
// you can simply use a TextDecoder, each character is
// stored as a int8 anyways so all you have to do is
// throw `utf-8` in the TextDecoder constructor
const mnemonic_bytes =
  buffer.slice(
    42, // offset for the mnemonic
    74 // 74 - 42 = 32 = mnemonic max length
  )

// TextDecoder doesn't automatically stop at null
// terminator, this isn't needed if your simply
// inspecting it, but for comparisons there will
// be trailing `\u0000`
const mn_null_index = mn_bytes.indexOf(0);
const truncated_mn =
    mn_null_index !== -1 ? mn_bytes.subarray(0, mn_null_index) : mn_bytes; // slice off every trailing null terminator

const mnemonic = new TextDecoder("utf-8").decode(truncated_mn)

// offsets are as follows:
// id: 0
// address: 8
// size: 16
// bytes: 18
// mnemonic: 42
// op_str: 74
// detail: 0 in the insn.detail.buffer

// NOT IMPLEMENTED

// OPT_SKIPDATA_SETUP: will need to implement a way to create the callback this needs, while still keeping as little memory management as possible.
// OPT_UNSIGNED: to little documentation.
// OPT_MEM: unnecessary because you won't need to worry about any memory management.

// support

// this will return a boolean, true if valid
// and false if not, To verify if this library
// supports all the archs, use CS.ARCH_ALL(true),
// To check if this library is in 'diet' mode,
// set query to CS.SUPPORT_DIET(false).
cs..support(CS.MODE_LITTLE_ENDIAN); // true

// version

// The version of capstone this library is using.
cs.version(); // 5.0

// group_name

// This returns the name of the group
// that an instruction can belong to
// These groups can be found in the
// arch/<arch>.ts file or the detail obj
// when CS_DETAIL is turned on.
cs.group_name(2); // call

// reg_name

// These register IDs can be found either in
// the arch/<arch>.ts file or the detail object
// when CS.DETAIL is on, like regs_read/regs_write.
cs.reg_name(183); // w15

// insn_name

// This returns the name of the mnemonic
// corresponding to the id. The id can be
// found either from the (arch/<arch>.ts)
// file or from disassembly results.
cs.insn_name(191); // s28

// op_index

// This retrieves the "position" of the given type.
// This can be used to determine operands without
// having to manually inspect the operands array.
// This requires the detail object to be present in
// the insn, so CS.OPT_DETAIL needs to be turned on
cs.op_index(example_insn, ARM64.OP_REG, 1); // 1

// op_count

// This retrieves the operand count for the input
// type provided an insn, which allows you to easily
// tell how many of a certain type is present in the // object while not having to manually inspect the
// detail object. This requires the detail object to
// be present in the insn, so CS.OPT_DETAIL needs
// to be turned on
cs.op_count(example_insn, ARM64.OP_REG); // 1

// regs_access

// Retrieve all the registers accessed by an
// instruction, either explicitly or implicitly.
cs.regs_access(example_insn); // { regs_read: [], regs_read_count: 0, regs_write: [], regs_write_count: 0 }

// reg_read

// Check if a disassembled instruction IMPLICITLY
// used a particular register. These registers can
// be found in the constants file corresponding to
// your chosen architecture (arch/<arch>.ts)
cs.reg_read(example_insn, ARM64.REG_NZCV); // false

// reg_write

// Check if a disassembled instruction IMPLICITLY
// modified a particular register. These registers can
// be found in the constants file corresponding to
// your chosen architecture (arch/<arch>.ts)
cs.reg_write(example_insn, ARM64.REG_B0); // false

// insn_group

// Check if a disassembled instruction belong to a
// particular group. You can find these groups
// in the constants file corresponding to your
// chosen architecture (arch/<arch>.ts)
cs.insn_group(example_insn, ARM64.GRP_PRIVILEGE); // true


// fmt

// This method is used to format the instruction
// (or instructions) to be printable, this also
// includes an option param that goes as follows:
const options = {
  bytes: true, // Specifies if the formatted string should have the instructions bytes(default is true).
  address: true, // Specifies if the formatted string should include the instructions address(default is true).
  ASCII: true, // Specifies if the formatted string should include the bytes ASCII representation(default is false).
}
const formatted_insn = cs.fmt(example_insn, options)
console.log(formatted_insn)
/*
output:
0x1008 0c 05 13 d5 .... msr dbgdtrtx_el0, x12
*/

// close

// this closes the Capstone instance, because we
// are binding c to JS we now have to free unused
// values, JS usually has garbage collection
// but C does not, so we have to free the
// cs instance from memory manually
// after it's no longer in use.
cs.close();
```

you can also take a look at the [tests](src/tests)

## Constants

if you would like to see all the options and capstone
constants, you can find them in either the [capstone.ts](src/capstone.ts)
file or the [typescript file](src/arch) (arch/<arch>.ts) for things like register ids, options,
error codes, groups, opcodes, manifest constants, insns, ect

## Compatibility

Although all core functions have been implemented to
the best of my ability some helper functions and options
haven't and soon will if they are relivant, all of this includes
the following.

| Case             | Compatibility |                                                       Notes |
| :--------------- | :-----------: | ----------------------------------------------------------: |
| Detail           |      ✅       |               Everything has also been checked and verified |
| Architectures    |      ✅       |                                   Eveything relative to 5.0 |
| Options          |      ❌       |                   OPT_MEM, OPT_SKIPDATA_SETUP, OPT_UNSIGNED |
| Helper functions |      ✅       | Everything including helper functions have been implemented |
| Web              |      ❔       |                                                    untested |

## TODO

- [ ] Implement all the options
- [x] Add support for all small helper functions
- [ ] Make an npm package
- [ ] Add better tests
- [x] Implement cs_detail
- [x] Make dedicated types
- [x] Add support for all architectures
- [x] Update capstone to 5.0
- [ ] JSDoc
- [ ] Better error handling

## Documentation

For detailed documentation on available constants and methods, refer to the source code comments or the Capstone website:

- [Function Reference](https://code.dlang.org/packages/d-capstone) for constants and function documentation
- [Capstone Website](https://www.capstone-engine.org/iteration.html) capstone website
- [Source](https://github.com/capstone-engine/capstone) source code for capstone

## Credits

- [capstone](https://github.com/capstone-engine/capstone)
- [emscripten](https://emscripten.org/docs/getting_started/downloads.html#sdk-download-and-install)

## Building

### Prerequisites

1. Initialize the original Capstone submodule:

```shell
git submodule update --init
```

2. Make sure you have bun and emsdk installed
3. Install dependancies

```shell
npm i -D
```

### Makefile

The makefile provides some commands for necessary builds, which includes

- `compile`: Compiles capstone into a static library via emcmake
- `build`: Transpiles the static library file into js via emcc(requires make compile first)
- `type`: Genorates declaration files
- `bundle`: Bundles the source into one file via Bun.build
- `format`: Formats everything
- `compare`: A check to see if everything is the same as it is in the official capstone(manual)

### Initializing

```typescript
import Module from "./capstone.js"; // capstone.js should be in the src directory after building
import Memory from "./memory.ts"; // utilities for working with memory

const Capstone = new Module();
// Use as necessary
// ...
```

## Contributing

Contributions to the Capstone module are welcome. If you would like to contribute, please follow these guidelines:

1. Fork the repository and clone it to your local machine.
2. Create a new branch for your feature or bug fix: `git checkout -b my-feature`.
3. Make your changes and test them thoroughly.
4. Commit your changes with a clear and descriptive commit message: `git commit -am 'Add new feature'`.
5. Push your branch to your fork: `git push origin my-feature`.
6. Create a pull request against the main repository's `main` branch.

Before submitting a pull request, ensure that:

- Your code follows the existing style and conventions ( in some cases this doesnt matter )
- You have added appropriate documentation for your changes.
- All existing tests pass, and you have added new tests for any new functionality.
- The fix or added function acts as it does in the official capstone

## Issues

If you encounter any bugs, have questions, or want to suggest new features for the Capstone wrapper, please open an issue on the GitHub repository.

Before opening a new issue, please ensure that:

- You have searched existing issues to see if the problem or suggestion has already been reported.
- You provide detailed information about the problem or suggestion, including steps to reproduce for bugs.
- Make sure this isnt something to do with your JavaScript runtime, or your typescript transpiler

When opening a new issue, please use a clear and descriptive title and provide as much context as possible to help understand the issue or suggestion.
