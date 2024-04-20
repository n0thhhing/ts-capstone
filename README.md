This module provides thin bindings for the Capstone disassembly framework.

```bash
# soon this will be a npm package
git clone https://github.com/n0thhhing/capstone-wrapper
```

## Example

```typescript
import cs, { cs_arch, cs_mode, cs_insn } from "./path/to/wrapper.js"; // soon this will be a package to import via npm, bun, yarn ect ...

const arch: cs_arch = cs.ARCH_ARM64; // or cs.ARCH_AARCH64.
const mode: cs_mode = cs.MODE_ARCH;

// prettier-ignore
const code: Array<number> = [
  0x00, 0x00, 0x80, 0xd2, // 0x1000: mov x0, #0
  0xfd, 0xfb, 0xff, 0x17, // 0x1004: b #0xfffffffffffffff8
  0x88, 0x02, 0x40, 0xb9, // 0x1008: ldr w8, [x20]
  0x20, 0x00, 0x02, 0x8b, // 0x100c: add x0, x1, x2
  0x20, 0x00, 0x00, 0xf9, // 0x1010: str x0, [x1]
  0x20, 0x00, 0x42, 0xf8, // 0x1014: ldur x0, [x1, #0x20]
  0x20, 0x88, 0x82, 0x4f, // 0x1018: mul v0.4s, v1.4s, v2.s[2]
];

const disassembler = new cs.Capstone(arch, mode);

const instructions: Array<cs_insn> = disassembler.disasm(code, 0x1000, /* optional length */);
for (const insn of instructions)
  console.log(
    `0x${insn.address.toString(16)}\t${insn.mnemonic}\t${insn.op_str}`,
  );
/*
the instruction array will look sort of like this:
[
  {
    id: 654, // can be found in src/constants/
    address: 4096, // 0x1000
    size: 4,
    mnemonic: "mov",
    op_str: "x0, #0",
    bytes: [ 0, 0, 128, 210 ]
    // If you have detail enabled you will have
    // a object called detail, most of it depends on
    // the chosen architecture or the instruction
    detail: {
      regs_write: [ ... ],
      groups: [ ... ],
      ​​regs_read: [ ... ],
      regs_read_count: 1,
      regs_write_count: 1,
      groups_count: 1,
      // ...
      // The detail object will have information
      // specific to your chosen architecture, this
      // contains things like operands, registers,
      // and other details involving the instruction.
      arm64: {
        // ...
      }
    }
  },
  // ...
]
*/

// if you want to iterate one at a time
// you can use the disasm_iter method,
// this is actually faster than using
// cs.disasm() due to set memory allocation.
const data = {
  // the input will have to be an object
  // because primitive values like booleans,
  // Numbers, strings, ect, are read only
  // (The function copies the value).
  buffer: armBuffer,
  addr: 0x1000,
  insn: { ... }, // or null, this will be filled once you call disasm_iter.
};

// this returns a boolean, which will become
// false either when it is done iterating,
// or if it comes upon an invalid instruction.
while (disassembler.disasm_iter(data)) {
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
// disassembler instance, movz will be aliased to
// foo, the id will still remain the same as movz.
// To reset the mnemonic, recall this with the same
// id, but with mnemonic set to null(JavaScript null)
const mnObj = {
  id: 191, // the id returned in the insn object, in this case, its movz, you can also find more in the constants directory.
  mnemonic: "foo", // the new name of the mnemonic, or null
};
disassembler.option(
  cs.OPT_MNEMONIC,
  mnObj
);

// OPT_MODE

// after using this, your disassembler mode
// will be MODE_LITTLE_ENDIAN until the
// instance is closed or changed again.
disassembler.option(
  cs.OPT_MODE,
  cs.MODE_LITTLE_ENDIAN
);

// OPT_SYNTAX

disassembler.option(cs.OPT_SYNTAX, OPT_SYNTAX_INTEL); // Default assembly syntax of all platforms (CS_OPT_SYNTAX).

// OPT_SKIPDATA

// When disassembling binary code, there are
// often sections that contain non-executable
// data, such as ASCII strings, data structures,
// or other non-instruction bytes. By using
// cs.OPT_SKIPDATA, you can instruct Capstone
// to skip over these non-instruction bytes
// and only disassemble the actual instructions.
disassembler.option(
  cs.OPT_SKIPDATA,
  true // true/false/cs.OPT_ON/cs.OPT_OFF
);

// OPT_DETAIL

// This option adds instructions/architecture
// specific detail, like operands, opcodes,
// reg_ids, groups, and in this case, a sub
// arm64 object with detailed info specific
// to the instruction and architecture.
disassembler.option(
  cs.OPT_DETAIL
  true
)

// NOT IMPLEMENTED

// OPT_SKIPDATA_SETUP: will need to implement a way to create the callback this needs, while still keeping as little memory management as possible.
// OPT_UNSIGNED: to little documentation.
// OPT_MEM: unnecessary because you won't need to worry about any memory management.

// support

// this will return a boolean, true if valid
// and false if not, To verify if this library
// supports all the archs, use cs.ARCH_ALL(true),
// To check if this library is in 'diet' mode,
// set query to cs.SUPPORT_DIET(false).
cs.support(cs.MODE_LITTLE_ENDIAN); // true

// version

// The version of capstone this library is using.
cs.version(); // 5.0

// group_name

// This returns the name of the group
// that an instruction can belong to
// These groups can be found in the
// constants directory or the detail obj
// when CS_DETAIL is turned on.
disassembler.group_name(2) // call

// reg_name

// These register IDs can be found either in
// the constants directory or the detail object
// when cs.DETAIL is on, like regs_read/regs_write.
disassembler.reg_name(183); // w15

// insn_name

// this returns the name of the mnemonic
// corresponding to the id. The id can be
// found either from the constants file
// or from disassembly results.
disassembler.insn_name(191); // s28

// close

// this closes the Capstone instance, because we
// are binding c to JS we now have to free unused
// values, JS usually has garbage collection
// but C does not, so we have to free the
// disassembler instance from memory manually
// after it's no longer in use.
disassembler.close();
```

you can also take a look at the [tests](src/tests)

## Constants

if you would like to see all the options and capstone
constants, you can find them in either the [wrapper.ts](src/wrapper.ts)
file or the [constants](src/constants) or things like register ids, options,
error codes, groups, opcodes, manifest constants, ect

## Compatibility

Although all core functions have been implemented to
the best of my ability some helper functions and options
haven't and soon will if they are relivant, all of this includes
the following.

| Case             | Compatibility |                                                            Notes |
| :--------------- | :-----------: | ---------------------------------------------------------------: |
| Detail           |      ✅       |                    Everything has also been checked and verified |
| Architectures    |      ✅       |                                        Eveything relative to 5.0 |
| Options          |      ❌       |                        OPT_MEM, OPT_SKIPDATA_SETUP, OPT_UNSIGNED |
| Helper functions |      ❌       | reg_read, reg_write, insn_group, op_index, op_count, regs_access |
| Web              |      ❔       |                                                         untested |

## TODO

- [ ] Implement all the options
- [ ] Add support for all small helper functions
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

1. Clone the capstone 5.0 repo

```shell
git clone https://github.com/capstone-engine/capstone
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

```javascript
import Module from './capstone.js'; // capstone.js should be in the src directory after building

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
