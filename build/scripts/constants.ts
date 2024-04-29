// Capstone Disassembler Engine
// By Dang Hoang Vu, 2013
// Modified by GitHub user n0thhhing

import * as fs from 'fs';
import * as path from 'path';

const INCL_DIR: string = './capstone/include/capstone/';

const include: string[] = ['arm.h', 'arm64.h', 'm68k.h', 'mips.h', 'x86.h', 'ppc.h', 'sparc.h', 'systemz.h', 'xcore.h', 'tms320c64x.h', 'm680x.h', 'evm.h', 'mos65xx.h', 'wasm.h', 'bpf.h', 'riscv.h', 'tricore.h'];

const template: Record<string, any> = {
    'typescript': {
        'header': "// For Capstone Engine. AUTO-GENERATED FILE, DO NOT EDIT\n",
        'footer': "",
        'line_format': '\t%s = %s,\n',
        'out_file': 'src/constants/%sConst.ts',
        // prefixes for constant filenames of all archs - case sensitive
        'arm.h': 'ARM',
        'arm64.h': 'ARM64',
        'm68k.h': 'M68K',
        'mips.h': 'MIPS',
        'x86.h': 'X86',
        'ppc.h': 'PPC',
        'sparc.h': 'SPARC',
        'systemz.h': 'SYSTEMZ',
        'xcore.h': 'XCORE',
        'tms320c64x.h': 'TMS320C64X',
        'm680x.h': 'M680X',
        'evm.h': 'EVM',
        'wasm.h': 'WASM',
        'mos65xx.h': 'MOS65XX',
        'bpf.h': 'BPF',
        'riscv.h': 'RISCV',
        'tricore.h': 'TRICORE',
        'comment_open': '//',
        'comment_close': '',
    }
};

// markup for comments to be added to autogen files
const MARKUP: string = '//>';

function camelize(name: string): string {
    const parts: string[] = name.split('_');
    return parts[0].toLowerCase() + parts.slice(1).map(part => part.charAt(0).toUpperCase() + part.slice(1)).join('');
}

function pascalize(name: string): string {
    const parts: string[] = name.split('_');
    return parts.map(part => part.charAt(0).toUpperCase() + part.slice(1)).join('');
}

function enumType(name: string, templ: any): string {
    for (const [enumType, pattern] of Object.entries(templ['enum_types'])) {
        if (RegExp(pattern).test(name)) {
            return enumType;
        }
    }
    return templ['enum_default_type'];
}

function writeEnumExtraOptions(outfile: fs.WriteStream, templ: any, enumName: string, enumValues: Record<string, any>): void {
    if ('enum_extra_options' in templ && enumName in templ['enum_extra_options']) {
        const extraOptions = templ['enum_extra_options'][enumName];
        for (const [name, value] of Object.entries(extraOptions)) {
            if (typeof value === 'string') {
                // evaluate within existing enum
                const evaluatedValue = eval(value);
                outfile.write(templ['line_format'].replace('%s', name).replace('%s', evaluatedValue));
            }
        }
    }
}

function gen(lang: string): void {
    console.log('Generating bindings for', lang);
    const templ = template[lang];
    for (const target of include) {
        if (!(target in templ)) {
            console.warn("Warning: No binding found for", target);
            continue;
        }
        const prefix: string = templ[target];
        const outfilePath: string = path.join('const', `${prefix}Const.ts`);
        const outfile: fs.WriteStream = fs.createWriteStream(outfilePath);

        outfile.write(templ['header']);

        const lines: string[] = fs.readFileSync(path.join(INCL_DIR, target), 'utf-8').split('\n');
        const constants: Record<string, string> = {};

        let count: number = 0;

        for (let line of lines) {
            line = line.trim();

            if (line.startsWith(MARKUP)) {
                continue;
            }

            if (line === '' || line.startsWith('//')) {
                continue;
            }

            if (line.startsWith('#define ')) {
                line = line.slice(8); // cut off define
                const xline = line.split(/\s+/); // split to at most 2 express
                if (xline.length !== 2) {
                    continue;
                }
                if (/\(|\)/.test(xline[0])) { // does it look like a function
                    continue;
                }
                xline.splice(1, 0, '='); // insert an = so the expression below can parse it
                line = xline.join(' ');
            }

            const tmp: string[] = line.split(',');
            for (let t of tmp) {
                t = t.trim();
                if (!t || t.startsWith('//')) continue;
                t = t.replace('(uint64_t)', '');
                t = t.replace(/\((\d+)ULL << (\d+)\)/, '$1 << $2'); // (1ULL<<1) to 1 << 1
                const f: string[] = t.split(/\s+/);

                if (!f[0].startsWith(prefix)) {
                    continue;
                }

                if (f.length > 1 && !['//', '///<', '='].includes(f[1])) {
                    console.error("Error: Unable to convert", f);
                    continue;
                } else if (f.length > 1 && f[1] === '=') {
                    var rhs = f.slice(2).join(' ');
                } else {
                    var rhs = count.toString();
                    count++;
                }

                try {
                    count = parseInt(rhs) + 1;
                    if (count === 1) {
                        outfile.write('\n');
                    }
                } catch (error) {
                    if (lang === 'typescript') {
                        // TypeScript does not need transformation
                    }
                }

                let name: string = f[0];

                if ('rename' in templ) {
                    // constant renaming
                    for (const [pattern, replacement] of Object.entries(templ['rename'])) {
                        if (RegExp(pattern).test(name)) {
                            name = name.replace(RegExp(pattern), replacement);
                            break;
                        }
                    }
                }

                constants[name] = rhs;
            }
        }

        outfile.write(`export enum ${prefix} {\n`);
        for (const [name, value] of Object.entries(constants)) {
            outfile.write(templ['line_format'].replace('%s', name).replace('%s', value));
        }
        outfile.write(`}\n`);
        outfile.write(templ['footer']);
        outfile.close();
    }
}

function main(): void {
    try {
        const binding: string = process.argv[2];
        if (binding === 'typescript') {
            gen(binding);
        } else {
            console.error(`Unsupported binding ${binding}`);
        }
    } catch (error) {
        throw new Error(`Unsupported binding ${process.argv[2]}`);
    }
}

if (process.argv.length < 3) {
    console.log("Usage:", process.argv[1], "<bindings: typescript>");
    process.exit(1);
}

main();
