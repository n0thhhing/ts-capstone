import fs from 'fs';
import { Glob } from "bun";
import path from 'path';

function transform(inputFilePaths: string[], outputDir: string): void {
    try {
        const combinedTsContent: { [key: string]: { entries: Set<string>, comment?: string } } = {};

        for (const inputFilePath of inputFilePaths) {
            const fileName = path.basename(inputFilePath, '.h');
            const outputFilePath = path.join(outputDir, `${fileName}_const.ts`);
            const hFileContent = fs.readFileSync(inputFilePath, 'utf-8');
            let tsContent = '';
            const enums = {};
            const lines = hFileContent.split("\n");
            let isInEnum = false;
            let current = "";
            let commentBuffer = '';
            for (const line of lines) {
                if (/^\s*\/\/\s*/.test(line)) {
                    commentBuffer += line.trim() + '\n';
                } else if (/enum \S+.*{/g.test(line)) {
                    const name = /enum (\S+)/.exec(line)[1];
                    current = name;
                    enums[name] = new Set();
                    combinedTsContent[name] = { entries: new Set(), comment: commentBuffer.trim() };
                    isInEnum = true;
                    commentBuffer = '';
                } else if (isInEnum && line.includes("}")) {
                    isInEnum = false;
                } else if (isInEnum) {
                    const entry = line.replace(/(\d*)U/g, "$1");
                    enums[current].add(entry);
                    combinedTsContent[current].entries.add(entry);
                }
            }

            for (const key in enums) {
                const { entries, comment } = combinedTsContent[key];
                tsContent += `${comment ? comment + '\n' : ''}export enum ${key} {\n`;
                entries.forEach(entry => tsContent += entry + "\n");
                tsContent += "}\n\n";
            }

            fs.writeFileSync(outputFilePath, tsContent);
            console.log(`Conversion successful. Output written to ${outputFilePath}`);
        }

        // Write combined output file
        const combinedOutputFilePath = path.join(outputDir, 'all_const.ts');
        let combinedTsContentStr = '';
        for (const key in combinedTsContent) {
            const { entries, comment } = combinedTsContent[key];
            combinedTsContentStr += `${comment ? comment + '\n' : ''}export enum ${key} {\n`;
            entries.forEach(entry => combinedTsContentStr += entry + "\n");
            combinedTsContentStr += "}\n\n";
        }
        fs.writeFileSync(combinedOutputFilePath, combinedTsContentStr);
        console.log(`Combined conversion successful. Output written to ${combinedOutputFilePath}`);
    } catch (err) {
        console.error('Error converting file:', err);
    }
}

const glob = new Glob("**/*.h");

const inputFilePaths = glob.scanSync({absolute: true, cwd: './capstone/include/capstone'})

console.log(glob.scan('.'))
const outputDir = 'const';
transform(inputFilePaths, outputDir);
