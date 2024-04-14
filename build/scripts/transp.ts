import fs from 'fs';
import { glob } from 'glob';
import path from 'path';

function transform(inputFilePaths: string[], outputDir: string): void {
    try {
        const combinedTsContent: { [key: string]: Set<string> } = {};

        for (const inputFilePath of inputFilePaths) {
            const fileName = path.basename(inputFilePath, '.h');
            const outputFilePath = path.join(outputDir, `${fileName}_const.ts`);
            const hFileContent = fs.readFileSync(inputFilePath, 'utf-8');
            let tsContent = '';
            const enums = {};
            const lines = hFileContent.split("\n");
            let isInEnum = false;
            let current = "";

            for (const line of lines) {
                if (/enum \S+.*{/g.test(line)) {
                    const name = /enum (\S+)/.exec(line)[1];
                    current = name;
                    enums[name] = new Set();
                    combinedTsContent[name] = combinedTsContent[name] || new Set();
                    isInEnum = true;
                } else if (isInEnum && line.includes("}")) {
                    isInEnum = false;
                } else if (isInEnum) {
                    const entry = line.replace(/(\d*)U/g, "$1");
                    enums[current].add(entry);
                    combinedTsContent[current].add(entry);
                }
            }

            for (const key in enums) {
                const enumEntries = enums[key];
                tsContent += `export enum ${key} {\n`;
                enumEntries.forEach(entry => tsContent += entry + "\n");
                tsContent += "}\n\n";
            }

            fs.writeFileSync(outputFilePath, tsContent);
            console.log(`Conversion successful. Output written to ${outputFilePath}`);
        }

        // Write combined output file
        const combinedOutputFilePath = path.join(outputDir, 'all_const.ts');
        let combinedTsContentStr = '';
        for (const key in combinedTsContent) {
            combinedTsContentStr += `export enum ${key} {\n`;
            combinedTsContent[key].forEach(entry => combinedTsContentStr += entry + "\n");
            combinedTsContentStr += "}\n\n";
        }
        fs.writeFileSync(combinedOutputFilePath, combinedTsContentStr);
        console.log(`Combined conversion successful. Output written to ${combinedOutputFilePath}`);
    } catch (err) {
        console.error('Error converting file:', err);
    }
}

const inputFilePaths = glob.sync('capstone/include/capstone/*.h');
const outputDir = 'const';
transform(inputFilePaths, outputDir);
