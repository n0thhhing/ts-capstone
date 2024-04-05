import * as constants from "../../src/constants/all_const.js"
import fs from "fs"

function generateDeclarationFile(constants: Record<string, any>, namespace: string, filePath: string) {
    const declarationLines = Object.entries(constants).map(([key, value]) => `    const ${key}: ${typeof value};`);
    const declarationContent = `${declarationLines.join('\n')}\n`;
    
    const declarationFile = fs.readFileSync("src/wrapper.d.ts", "utf-8")
    
    fs.writeFileSync(filePath, declarationFile.replace(/declare namespace cs \{\n/, `declare namespace cs \{\n${declarationContent}`));
}

generateDeclarationFile(constants, 'cs', 'src/wrapper.d.ts');
