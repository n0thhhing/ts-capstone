import * as constants from "../../src/constants/all_const.js"
import fs from "fs"

function gen(constants: Record<string, any>, namespace: string, filePath: string) {
    const declarationFile = fs.readFileSync(filePath, "utf-8");
    const existing_keys = declarationFile.match(/const\s+(\w+)\s*:/g).map(match => match.match(/const\s+(\w+)\s*:/)[1]);
    
    const new_constants = Object.entries(constants)
        .filter(([key, _]) => !existing_keys.includes(key))
        .map(([key, value]) => `    const ${key}: ${value};`);
        
    const declare_content = `${new_constants.join('\n')}\n`;
    
    fs.writeFileSync(filePath, declarationFile.replace(/declare namespace cs \{\n/, `declare namespace cs \{\n${declare_content}`));
}

gen(constants, 'cs', 'src/wrapper.d.ts');
