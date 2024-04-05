const result = await Bun.build({
  entrypoints: ["src/wrapper.ts"],
  outdir: "./build",
  target: "node",
});

if (!result.success) {
  console.error("Build failed");
  for (const message of result.logs) {
    // Bun will pretty print the message object
    console.error(message);
  }
}

let content = require("fs").readFileSync("build/wrapper.js", "utf8")

content = content.replace(/.*var __dirname.*/g, "")
content = 
`import path from 'node:path';
import { fileURLToPath } from 'node:url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
` + content
require("fs").writeFileSync("build/wrapper.js", content)