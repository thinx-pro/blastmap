// Copies src/rules.js to docs/rules.js so the web checker uses the same rules.
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
fs.copyFileSync(path.join(root, "src", "rules.js"), path.join(root, "docs", "rules.js"));
console.log("docs/rules.js updated");
