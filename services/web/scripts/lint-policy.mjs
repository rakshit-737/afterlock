// Policy lint for the investigation frontend. Type errors are caught by
// `npm run typecheck`; this enforces rules a type checker cannot:
//   - API strings are rendered as text: no innerHTML / dangerouslySetInnerHTML / eval.
//   - Bearer tokens stay in memory: no localStorage / sessionStorage / indexedDB / cookies.
//   - No external origins (CDNs) in shipped source or index.html.
import { readFileSync, readdirSync, statSync } from "node:fs";
import { dirname, join, relative } from "node:path";
import { fileURLToPath } from "node:url";

const root = join(dirname(fileURLToPath(import.meta.url)), "..");
const rules = [
  [/dangerouslySetInnerHTML/, "render API strings as text, never as HTML"],
  [/\.(inner|outer)HTML\b/, "render API strings as text, never as HTML"],
  [/insertAdjacentHTML|document\.write/, "no HTML string injection"],
  [/\beval\s*\(|new Function\s*\(/, "no dynamic code evaluation"],
  [/\b(localStorage|sessionStorage|indexedDB)\b|document\.cookie/, "tokens and results must stay in memory"],
  [/https?:\/\/(?!127\.0\.0\.1|localhost)[a-z0-9.-]+\.[a-z]{2,}/i, "no external origins (CDN) in shipped code"],
];

function walk(dir, out = []) {
  for (const name of readdirSync(dir)) {
    const p = join(dir, name);
    if (statSync(p).isDirectory()) walk(p, out);
    else if (/\.(ts|tsx|html|css)$/.test(name) && !/\.test\.tsx?$/.test(name)) out.push(p);
  }
  return out;
}

const files = [...walk(join(root, "src")), join(root, "index.html")];
let failures = 0;
for (const file of files) {
  readFileSync(file, "utf8")
    .split(/\r?\n/)
    .forEach((line, i) => {
      for (const [re, why] of rules) {
        if (re.test(line)) {
          failures++;
          console.error(`${relative(root, file)}:${i + 1}: ${why}\n    ${line.trim()}`);
        }
      }
    });
}
if (failures) {
  console.error(`\n${failures} policy violation(s)`);
  process.exit(1);
}
console.log(`lint-policy: ${files.length} files clean`);
