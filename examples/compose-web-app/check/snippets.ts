// Every snippet the recipe's page and manifest name is present in the
// example source, opened and closed once. Run from the recipe directory:
// `node check/snippets.ts`.
import { readFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const recipe = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const read = (file: string) => readFileSync(resolve(recipe, file), "utf8");

const manifest = JSON.parse(read("recipe.json")) as {
  snippets: { file: string; markers: string[] }[];
  files: string[];
};
const page = read("README.md");
const named = new Set(
  [...page.matchAll(/`snippet:([a-z-]+)`/g)].map((match) => match[1]!),
);

let failed = false;
const fail = (message: string) => {
  console.error(message);
  failed = true;
};

for (const file of manifest.files) {
  try {
    read(file);
  } catch {
    fail(`recipe.json lists ${file}, which does not exist`);
  }
}

const listed = new Set<string>();
for (const { file, markers } of manifest.snippets) {
  const source = read(file).split("\n");
  for (const marker of markers) {
    listed.add(marker);
    const opened = source.filter((line) => line.trim() === `// snippet:${marker}`);
    const closed = source.filter((line) => line.trim() === `// end:${marker}`);
    if (opened.length !== 1 || closed.length !== 1) {
      fail(`${file}: snippet ${marker} is opened ${opened.length} and closed ${closed.length} times`);
    }
  }
}
for (const marker of named) {
  if (!listed.has(marker)) fail(`README.md names snippet ${marker}, absent from recipe.json`);
}
for (const marker of listed) {
  if (!named.has(marker)) fail(`recipe.json lists snippet ${marker}, which README.md does not explain`);
}

if (failed) process.exit(1);
console.log(`snippets: ${[...listed].join(", ")}`);
