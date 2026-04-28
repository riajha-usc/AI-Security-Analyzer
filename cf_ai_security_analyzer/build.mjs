#!/usr/bin/env node
/**
 * build.mjs
 * Reads public/index.html and inlines it into src/index.ts
 * by replacing the __HTML_PLACEHOLDER__ token.
 *
 * Run: node build.mjs
 * The output is written to dist/index.ts which wrangler then compiles.
 */

import fs from "fs";
import path from "path";
import { fileURLToPath } from "url";

const __dirname = path.dirname(fileURLToPath(import.meta.url));

const htmlPath = path.join(__dirname, "public", "index.html");
const srcPath = path.join(__dirname, "src", "index.ts");
const distDir = path.join(__dirname, "dist");
const outPath = path.join(distDir, "index.ts");

if (!fs.existsSync(distDir)) fs.mkdirSync(distDir, { recursive: true });

// Copy all src files to dist
const srcFiles = fs.readdirSync(path.join(__dirname, "src"));
for (const file of srcFiles) {
  fs.copyFileSync(
    path.join(__dirname, "src", file),
    path.join(distDir, file)
  );
}

// Inline HTML into index.ts
const html = fs.readFileSync(htmlPath, "utf-8");
const escapedHTML = html
  .replace(/\\/g, "\\\\")
  .replace(/`/g, "\\`")
  .replace(/\$\{/g, "\\${");

let indexSrc = fs.readFileSync(outPath, "utf-8");
indexSrc = indexSrc.replace("`__HTML_PLACEHOLDER__`", `\`${escapedHTML}\``);
fs.writeFileSync(outPath, indexSrc);

console.log("✓ Build complete → dist/");
console.log(`  HTML inlined: ${(html.length / 1024).toFixed(1)}KB`);
