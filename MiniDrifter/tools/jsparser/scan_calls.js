/**
 * Walk a mini-program directory and emit platform request call sites.
 * stdout: JSON object { "rel/file.js": [ {callee, start, argStart, argEnd, line} ] }
 */
const fs = require('fs');
const path = require('path');
const acorn = require('acorn');

const TARGETS = new Set([
  'wx.request', 'wx.uploadFile', 'wx.downloadFile',
  'my.request', 'my.httpRequest',
  'swan.request',
  'tt.request',
]);

function walk(dir, out) {
  for (const name of fs.readdirSync(dir)) {
    if (name === 'node_modules' || name === 'miniprogram_npm') continue;
    const full = path.join(dir, name);
    const st = fs.statSync(full);
    if (st.isDirectory()) walk(full, out);
    else if (name.endsWith('.js')) out.push(full);
  }
}

function calleeName(node) {
  const c = node.callee;
  if (!c) return '';
  if (c.type === 'Identifier') return c.name;
  if (c.type === 'MemberExpression' && !c.computed && c.property && c.property.type === 'Identifier') {
    const obj = c.object && c.object.type === 'Identifier' ? c.object.name : '';
    return obj ? obj + '.' + c.property.name : c.property.name;
  }
  return '';
}

function scanFile(file, root) {
  const text = fs.readFileSync(file, 'utf8');
  let ast;
  try {
    ast = acorn.parse(text, {
      ecmaVersion: 'latest',
      sourceType: 'script',
      locations: true,
      allowReturnOutsideFunction: true,
      allowImportExportEverywhere: true,
      allowHashBang: true,
    });
  } catch (err) {
    return { rel: path.relative(root, file).replace(/\\/g, '/'), error: String(err.message).slice(0, 180), calls: [] };
  }
  const calls = [];
  const stack = [ast];
  while (stack.length) {
    const node = stack.pop();
    if (!node || typeof node !== 'object') continue;
    if (node.type === 'CallExpression') {
      const name = calleeName(node);
      if (TARGETS.has(name) && node.arguments && node.arguments.length) {
        const arg0 = node.arguments[0];
        calls.push({
          callee: name,
          start: node.start,
          argStart: arg0.start,
          argEnd: arg0.end,
          line: node.loc ? node.loc.start.line : 1,
        });
      }
    }
    for (const key of Object.keys(node)) {
      if (key === 'loc' || key === 'start' || key === 'end') continue;
      const child = node[key];
      if (Array.isArray(child)) {
        for (let i = child.length - 1; i >= 0; i--) {
          if (child[i] && typeof child[i].type === 'string') stack.push(child[i]);
        }
      } else if (child && typeof child.type === 'string') {
        stack.push(child);
      }
    }
  }
  return { rel: path.relative(root, file).replace(/\\/g, '/'), calls };
}

const root = process.argv[2];
if (!root) {
  console.error('usage: node scan_calls.js <root>');
  process.exit(2);
}
const files = [];
walk(root, files);
const result = {};
let parsed = 0;
let failed = 0;
for (const file of files) {
  const item = scanFile(file, root);
  if (item.error) failed += 1;
  else parsed += 1;
  if (item.calls.length) result[item.rel] = item.calls;
}
process.stdout.write(JSON.stringify({ parsed, failed, files: files.length, calls: result }));
