'use strict';
// Plain-node test runner (no framework). Run: node test/lineBuffer.test.js
const assert = require('assert');
const { createLineBuffer } = require('../lib/lineBuffer');

let passed = 0, failed = 0;
function test(name, fn) {
  try { fn(); passed++; console.log(`  ok  - ${name}`); }
  catch (e) { failed++; console.log(`FAIL  - ${name}\n        ${e.message}`); }
}

const MB = 1024 * 1024;

test('splits on \\n into lines, keeps trailing partial in pending', () => {
  const b = createLineBuffer(MB);
  b.append('one\ntwo\nthree');
  assert.strictEqual(b.lines.length, 2);
  assert.strictEqual(b.lines[0].data, 'one\n');
  assert.strictEqual(b.lines[1].data, 'two\n');
  assert.strictEqual(b.pending, 'three');
});

test('does not split on \\n inside a CSI escape sequence', () => {
  const b = createLineBuffer(MB);
  b.append('\x1b[\n31mhi\n');
  assert.strictEqual(b.lines.length, 1);
  assert.strictEqual(b.lines[0].data, '\x1b[\n31mhi\n');
});

test('evicts oldest lines past maxBytes and advances firstLineIndex', () => {
  const b = createLineBuffer(100); // tiny budget
  for (let i = 0; i < 50; i++) b.append('0123456789\n'); // 11 bytes each
  assert.ok(b.totalBytes <= 100, `totalBytes=${b.totalBytes}`);
  assert.ok(b.firstLineIndex > 0, 'firstLineIndex should advance');
  assert.strictEqual(b.firstLineIndex + b.lines.length, 50);
});

// Raw fidelity: \r and cursor-addressed bytes are preserved verbatim (NOT collapsed) so a
// TUI's screen can be reconstructed by replaying the stored stream.
test('preserves \\r verbatim — does not collapse carriage returns', () => {
  const b = createLineBuffer(MB);
  b.append('0%\r10%\r100%\n');
  assert.strictEqual(b.lines.length, 1);
  assert.strictEqual(b.lines[0].data, '0%\r10%\r100%\n'); // stored exactly as received
});

test('CRLF is stored as a normal line ending', () => {
  const b = createLineBuffer(MB);
  b.append('hello world\r\n');
  assert.strictEqual(b.lines.length, 1);
  assert.strictEqual(b.lines[0].data, 'hello world\r\n');
  assert.strictEqual(b.pending, '');
});

test('CRLF split across two chunks reassembles correctly', () => {
  const b = createLineBuffer(MB);
  b.append('hello world\r'); // \r at end of chunk
  b.append('\nnext');         // \n flushes the full line
  assert.strictEqual(b.lines.length, 1);
  assert.strictEqual(b.lines[0].data, 'hello world\r\n');
  assert.strictEqual(b.pending, 'next');
});

test('tailByBytes includes pending and reports correct line range', () => {
  const b = createLineBuffer(MB);
  b.append('a\nb\nc\n');     // 3 lines, indices 0,1,2
  b.append('partial');       // unterminated tail
  const t = b.tailByBytes(2);
  assert.strictEqual(t.pending, 'partial');
  assert.strictEqual(t.endLine, 3);
});

// ---- Alternate-screen (tmux / vim / htop): do NOT cache while active ----
test('does not cache output while on the alternate screen', () => {
  const b = createLineBuffer(MB);
  b.append('shell line before\n');
  b.append('\x1b[?1049h');                 // enter alt screen (tmux)
  assert.strictEqual(b.altScreen, true);
  b.append('TUI_REPAINT_1\nTUI_REPAINT_2\n'); // full-screen repaint — must NOT be cached
  const text = b.lines.map(l => l.data).join('');
  assert.ok(text.includes('shell line before'), 'pre-alt scrollback preserved');
  assert.ok(!text.includes('TUI_REPAINT'), 'alt-screen output not cached');
});

test('resumes caching after leaving the alternate screen', () => {
  const b = createLineBuffer(MB);
  b.append('before\n');
  b.append('\x1b[?1049h');
  b.append('vim stuff here\n');
  b.append('\x1b[?1049l');                  // exit alt screen
  assert.strictEqual(b.altScreen, false);
  b.append('after vim\n');
  const text = b.lines.map(l => l.data).join('');
  assert.ok(text.includes('before') && text.includes('after vim'), 'pre/post-alt lines cached');
  assert.ok(!text.includes('vim stuff'), 'alt-screen content dropped');
});

test('handles ?47h / ?1047h alternate-screen variants', () => {
  const b = createLineBuffer(MB);
  b.append('\x1b[?47h'); assert.strictEqual(b.altScreen, true);
  b.append('\x1b[?47l'); assert.strictEqual(b.altScreen, false);
  b.append('\x1b[?1047h'); assert.strictEqual(b.altScreen, true);
  b.append('\x1b[?1047l'); assert.strictEqual(b.altScreen, false);
});

console.log(`\n${passed} passed, ${failed} failed`);
process.exit(failed ? 1 : 0);
