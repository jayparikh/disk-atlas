const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const vm = require("node:vm");

const html = fs.readFileSync(path.join(__dirname, "index.html"), "utf8");
const start = html.indexOf("function treemapLayout(");
const end = html.indexOf("\nfunction mapInspect(", start);
assert.ok(start > 0 && end > start);
const layout = vm.runInNewContext(`(${html.slice(start, end)})`);

function verify(values, width = 1328, height = 820) {
  const rectangles = layout(values.map(bytes => ({ bytes })), 3, 32, width, height);
  assert.ok(rectangles.every(rect => [rect.x, rect.y, rect.w, rect.h].every(Number.isFinite)));
  for (const rect of rectangles) {
    assert.ok(rect.w >= 0 && rect.h >= 0);
    assert.ok(rect.x >= 3 - 1e-6 && rect.y >= 32 - 1e-6);
    assert.ok(rect.x + rect.w <= width + 3 + 1e-6);
    assert.ok(rect.y + rect.h <= height + 32 + 1e-6);
  }
  if (values.some(value => value > 0)) {
    const area = rectangles.reduce((sum, rect) => sum + rect.w * rect.h, 0);
    assert.ok(Math.abs(area - width * height) < 0.01);
  } else {
    assert.equal(rectangles.length, 0);
  }
}

verify([]);
verify([0, 0]);
verify([70, 25, 5]);
verify([1], 339, 614);
for (let length = 1; length < 100; length += 7) {
  verify(Array.from({ length }, (_, index) => Math.pow(1.7, length - index)));
  verify(Array.from({ length }, () => 1), 339, 660);
}
console.log("Treemap geometry: finite coordinates, bounds and area conservation passed.");
