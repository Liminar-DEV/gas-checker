const assert = require("assert");
const { makeCode, parseMessage, verdict, groupCode, plural, matchCount, formatMs, CODE_RE } = require("./logic.js");
const crypto = require("crypto");

const rnd = (a) => crypto.getRandomValues(a);
for (let i = 0; i < 200; i++) assert.match(makeCode(rnd), CODE_RE);
// bytes >= 248 are skipped: 255s then 0s must yield only 'A'
let calls = 0;
assert.strictEqual(makeCode((a) => (a.fill(calls++ ? 0 : 255))), "AAAAAAAAAAAA");

assert.strictEqual(groupCode("ABCDEFGHJKMN"), "ABCD-EFGH-JKMN");

assert.strictEqual(parseMessage("not json"), null);
assert.strictEqual(parseMessage('{"v":2,"t":"hello"}'), null);
assert.strictEqual(parseMessage('{"v":1,"t":"zzz"}'), null);
assert.strictEqual(parseMessage('{"v":1,"t":"progress","phase":"x"}'), null);
assert.deepStrictEqual(parseMessage('{"v":1,"t":"hello","host":"PC"}'), { t: "hello", host: "PC" });
assert.deepStrictEqual(parseMessage('{"v":1,"t":"progress","phase":"checking","checked":3,"total":10}'),
  { t: "progress", phase: "checking", checked: 3, total: 10 });
const r = parseMessage('{"v":1,"t":"result","jars":5,"unreadable":1,"ms":99,"stalled":0,"det":[{"k":"meteor","p":"C:\\\\a.jar"}],"sus":[],"more":2}');
assert.strictEqual(r.det[0].p, "C:\\a.jar");
assert.strictEqual(r.more, 2);
assert.strictEqual(parseMessage('{"v":1,"t":"result","det":[{"k":1}],"sus":[]}'), null);

assert.strictEqual(verdict({ det: [1], sus: [1] }), "detected");
assert.strictEqual(verdict({ det: [], sus: [1] }), "suspicious");
assert.strictEqual(verdict({ det: [], sus: [] }), "clean");
const P = ["а", "б", "в"];
[[1, "а"], [2, "б"], [5, "в"], [11, "в"], [12, "в"], [21, "а"], [22, "б"], [25, "в"]].forEach(([n, w]) => assert.strictEqual(plural(n, P), w));
assert.strictEqual(matchCount({ det: [1], sus: [1, 2] }), 1);
assert.strictEqual(matchCount({ det: [], sus: [1, 2] }), 2);
assert.strictEqual(formatMs(41000), "41 с");
assert.strictEqual(formatMs(65000), "1 мин 5 с");
assert.strictEqual(formatMs(60000), "1 мин 0 с");
console.log("ok");
