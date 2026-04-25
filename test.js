const assert = require("node:assert/strict");
const fs = require("node:fs");
const rules = require("./rules.js");
const calculator = require("./app.js");

calculator.prepareData();

function firstRange(result) {
  return result.portRanges[0].start + "-" + result.portRanges[0].end;
}

{
  const result = calculator.calculate("v6plus", "240b:0010:0000:3400::");
  assert.equal(result.ipv4Address, "106.72.0.0");
  assert.equal(result.psid, 52);
  assert.equal(result.brAddress, "2404:9200:225:100::64");
  assert.equal(result.totalPorts, 240);
  assert.equal(firstRange(result), "4928-4943");
}

{
  const result = calculator.calculate("biglobe", "2404:7a82:0000:3400::");
  assert.equal(result.ipv4Address, "125.196.208.0");
  assert.equal(result.psid, 52);
  assert.equal(result.brAddress, "2001:260:700:1::1:275");
  assert.equal(result.totalPorts, 240);
  assert.equal(firstRange(result), "4928-4943");
}

{
  const result = calculator.calculate("ocn", "2400:4050:0000:0000::");
  assert.equal(result.ipv4Address, "153.240.0.0");
  assert.equal(result.psid, 0);
  assert.equal(result.brAddress, "2001:380:a120::9");
  assert.equal(result.totalPorts, 1008);
  assert.equal(firstRange(result), "1024-1039");
}

{
  const a = calculator.calculate(
    "v6plus",
    "240b:0010:0000:3400:1234:5678:9abc:def0"
  );
  const b = calculator.calculate("v6plus", "240b:0010:0000:3400::/64");
  assert.equal(a.ipv4Address, b.ipv4Address);
  assert.equal(a.psid, b.psid);
}

assert.throws(function () {
  calculator.calculate("v6plus", "not-an-ipv6");
});

assert.ok(Array.isArray(rules.services));
assert.ok(
  rules.services.every(function (service) {
    return service.bgp &&
      typeof service.bgp.originAsn === "string" &&
      Array.isArray(service.bgp.lookupUrls) &&
      Array.isArray(service.bgp.brAddresses);
  })
);
assert.ok(
  rules.services.every(function (service) {
    return !Object.prototype.hasOwnProperty.call(service, "updateSources") &&
      !Object.prototype.hasOwnProperty.call(service, "notes");
  })
);
assert.equal(
  rules.calculationSourceNote,
  "RIPEstat / BGP HE の情報は AS / BR の参考情報です。"
);
assert.equal(fs.existsSync("./prefixes.html"), false);
assert.equal(fs.existsSync("./style.css"), true);
assert.equal(fs.readFileSync("./index.html", "utf8").includes("style.css"), true);
assert.equal(
  fs.readFileSync("./rules.js", "utf8").includes("FC2 MAP-E Calculator"),
  false
);

console.log("All MAP-E tests passed.");
