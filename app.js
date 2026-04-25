(function (global) {
  "use strict";

  const FULL_MASK_128 = (1n << 128n) - 1n;
  const DATA = global.MAPE_RULES_DATA ||
    (typeof module !== "undefined" && module.exports ? require("./rules.js") : null);

  function buildPrefixMask(prefixLength) {
    if (prefixLength < 0 || prefixLength > 128) {
      throw new Error("prefix length が不正です。");
    }
    if (prefixLength === 0) {
      return 0n;
    }
    return ((1n << BigInt(prefixLength)) - 1n) << BigInt(128 - prefixLength);
  }

  function maskIpv6(value, prefixLength) {
    return value & buildPrefixMask(prefixLength);
  }

  function extractBits(value, startBit, length) {
    if (length === 0) {
      return 0n;
    }
    const shift = BigInt(128 - (startBit + length));
    const mask = (1n << BigInt(length)) - 1n;
    return (value >> shift) & mask;
  }

  function normalizeIpv6Input(rawInput) {
    const trimmed = String(rawInput || "").trim();
    if (!trimmed) {
      throw new Error("IPv6 アドレスを入力してください。");
    }

    const parts = trimmed.split("/");
    if (parts.length > 2) {
      throw new Error("CIDR 表記が不正です。");
    }

    const addressPart = parts[0].trim();
    const prefixLength = parts.length === 2 ? parsePrefixLength(parts[1]) : null;

    if (addressPart.includes(".")) {
      throw new Error("IPv4 埋め込み形式の IPv6 は未対応です。");
    }
    if (addressPart.includes("%")) {
      throw new Error("ゾーン ID 付き IPv6 は未対応です。");
    }

    const hextets = expandIpv6(addressPart);
    const addressBigInt = hextetsToBigInt(hextets);

    return {
      rawInput: trimmed,
      prefixLength,
      hextets,
      addressBigInt,
      compressedAddress: compressIpv6(hextets),
    };
  }

  function parsePrefixLength(rawPrefixLength) {
    const value = Number(rawPrefixLength.trim());
    if (!Number.isInteger(value) || value < 0 || value > 128) {
      throw new Error("CIDR の長さが不正です。");
    }
    return value;
  }

  function expandIpv6(address) {
    const lower = address.toLowerCase();
    if (!/^[0-9a-f:]+$/.test(lower)) {
      throw new Error("IPv6 アドレスの形式が不正です。");
    }

    const doubleColonCount = lower.split("::").length - 1;
    if (doubleColonCount > 1) {
      throw new Error("IPv6 アドレスの形式が不正です。");
    }

    let left = [];
    let right = [];

    if (lower.includes("::")) {
      const halves = lower.split("::");
      left = halves[0] ? halves[0].split(":") : [];
      right = halves[1] ? halves[1].split(":") : [];
    } else {
      left = lower.split(":");
    }

    const explicitLength = left.filter(Boolean).length + right.filter(Boolean).length;
    if ((!lower.includes("::") && explicitLength !== 8) || explicitLength > 8) {
      throw new Error("IPv6 アドレスの形式が不正です。");
    }

    const fill = lower.includes("::") ? new Array(8 - explicitLength).fill("0") : [];
    const merged = left.concat(fill, right).map(function (part) {
      if (!part) {
        return 0;
      }
      if (!/^[0-9a-f]{1,4}$/.test(part)) {
        throw new Error("IPv6 アドレスの形式が不正です。");
      }
      return parseInt(part, 16);
    });

    if (merged.length !== 8) {
      throw new Error("IPv6 アドレスの形式が不正です。");
    }

    return merged;
  }

  function hextetsToBigInt(hextets) {
    return hextets.reduce(function (value, hextet) {
      return (value << 16n) | BigInt(hextet);
    }, 0n);
  }

  function bigIntToHextets(value) {
    const result = [];
    for (let index = 0; index < 8; index += 1) {
      const shift = BigInt((7 - index) * 16);
      result.push(Number((value >> shift) & 0xffffn));
    }
    return result;
  }

  function compressIpv6(hextets) {
    const parts = hextets.map(function (hextet) {
      return hextet.toString(16);
    });

    let bestStart = -1;
    let bestLength = 0;
    let currentStart = -1;
    let currentLength = 0;

    for (let index = 0; index <= parts.length; index += 1) {
      if (index < parts.length && parts[index] === "0") {
        if (currentStart === -1) {
          currentStart = index;
        }
        currentLength += 1;
      } else {
        if (currentLength > bestLength && currentLength > 1) {
          bestStart = currentStart;
          bestLength = currentLength;
        }
        currentStart = -1;
        currentLength = 0;
      }
    }

    if (bestStart === -1) {
      return parts.join(":");
    }

    const left = parts.slice(0, bestStart).join(":");
    const right = parts.slice(bestStart + bestLength).join(":");

    if (!left && !right) {
      return "::";
    }
    if (!left) {
      return "::" + right;
    }
    if (!right) {
      return left + "::";
    }
    return left + "::" + right;
  }

  function ipv4StringToNumber(ipv4Address) {
    const octets = ipv4Address.split(".").map(function (part) {
      return Number(part);
    });
    if (octets.length !== 4 || octets.some(function (part) {
      return !Number.isInteger(part) || part < 0 || part > 255;
    })) {
      throw new Error("IPv4 ルールの形式が不正です。");
    }
    return (((octets[0] << 24) >>> 0) |
      (octets[1] << 16) |
      (octets[2] << 8) |
      octets[3]) >>> 0;
  }

  function ipv4NumberToString(ipv4Number) {
    return [
      (ipv4Number >>> 24) & 255,
      (ipv4Number >>> 16) & 255,
      (ipv4Number >>> 8) & 255,
      ipv4Number & 255,
    ].join(".");
  }

  function buildPortRanges(psid, psidLength, offset) {
    const ranges = [];
    const blockSize = 1 << (16 - offset - psidLength);
    const maxA = (1 << offset) - 1;
    for (let a = 1; a <= maxA; a += 1) {
      const start = (a << (16 - offset)) | (psid << (16 - offset - psidLength));
      ranges.push({
        start,
        end: start + blockSize - 1,
      });
    }
    return ranges;
  }

  function buildLegacyCeAddress(inputHextets, ipv4Octets, psid) {
    const hextets = inputHextets.slice(0, 4);
    hextets[3] &= 0xff00;
    const ceHextets = hextets.concat([
      ipv4Octets[0],
      (ipv4Octets[1] << 8) | ipv4Octets[2],
      ipv4Octets[3] << 8,
      psid << 8,
    ]);
    return compressIpv6(ceHextets);
  }

  function prepareData() {
    DATA.services.forEach(function (service) {
      service.rules.forEach(function (rule) {
        rule.ruleIpv6PrefixBigInt = hextetsToBigInt(expandIpv6(rule.ruleIpv6Prefix));
        rule.ruleIpv4PrefixNumber = ipv4StringToNumber(rule.ruleIpv4Prefix);
        rule.psidLength = rule.eaLength - (32 - rule.ruleIpv4PrefixLength);
        rule.totalPorts = ((1 << rule.psidOffset) - 1) *
          (1 << (16 - rule.psidOffset - rule.psidLength));
      });
      service.rules.sort(function (left, right) {
        return right.ruleIpv6PrefixLength - left.ruleIpv6PrefixLength;
      });
    });
    return DATA;
  }

  function findService(serviceId) {
    const service = DATA.services.find(function (candidate) {
      return candidate.id === serviceId;
    });
    if (!service) {
      throw new Error("サービスを選択してください。");
    }
    return service;
  }

  function findMatchingRule(service, addressBigInt) {
    return service.rules.find(function (rule) {
      return maskIpv6(addressBigInt, rule.ruleIpv6PrefixLength) === rule.ruleIpv6PrefixBigInt;
    }) || null;
  }

  function calculate(serviceId, rawInput) {
    const service = findService(serviceId);
    const parsed = normalizeIpv6Input(rawInput);
    const rule = findMatchingRule(service, parsed.addressBigInt);

    if (!rule) {
      throw new Error("選択したサービスに対応する MAP-E ルールが見つかりません。");
    }

    const eaBits = extractBits(
      parsed.addressBigInt,
      rule.ruleIpv6PrefixLength,
      rule.eaLength
    );
    const psidMask = rule.psidLength === 0 ? 0n : (1n << BigInt(rule.psidLength)) - 1n;
    const psid = rule.psidLength === 0 ? 0 : Number(eaBits & psidMask);
    const ipv4Suffix = rule.psidLength === 0 ? eaBits : (eaBits >> BigInt(rule.psidLength));
    const ipv4Number = (rule.ruleIpv4PrefixNumber | Number(ipv4Suffix)) >>> 0;
    const ipv4Address = ipv4NumberToString(ipv4Number);
    const ipv4Octets = ipv4Address.split(".").map(function (part) {
      return Number(part);
    });
    const portRanges = buildPortRanges(psid, rule.psidLength, rule.psidOffset);
    const prefix56Address = maskIpv6(parsed.addressBigInt, 56);
    const ignoredBits = parsed.addressBigInt & (FULL_MASK_128 ^ buildPrefixMask(56));
    const notes = [];

    if (ignoredBits !== 0n) {
      notes.push("入力アドレスの /56 より下位ビットは計算に使わず、上位 56 ビットを使用しました。");
    }
    if (parsed.prefixLength !== null && parsed.prefixLength !== 56 && parsed.prefixLength !== 64) {
      notes.push("CIDR の長さは受け付けましたが、計算は IPv6 値に埋め込まれた MAP-E ビットから求めています。");
    }
    if (rule.region) {
      notes.push("BIGLOBE の BR は " + rule.region + " 系のルールを使用しました。");
    }

    return {
      service,
      parsed,
      rule,
      ipv4Address,
      psid,
      ceAddress: buildLegacyCeAddress(parsed.hextets, ipv4Octets, psid),
      brAddress: rule.brAddress,
      portRanges,
      totalPorts: rule.totalPorts,
      prefix56: compressIpv6(bigIntToHextets(prefix56Address)),
      notes,
    };
  }

  function formatPortRanges(ranges) {
    return ranges.map(function (range) {
      return range.start + "-" + range.end;
    }).join("\n");
  }

  function setStatus(message, state) {
    const status = document.getElementById("status");
    status.textContent = message;
    status.dataset.state = state || "";
  }

  function clearStatus() {
    setStatus("", "");
  }

  function escapeHtml(text) {
    return String(text)
      .replaceAll("&", "&amp;")
      .replaceAll("<", "&lt;")
      .replaceAll(">", "&gt;");
  }

  function renderBrList(brAddresses) {
    return brAddresses.map(function (br) {
      return `${escapeHtml(br.label)}: ${escapeHtml(br.address)}`;
    }).join("<br>");
  }

  function renderIspMatrix() {
    const body = document.getElementById("isp-matrix-body");
    body.innerHTML = DATA.services.map(function (service) {
      return `
        <tr>
          <td>${escapeHtml(service.name)}</td>
          <td>${escapeHtml(service.vne)}</td>
          <td>${escapeHtml(service.supportedIsps.join(" / "))}</td>
        </tr>
      `;
    }).join("");
  }

  function renderServiceReferenceTable() {
    const body = document.getElementById("service-reference-body");
    body.innerHTML = DATA.services.map(function (service) {
      const bgpCell = [
        `${escapeHtml(service.bgp.originAsn)} (${escapeHtml(service.bgp.originHolder)})`,
        `代表 BGP プレフィックス: ${escapeHtml(service.bgp.representativeBgpPrefix)}`,
        `BR 収容プレフィックス: ${escapeHtml(service.bgp.brOriginPrefix)}`,
      ].join("<br>");
      return `
        <tr>
          <td>${escapeHtml(service.name)}</td>
          <td>${escapeHtml(service.vne)}</td>
          <td>${renderBrList(service.bgp.brAddresses)}</td>
          <td>${escapeHtml(String(service.portCount))}</td>
          <td>${escapeHtml(String(service.sharedUsers))}</td>
          <td>${escapeHtml(service.addressRangeSummary)}</td>
          <td>${bgpCell}</td>
        </tr>
      `;
    }).join("");
  }

  function renderAsLinks() {
    const target = document.getElementById("as-links-list");
    target.innerHTML = DATA.services.map(function (service) {
      const urls = (service.bgp.lookupUrls || [])
        .filter(function (link) {
          return link.label.includes("AS");
        })
        .map(function (link) {
          const escapedUrl = escapeHtml(link.url);
          return `<a href="${escapedUrl}" target="_blank" rel="noreferrer">${escapedUrl}</a>`;
        })
        .join("<br>");

      return `
        <p>
          ${escapeHtml(service.name)} (${escapeHtml(service.bgp.originAsn)})<br>
          ${urls}
        </p>
      `;
    }).join("");
  }

  function renderGeneratedNotes() {
    const target = document.getElementById("calculation-source-note");
    const date = DATA.generatedAt ? `最終生成: ${new Date(DATA.generatedAt).toLocaleString("ja-JP")}` : "";
    target.textContent = [DATA.calculationSourceNote, date].filter(Boolean).join(" ");
  }

  function clearResultDisplay() {
    document.getElementById("result-ipv4").textContent = "-";
    document.getElementById("result-psid").textContent = "-";
    document.getElementById("result-ce").textContent = "-";
    document.getElementById("result-br").textContent = "-";
    document.getElementById("result-rule-ipv6").textContent = "-";
    document.getElementById("result-rule-ipv4").textContent = "-";
    document.getElementById("result-ea-psid").textContent = "-";
    document.getElementById("result-offset-ports").textContent = "-";
    document.getElementById("result-prefix56").textContent = "-";
    document.getElementById("result-source-date").textContent = "-";
    document.getElementById("result-port-ranges").value = "";
    document.getElementById("result-v6plus-dns").textContent = "";
    document.getElementById("result-v6plus-domain").textContent = "";
    document.getElementById("result-v6plus-sntp").textContent = "";
    document.getElementById("v6plus-extra-section").hidden = true;
    document.getElementById("result-notes").textContent = "";
  }

  function renderCalculation(result) {
    document.getElementById("result-ipv4").textContent = result.ipv4Address;
    document.getElementById("result-psid").textContent = String(result.psid);
    document.getElementById("result-ce").textContent = result.ceAddress;
    document.getElementById("result-br").textContent = result.brAddress;
    document.getElementById("result-rule-ipv6").textContent =
      result.rule.ruleIpv6Prefix + "/" + result.rule.ruleIpv6PrefixLength;
    document.getElementById("result-rule-ipv4").textContent =
      result.rule.ruleIpv4Prefix + "/" + result.rule.ruleIpv4PrefixLength;
    document.getElementById("result-ea-psid").textContent =
      result.rule.eaLength + " / " + result.rule.psidLength;
    document.getElementById("result-offset-ports").textContent =
      result.rule.psidOffset + " / " + result.totalPorts;
    document.getElementById("result-prefix56").textContent = result.prefix56 + "/56";
    document.getElementById("result-source-date").textContent = result.rule.sourceDate;
    document.getElementById("result-port-ranges").value = formatPortRanges(result.portRanges);

    const notes = document.getElementById("result-notes");
    notes.textContent = "";
    result.notes.forEach(function (note) {
      const item = document.createElement("li");
      item.textContent = note;
      notes.appendChild(item);
    });

    const v6plusSection = document.getElementById("v6plus-extra-section");
    if (result.service.id === "v6plus" && result.service.v6plusDetails) {
      v6plusSection.hidden = false;
      document.getElementById("result-v6plus-dns").textContent =
        result.service.v6plusDetails.dns.join(", ");
      document.getElementById("result-v6plus-domain").textContent =
        result.service.v6plusDetails.domain.join(", ");
      document.getElementById("result-v6plus-sntp").textContent =
        result.service.v6plusDetails.sntp.join(", ");
    } else {
      v6plusSection.hidden = true;
      document.getElementById("result-v6plus-dns").textContent = "";
      document.getElementById("result-v6plus-domain").textContent = "";
      document.getElementById("result-v6plus-sntp").textContent = "";
    }
  }

  function resetForm() {
    document.getElementById("calculator-form").reset();
    clearResultDisplay();
    clearStatus();
  }

  function init() {
    prepareData();
    clearResultDisplay();
    renderIspMatrix();
    renderServiceReferenceTable();
    renderAsLinks();
    renderGeneratedNotes();

    const serviceSelect = document.getElementById("service");
    DATA.services.forEach(function (service) {
      const option = document.createElement("option");
      option.value = service.id;
      option.textContent = service.name;
      serviceSelect.appendChild(option);
    });

    document.getElementById("calculator-form").addEventListener("submit", function (event) {
      event.preventDefault();
      const serviceId = serviceSelect.value;
      const rawInput = document.getElementById("ipv6-input").value;

      try {
        const result = calculate(serviceId, rawInput);
        renderCalculation(result);
        setStatus("計算しました。", "success");
      } catch (error) {
        clearResultDisplay();
        setStatus(error.message, "error");
      }
    });

    document.getElementById("reset-button").addEventListener("click", resetForm);
  }

  if (typeof document !== "undefined") {
    document.addEventListener("DOMContentLoaded", init);
  }

  const api = {
    calculate,
    normalizeIpv6Input,
    compressIpv6,
    expandIpv6,
    buildPortRanges,
    prepareData,
  };

  global.MapeCalculator = api;

  if (typeof module !== "undefined" && module.exports) {
    module.exports = api;
  }
})(typeof window !== "undefined" ? window : globalThis);
