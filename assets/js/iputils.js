/* iputils.js — small IPv4 / CIDR helpers (no dependencies)
 * MIT License
 */
(function () {
  "use strict";

  function isByte(n) { return Number.isInteger(n) && n >= 0 && n <= 255; }

  function ipToInt(ip) {
    var parts = String(ip).trim().split(".");
    if (parts.length !== 4) return null;
    var out = 0;
    for (var i = 0; i < 4; i++) {
      if (!/^\d+$/.test(parts[i])) return null;
      var b = parseInt(parts[i], 10);
      if (!isByte(b)) return null;
      out = (out * 256) + b; // avoid 32-bit sign issues by using *256
    }
    return out;
  }

  function intToIp(n) {
    return [
      Math.floor(n / 16777216) % 256,
      Math.floor(n / 65536) % 256,
      Math.floor(n / 256) % 256,
      n % 256
    ].join(".");
  }

  // "10.10.10.0/24" -> { ip, prefix, base, broadcast, mask, count }
  function parseCidr(cidr) {
    var m = String(cidr).trim().match(/^(\d{1,3}(?:\.\d{1,3}){3})\s*\/\s*(\d{1,2})$/);
    if (!m) return null;
    var ipInt = ipToInt(m[1]);
    var prefix = parseInt(m[2], 10);
    if (ipInt === null || prefix < 0 || prefix > 32) return null;
    var hostBits = 32 - prefix;
    var size = Math.pow(2, hostBits);
    var maskInt = prefix === 0 ? 0 : (size === 4294967296 ? 4294967295 : (4294967296 - size));
    var base = ipInt - (ipInt % size); // network address
    return {
      ip: m[1],
      prefix: prefix,
      base: base,
      broadcast: base + size - 1,
      mask: maskInt,
      count: size
    };
  }

  function isValidIp(ip) { return ipToInt(ip) !== null; }

  function isValidCidr(cidr) { return parseCidr(cidr) !== null; }

  // Is `ip` inside `cidr` (network/usable range, excludes nothing here)
  function ipInCidr(ip, cidr) {
    var n = parseCidr(cidr);
    var v = ipToInt(ip);
    if (!n || v === null) return false;
    return v >= n.base && v <= n.broadcast;
  }

  window.IPUtils = {
    ipToInt: ipToInt,
    intToIp: intToIp,
    parseCidr: parseCidr,
    isValidIp: isValidIp,
    isValidCidr: isValidCidr,
    ipInCidr: ipInCidr
  };
})();
