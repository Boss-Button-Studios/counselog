/* The bytes a browser stamps, and how it stamps them.
 *
 * This file is the whole of Counselog that has to agree with Python. It is kept
 * separate from `capture.js`, which does the page work, so that this half is
 * pure — no DOM, no storage, no page — and can be run straight under node and
 * compared with `core/spool.py` byte for byte. `tests/test_web_capture.py` does
 * exactly that; if the two ever drift, that test fails rather than a genuine
 * note being held for review with no explanation.
 *
 * Three agreements, all of them deliberate:
 *
 *   1. **The stamped bytes.** Four bytes of big-endian length in front of each
 *      UTF-8 field, in the order text, captured_at, device_id. Not JSON: two
 *      languages do not agree on JSON escaping of control characters and
 *      non-ASCII, and they do agree on this. Matches `spool.stamped_bytes`.
 *   2. **The timestamp.** `2026-09-02T10:11:12+00:00` — seconds, UTC, explicit
 *      offset, never the `Z` form, so times sort as text in one order
 *      everywhere. Matches `spool.utc_now` and `devices.CAPTURED_AT`.
 *   3. **Newlines.** A form submission rewrites them as CRLF in transit, so
 *      both sides normalise first. Matches `sanitize.normalize_newlines`.
 */

(function (global) {
  "use strict";

  function lengthPrefixed(bytes) {
    var out = new Uint8Array(4 + bytes.length);
    new DataView(out.buffer).setUint32(0, bytes.length, false); // big-endian
    out.set(bytes, 4);
    return out;
  }

  function stampedBytes(text, capturedAt, deviceId) {
    var encoder = new TextEncoder();
    var parts = [text, capturedAt, deviceId].map(function (part) {
      return lengthPrefixed(encoder.encode(part));
    });
    var total = parts.reduce(function (sum, part) { return sum + part.length; }, 0);
    var out = new Uint8Array(total);
    var at = 0;
    parts.forEach(function (part) { out.set(part, at); at += part.length; });
    return out;
  }

  function fromHex(hex) {
    var out = new Uint8Array(hex.length / 2);
    for (var i = 0; i < out.length; i++) {
      out[i] = parseInt(hex.substr(i * 2, 2), 16);
    }
    return out;
  }

  function toHex(bytes) {
    return Array.prototype.map.call(bytes, function (byte) {
      return byte.toString(16).padStart(2, "0");
    }).join("");
  }

  function stamp(secretHex, text, capturedAt, deviceId) {
    var subtle = global.crypto.subtle;
    return subtle.importKey(
      "raw", fromHex(secretHex), { name: "HMAC", hash: "SHA-256" }, false, ["sign"]
    ).then(function (key) {
      return subtle.sign("HMAC", key, stampedBytes(text, capturedAt, deviceId));
    }).then(function (signature) {
      return toHex(new Uint8Array(signature));
    });
  }

  /* Built by hand rather than trimmed out of toISOString, so the intent is
     visible rather than implied by a slice index. */
  function nowStamp(date) {
    var now = date || new Date();
    function two(value) { return String(value).padStart(2, "0"); }
    return now.getUTCFullYear() + "-" + two(now.getUTCMonth() + 1) + "-" +
           two(now.getUTCDate()) + "T" + two(now.getUTCHours()) + ":" +
           two(now.getUTCMinutes()) + ":" + two(now.getUTCSeconds()) + "+00:00";
  }

  function normalizeNewlines(text) {
    return text.replace(/\r\n/g, "\n").replace(/\r/g, "\n");
  }

  global.counselogStamp = {
    stampedBytes: stampedBytes,
    stamp: stamp,
    nowStamp: nowStamp,
    normalizeNewlines: normalizeNewlines,
    toHex: toHex,
    fromHex: fromHex,
  };
})(typeof window !== "undefined" ? window : globalThis);
