/* The page work: remembering which browser this is, and stamping on the way out.
 *
 * The server that takes a note while the database is locked holds no key, so it
 * cannot tell a real note from one dropped into the spool by anything else able
 * to write the file. This is the other half of that: an enrolled browser keeps a
 * random key of its own and stamps every note it writes, and the *unlocked*
 * server checks the stamp against the copy inside the encrypted database.
 *
 * The bytes being stamped live in `stamp.js`, which is pure and tested against
 * the Python directly. This file only deals with the page.
 *
 * Nothing here is a security boundary on its own. A browser that cannot run it —
 * scripting off, storage blocked, an old engine — still writes notes; they are
 * simply held for review instead of filed, and the page says so at the time.
 */

(function () {
  "use strict";

  var DEVICE_ID = "counselog.device.id";
  var DEVICE_SECRET = "counselog.device.secret";
  var DEVICE_LABEL = "counselog.device.label";

  /* ── this browser's identity ─────────────────────────────────────────── */

  function readDevice() {
    try {
      var id = window.localStorage.getItem(DEVICE_ID);
      var secret = window.localStorage.getItem(DEVICE_SECRET);
      if (!id || !secret) return null;
      return { id: id, secret: secret,
               label: window.localStorage.getItem(DEVICE_LABEL) || id };
    } catch (error) {
      // Private browsing and blocked site data both throw here rather than
      // returning null. Not being enrolled is a supported state, so this is a
      // normal answer, not a failure.
      return null;
    }
  }

  function storeDevice(id, secret, label) {
    try {
      window.localStorage.setItem(DEVICE_ID, id);
      window.localStorage.setItem(DEVICE_SECRET, secret);
      window.localStorage.setItem(DEVICE_LABEL, label || id);
      return true;
    } catch (error) {
      return false;
    }
  }

  /* ── the capture form ────────────────────────────────────────────────── */

  function describeDevice(element, device) {
    if (!element) return;
    if (device) {
      element.textContent = "This browser writes as “" + device.label +
        "”. Notes written while locked are sealed until you sign in.";
      return;
    }
    element.textContent = element.dataset.unlocked === "1"
      ? "This browser is not enrolled, so notes it writes while locked will be " +
        "held for review. Enrol it on the Browsers page."
      : "This browser is not enrolled. It can still write; notes will be held " +
        "for review until you sign in and enrol it.";
  }

  function wireCaptureForm(form, stamping) {
    var state = document.getElementById("device-state");
    var device = readDevice();
    describeDevice(state, device);

    form.addEventListener("submit", function (event) {
      if (form.dataset.stamped === "yes") return;   // our own resubmit
      if (!device || !stamping || !window.crypto || !window.crypto.subtle) return;

      event.preventDefault();
      var text = stamping.normalizeNewlines(form.elements.text.value);
      var capturedAt = stamping.nowStamp();

      stamping.stamp(device.secret, text, capturedAt, device.id)
        .then(function (mac) {
          form.elements.device.value = device.id;
          form.elements.mac.value = mac;
          form.elements.captured_at.value = capturedAt;
        })
        .catch(function () {
          // Could not stamp. Send it anyway: a note held for review is far
          // better than a note the user believes they wrote and did not.
        })
        .then(function () {
          form.dataset.stamped = "yes";
          form.submit();
        });
    });
  }

  /* ── the enrolment page ──────────────────────────────────────────────── */

  function completeEnrolment(element) {
    var stored = storeDevice(element.dataset.deviceId,
                             element.dataset.deviceSecret,
                             element.dataset.deviceLabel);
    element.textContent = stored
      ? "This browser is now enrolled as “" + element.dataset.deviceLabel +
        "”. Notes it writes while locked will be filed, not held."
      : "This browser could not store its key, so the enrolment did not take. " +
        "Site data may be blocked here. You can revoke it below.";
    // The key was rendered into the page to get it here. Take it back out, so
    // it is not left sitting in the DOM.
    element.removeAttribute("data-device-secret");
  }

  document.addEventListener("DOMContentLoaded", function () {
    var enrolled = document.getElementById("enrolled");
    if (enrolled) completeEnrolment(enrolled);

    var form = document.getElementById("capture");
    if (form) wireCaptureForm(form, window.counselogStamp);
  });
})();
