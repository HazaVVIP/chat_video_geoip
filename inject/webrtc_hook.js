// WebRTC ICE candidate interceptor — injected via Playwright add_init_script
(function () {
  "use strict";

  const OriginalRTC = window.RTCPeerConnection;

  function parseCandidate(candidateStr) {
    if (!candidateStr) return null;
    const m = candidateStr.match(
      /(\d{1,3}(?:\.\d{1,3}){3})\s+(\d+)\s+typ\s+(host|srflx|relay|prflx)/i
    );
    if (!m) return null;
    return { ip: m[1], port: parseInt(m[2], 10), typ: m[3].toLowerCase(), raw: candidateStr };
  }

  function report(data) {
    try {
      if (typeof window.reportIceCandidate === "function") {
        window.reportIceCandidate(data);
      }
    } catch (e) {
      /* binding not ready */
    }
  }

  function wrapPeerConnection(config, constraints) {
    const icePolicy = (config && config.iceTransportPolicy) || "all";
    if (icePolicy === "relay") {
      report({ warning: "relay_only_policy", timestamp: Date.now() });
    }

    const pc = new OriginalRTC(config, constraints);

    const origAddIceCandidate = pc.addIceCandidate.bind(pc);
    pc.addIceCandidate = function (candidate) {
      if (candidate && candidate.candidate) {
        const parsed = parseCandidate(candidate.candidate);
        if (parsed) {
          report({
            direction: "remote",
            candidate: candidate.candidate,
            ip: parsed.ip,
            port: parsed.port,
            typ: parsed.typ,
            timestamp: Date.now(),
          });
        }
      }
      return origAddIceCandidate(candidate);
    };

    pc.addEventListener("icecandidate", function (event) {
      if (event.candidate && event.candidate.candidate) {
        const parsed = parseCandidate(event.candidate.candidate);
        if (parsed) {
          report({
            direction: "local",
            candidate: event.candidate.candidate,
            ip: parsed.ip,
            port: parsed.port,
            typ: parsed.typ,
            timestamp: Date.now(),
          });
        }
      }
    });

    return pc;
  }

  wrapPeerConnection.prototype = OriginalRTC.prototype;
  Object.setPrototypeOf(wrapPeerConnection, OriginalRTC);
  window.RTCPeerConnection = wrapPeerConnection;
})();
