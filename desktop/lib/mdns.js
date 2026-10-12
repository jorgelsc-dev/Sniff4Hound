"use strict";

const { isIP } = require("node:net");

function validHostname(value) {
  return typeof value === "string" && value.length <= 253 && value.endsWith(".local") &&
    value.split(".").every((label) => /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/.test(label));
}

/** Resolve the exact service announced by our child, without trusting TXT data as credentials. */
function verifyLocalService({ execFile, python, env, cwd, ready, prepared }) {
  if (!ready.mdns || !ready.mdns.enabled) {
    return prepared && prepared.mdnsHost
      ? Promise.reject(new Error("The runtime did not publish its mDNS service."))
      : Promise.resolve();
  }
  const expected = ready.mdns;
  if (!prepared || !validHostname(prepared.mdnsHost) || !isIP(prepared.address) ||
      ready.host !== prepared.mdnsHost || Number(ready.port) !== prepared.port ||
      expected.hostname !== ready.host || Number(expected.port) !== prepared.port || expected.service_type !== "_sniff4hound._tcp.local." ||
      typeof expected.service_name !== "string" || expected.service_name.length > 255 ||
      !Array.isArray(expected.addresses) || !expected.addresses.includes(prepared.address)) {
    return Promise.reject(new Error("The runtime's mDNS endpoint differs from the prepared local endpoint."));
  }
  return new Promise((resolve, reject) => {
    execFile(python, ["-m", "sniff4hound.mdns", "--service", expected.service_name,
      "--address", prepared.address, "--timeout", "3"],
    { env, cwd, timeout: 7000, encoding: "utf8", maxBuffer: 64 * 1024 }, (error, stdout) => {
      if (error) return reject(new Error("Could not resolve the local runtime through mDNS."));
      try {
        const found = JSON.parse(stdout.trim().split("\n").pop());
        if (found.service_name !== expected.service_name || found.service_type !== expected.service_type ||
            found.hostname !== prepared.mdnsHost || found.port !== prepared.port ||
            found.role !== "runtime" || found.scheme !== ready.protocol ||
            !Array.isArray(found.addresses) || !found.addresses.includes(prepared.address)) {
          throw new Error("mDNS returned a different runtime endpoint.");
        }
        resolve();
      } catch (parseError) {
        reject(parseError);
      }
    });
  });
}

module.exports = { validHostname, verifyLocalService };
