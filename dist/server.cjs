var __create = Object.create;
var __defProp = Object.defineProperty;
var __getOwnPropDesc = Object.getOwnPropertyDescriptor;
var __getOwnPropNames = Object.getOwnPropertyNames;
var __getProtoOf = Object.getPrototypeOf;
var __hasOwnProp = Object.prototype.hasOwnProperty;
var __copyProps = (to, from, except, desc) => {
  if (from && typeof from === "object" || typeof from === "function") {
    for (let key of __getOwnPropNames(from))
      if (!__hasOwnProp.call(to, key) && key !== except)
        __defProp(to, key, { get: () => from[key], enumerable: !(desc = __getOwnPropDesc(from, key)) || desc.enumerable });
  }
  return to;
};
var __toESM = (mod, isNodeMode, target) => (target = mod != null ? __create(__getProtoOf(mod)) : {}, __copyProps(
  // If the importer is in node compatibility mode or this is not an ESM
  // file that has been converted to a CommonJS file using a Babel-
  // compatible transform (i.e. "__esModule" has not been set), then set
  // "default" to the CommonJS "module.exports" for node compatibility.
  isNodeMode || !mod || !mod.__esModule ? __defProp(target, "default", { value: mod, enumerable: true }) : target,
  mod
));

// server.ts
var import_express = __toESM(require("express"), 1);
var import_path = __toESM(require("path"), 1);
var import_vite = require("vite");
var import_net = __toESM(require("net"), 1);
var import_dns = __toESM(require("dns"), 1);
var import_util = require("util");
var import_cors = __toESM(require("cors"), 1);
var resolveMx = (0, import_util.promisify)(import_dns.default.resolveMx);
var resolveTxt = (0, import_util.promisify)(import_dns.default.resolveTxt);
var app = (0, import_express.default)();
var PORT = 3e3;
app.use((0, import_cors.default)());
app.use(import_express.default.json());
var checkPort = (port, host, timeout = 2e3) => {
  return new Promise((resolve) => {
    const socket = new import_net.default.Socket();
    let status = false;
    socket.on("connect", () => {
      status = true;
      socket.destroy();
    });
    socket.setTimeout(timeout);
    socket.on("timeout", () => {
      socket.destroy();
    });
    socket.on("error", () => {
      socket.destroy();
    });
    socket.on("close", () => {
      resolve(status);
    });
    socket.connect(port, host);
  });
};
app.get("/api/net/portscan", async (req, res) => {
  const { target, ports } = req.query;
  if (!target || typeof target !== "string") {
    return res.status(400).json({ error: "Target is required" });
  }
  const defaultPorts = [
    { port: 21, service: "FTP" },
    { port: 22, service: "SSH" },
    { port: 23, service: "Telnet" },
    { port: 25, service: "SMTP" },
    { port: 53, service: "DNS" },
    { port: 80, service: "HTTP" },
    { port: 110, service: "POP3" },
    { port: 143, service: "IMAP" },
    { port: 443, service: "HTTPS" },
    { port: 445, service: "SMB" },
    { port: 3306, service: "MySQL" },
    { port: 8080, service: "HTTP-Proxy" }
  ];
  let portsToScan = defaultPorts;
  if (ports && typeof ports === "string") {
    portsToScan = ports.split(",").map((p) => ({ port: parseInt(p, 10), service: "Unknown" })).filter((p) => !isNaN(p.port));
  }
  try {
    const results = await Promise.all(
      portsToScan.map(async (p) => {
        const isOpen = await checkPort(p.port, target, 2500);
        return { ...p, isOpen };
      })
    );
    res.json({ results });
  } catch (error) {
    res.status(500).json({ error: "Failed to scan ports" });
  }
});
app.get("/api/net/blacklist", async (req, res) => {
  const { target } = req.query;
  if (!target || typeof target !== "string") {
    return res.status(400).json({ error: "Target is required" });
  }
  try {
    const isIp = /^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$/.test(target);
    let ip = target;
    if (!isIp) {
      const lookRes = await import_dns.default.promises.lookup(target);
      ip = lookRes.address;
    }
    const reverseIp = ip.split(".").reverse().join(".");
    const lists = ["zen.spamhaus.org", "b.barracudacentral.org", "bl.spamcop.net"];
    const results = await Promise.all(lists.map(async (list) => {
      try {
        await import_dns.default.promises.resolve(`${reverseIp}.${list}`);
        return { list, clean: false };
      } catch (e) {
        return { list, clean: true };
      }
    }));
    res.json({ ip, results });
  } catch (e) {
    res.status(500).json({ error: "DNS resolution failed" });
  }
});
app.get("/api/net/dns", async (req, res) => {
  const { target, server, reverse } = req.query;
  if (!target || typeof target !== "string") return res.status(400).json({ error: "Target required" });
  try {
    const resolver = new import_dns.default.promises.Resolver();
    if (server && typeof server === "string" && server !== "default") {
      try {
        resolver.setServers([server]);
      } catch (e) {
      }
    }
    let output = "";
    output += `; <<>> PWN//NET DNS Lookup <<>> ${target}
`;
    if (server && server !== "default") output += `; Server: ${server}
`;
    output += `
`;
    if (reverse === "true") {
      try {
        const hostnames = await resolver.reverse(target);
        output += ";; REVERSE RECORDS:\n" + hostnames.map((r) => `${target}.	IN	PTR	${r}`).join("\n") + "\n\n";
      } catch (e) {
        output += `;; REVERSE LOOKUP FAILED: ${e.message}
`;
      }
      return res.json({ result: output || "No Reverse DNS records found." });
    }
    try {
      const ns = await resolver.resolveNs(target);
      output += ";; NS RECORDS:\n" + ns.map((r) => `${target}.	IN	NS	${r}`).join("\n") + "\n\n";
    } catch (e) {
    }
    try {
      const a = await resolver.resolve4(target);
      output += ";; A RECORDS:\n" + a.map((r) => `${target}.	IN	A	${r}`).join("\n") + "\n\n";
    } catch (e) {
    }
    try {
      const mx = await resolver.resolveMx(target);
      output += ";; MX RECORDS:\n" + mx.map((r) => `${target}.	IN	MX	${r.priority} ${r.exchange}`).join("\n") + "\n\n";
    } catch (e) {
    }
    try {
      const txt = await resolver.resolveTxt(target);
      output += ";; TXT RECORDS:\n" + txt.map((r) => `${target}.	IN	TXT	"${r.join("")}"`).join("\n") + "\n";
    } catch (e) {
    }
    res.json({ result: output || "No DNS records found." });
  } catch (e) {
    res.json({ result: "No DNS records found or lookup failed." });
  }
});
app.get("/api/net/whois", async (req, res) => {
  const { target } = req.query;
  if (!target || typeof target !== "string") return res.status(400).json({ error: "Target required" });
  try {
    const socket = new import_net.default.Socket();
    let data = "";
    socket.setTimeout(5e3);
    socket.connect(43, "whois.iana.org", () => {
      socket.write(target + "\r\n");
    });
    socket.on("data", (chunk) => data += chunk);
    socket.on("end", () => res.json({ result: data }));
    socket.on("error", () => res.json({ result: "Whois lookup failed (connection error)." }));
    socket.on("timeout", () => {
      socket.destroy();
      res.json({ result: "Whois lookup timed out." });
    });
  } catch (e) {
    res.json({ result: "Failed to perform whois" });
  }
});
app.get("/api/net/spider", async (req, res) => {
  const { target } = req.query;
  if (!target || typeof target !== "string") {
    return res.status(400).json({ error: "Target is required" });
  }
  let baseUrl = target.replace(/\/$/, "");
  if (!baseUrl.startsWith("http://") && !baseUrl.startsWith("https://")) baseUrl = "https://" + baseUrl;
  try {
    const crawled = /* @__PURE__ */ new Set();
    const queue = [baseUrl];
    const allLinks = /* @__PURE__ */ new Set();
    const startTime = Date.now();
    const MAX_PAGES = 5;
    while (queue.length > 0 && crawled.size < MAX_PAGES) {
      if (Date.now() - startTime > 15e3) break;
      const currentUrl = queue.shift();
      if (crawled.has(currentUrl)) continue;
      crawled.add(currentUrl);
      try {
        const controller = new AbortController();
        const timeoutId = setTimeout(() => controller.abort(), 6e3);
        let fetchUrl = currentUrl;
        let response;
        try {
          response = await fetch(fetchUrl, {
            signal: controller.signal,
            headers: { "User-Agent": "Mozilla/5.0 (compatible; PWNNET-Spider/1.0)" }
          });
        } catch (e) {
          if (currentUrl === baseUrl && currentUrl.startsWith("https://")) {
            fetchUrl = currentUrl.replace("https://", "http://");
            const fallbackController = new AbortController();
            const fallbackTimeout = setTimeout(() => fallbackController.abort(), 6e3);
            try {
              response = await fetch(fetchUrl, { signal: fallbackController.signal, headers: { "User-Agent": "Mozilla/5.0 (compatible; PWNNET-Spider/1.0)" } });
            } catch (fallbackErr) {
              clearTimeout(fallbackTimeout);
              continue;
            }
            clearTimeout(fallbackTimeout);
          } else {
            continue;
          }
        }
        clearTimeout(timeoutId);
        if (!response || !response.ok) continue;
        const contentType = response.headers.get("content-type") || "";
        if (!contentType.includes("text/html")) {
          allLinks.add(fetchUrl);
          continue;
        }
        const text = await response.text();
        const urlRegex = /(?:href|src|action)\s*=\s*(?:["'])(.*?)(?:["'])/gi;
        let match;
        while ((match = urlRegex.exec(text)) !== null) {
          let l = match[1].trim();
          if (!l || l.startsWith("javascript:") || l.startsWith("mailto:") || l.startsWith("tel:") || l.startsWith("#") || l.startsWith("data:")) continue;
          let absoluteUrl = "";
          try {
            absoluteUrl = new URL(l, fetchUrl).href;
          } catch (e) {
            continue;
          }
          allLinks.add(absoluteUrl);
          try {
            const parsedUrl = new URL(absoluteUrl);
            const baseHost = new URL(baseUrl).host;
            if (parsedUrl.host === baseHost && !crawled.has(absoluteUrl) && !queue.includes(absoluteUrl)) {
              if (!absoluteUrl.match(/\.(png|jpg|jpeg|gif|css|js|json|xml|pdf|zip|mp4|svg|ico|woff|woff2|ttf|eot)$/i)) {
                queue.push(absoluteUrl);
              }
            }
          } catch (e) {
          }
        }
      } catch (e) {
        continue;
      }
    }
    const uniqueLinks = Array.from(allLinks);
    const internalLinks = uniqueLinks.filter((l) => {
      try {
        return new URL(l).host === new URL(baseUrl).host;
      } catch (e) {
        return false;
      }
    });
    const externalLinks = uniqueLinks.filter((l) => !internalLinks.includes(l));
    let result = `Spider Results for ${baseUrl} (Crawled ${crawled.size} pages):
`;
    const MAX_RESULTS = 100;
    result += `
[--- INTERNAL LINKS (${internalLinks.length}) ---]
`;
    result += internalLinks.slice(0, MAX_RESULTS).join("\n") || "None found.";
    if (internalLinks.length > MAX_RESULTS) result += `
...and ${internalLinks.length - MAX_RESULTS} more.`;
    result += `

[--- EXTERNAL LINKS (${externalLinks.length}) ---]
`;
    result += externalLinks.slice(0, MAX_RESULTS).join("\n") || "None found.";
    if (externalLinks.length > MAX_RESULTS) result += `
...and ${externalLinks.length - MAX_RESULTS} more.`;
    if (uniqueLinks.length === 0) result += "\nNo links found.";
    res.json({ result: result.trim(), links: uniqueLinks.slice(0, 500) });
  } catch (e) {
    res.json({ result: "Failed to crawl target. Target may be blocking requests or offline.", links: [] });
  }
});
app.get("/api/net/http", async (req, res) => {
  const { target } = req.query;
  if (!target || typeof target !== "string") {
    return res.status(400).json({ error: "Target is required" });
  }
  let baseUrl = target.replace(/\/$/, "");
  if (!baseUrl.startsWith("http://") && !baseUrl.startsWith("https://")) baseUrl = "http://" + baseUrl;
  try {
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), 5e3);
    const response = await fetch(baseUrl, { method: "HEAD", signal: controller.signal });
    clearTimeout(timeoutId);
    let result = `HTTP/${response.status === 200 ? "1.1" : "1.1"} ${response.status} ${response.statusText}
`;
    for (const [key, value] of response.headers.entries()) {
      result += `${key.replace(/(^\w|-\w)/g, (c) => c.toUpperCase())}: ${value}
`;
    }
    res.json({ result });
  } catch (e) {
    res.json({ result: "Failed to fetch HTTP headers. Target may be offline." });
  }
});
app.get("/api/net/subdomains", async (req, res) => {
  const { target } = req.query;
  if (!target || typeof target !== "string") return res.status(400).json({ error: "Target is required" });
  let host = target.replace(/^https?:\/\//, "").split("/")[0];
  try {
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), 1e4);
    const response = await fetch(`https://crt.sh/?q=%25.${host}&output=json`, { signal: controller.signal });
    clearTimeout(timeoutId);
    if (response.ok) {
      const data = await response.json();
      const subdomains = /* @__PURE__ */ new Set();
      data.forEach((entry) => {
        if (entry.name_value) {
          const names = entry.name_value.split("\n");
          names.forEach((n) => {
            if (n.endsWith(`.${host}`) && !n.includes("*")) {
              subdomains.add(n.toLowerCase());
            }
          });
        }
      });
      res.json({ result: Array.from(subdomains).sort() });
    } else {
      res.status(500).json({ error: `crt.sh API returned status ${response.status}` });
    }
  } catch (error) {
    res.status(500).json({ error: "Failed to access crt.sh API (timeout or network error)" });
  }
});
app.get("/api/net/mail", async (req, res) => {
  const { target } = req.query;
  if (!target || typeof target !== "string") {
    return res.status(400).json({ error: "Target is required" });
  }
  try {
    let mxRecords = [];
    try {
      mxRecords = await resolveMx(target);
      mxRecords.sort((a, b) => a.priority - b.priority);
    } catch (e) {
    }
    let txtRecordsStr = [];
    try {
      const txtRecords = await resolveTxt(target);
      txtRecordsStr = txtRecords.map((t) => t.join(""));
    } catch (e) {
    }
    const spf = txtRecordsStr.filter((r) => r.startsWith("v=spf1"));
    let dmarc = [];
    try {
      const dmarcTxt = await resolveTxt(`_dmarc.${target}`);
      dmarc = dmarcTxt.map((t) => t.join("")).filter((r) => r.startsWith("v=DMARC1"));
    } catch (e) {
    }
    res.json({ mx: mxRecords, spf, dmarc });
  } catch (error) {
    res.status(500).json({ error: "Failed DNS lookup" });
  }
});
app.get("/api/net/mac", async (req, res) => {
  const { address } = req.query;
  if (!address || typeof address !== "string") {
    return res.status(400).json({ error: "MAC Address is required" });
  }
  try {
    const response = await fetch(`https://api.macvendors.com/${encodeURIComponent(address)}`);
    if (response.ok) {
      const vendor = await response.text();
      res.json({ vendor });
    } else {
      res.status(404).json({ error: "Vendor not found for this MAC address" });
    }
  } catch (error) {
    res.status(500).json({ error: "Failed to lookup MAC" });
  }
});
app.get("/api/net/traceroute", async (req, res) => {
  const { target } = req.query;
  if (!target || typeof target !== "string") {
    return res.status(400).json({ error: "Target is required" });
  }
  let hostTarget = target;
  if (target.startsWith("http")) hostTarget = target.replace(/^https?:\/\//, "").split("/")[0];
  try {
    const response = await fetch(`https://api.hackertarget.com/mtr/?q=${encodeURIComponent(hostTarget)}`);
    if (response.ok) {
      const data = await response.text();
      if (data.includes("error") || data.includes("API count exceeded")) {
        const start = Date.now();
        try {
          const rc = new AbortController();
          const rt = setTimeout(() => rc.abort(), 4e3);
          await fetch(`http://${hostTarget}`, { signal: rc.signal }).catch(() => fetch(`https://${hostTarget}`, { signal: rc.signal }));
          clearTimeout(rt);
          const time = Date.now() - start;
          res.json({ result: `MTR API limit hit. Fallback HTTP/HTTPS test:

Connected to ${hostTarget}
Time: ${time}ms
Status: REACHABLE

(Full MTR trace disabled in restricted environment)` });
        } catch (e) {
          res.json({ result: `MTR API limit hit. Fallback HTTP/HTTPS test:

Could not reach ${hostTarget} on web ports.
Status: UNREACHABLE or FILTERED` });
        }
      } else {
        res.json({ result: data });
      }
    } else {
      res.status(500).json({ error: "Failed to perform traceroute" });
    }
  } catch (error) {
    res.status(500).json({ error: "Failed to perform traceroute" });
  }
});
app.get("/api/net/netscan", async (req, res) => {
  const { target } = req.query;
  if (!target || typeof target !== "string") {
    return res.status(400).json({ error: "Target is required" });
  }
  try {
    let scanIp = target;
    if (!/^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$/.test(target)) {
      try {
        const dnsRes = await resolveTxt(target);
      } catch (e) {
      }
      const lookRes = await import_dns.default.promises.lookup(target);
      scanIp = lookRes.address;
    }
    const parts = scanIp.split(".");
    if (parts.length === 4) {
      const base = `${parts[0]}.${parts[1]}.${parts[2]}`;
      const results = [];
      const BATCH_SIZE = 50;
      for (let i = 1; i <= 254; i += BATCH_SIZE) {
        const batch = [];
        for (let j = 0; j < BATCH_SIZE && i + j <= 254; j++) {
          batch.push(i + j);
        }
        const batchResults = await Promise.all(
          batch.map(async (lastOctet) => {
            const ip = `${base}.${lastOctet}`;
            const isAlive = await checkPort(80, ip, 1e3) || await checkPort(443, ip, 1e3) || await checkPort(22, ip, 1e3);
            return { ip, isAlive };
          })
        );
        results.push(...batchResults);
      }
      res.json({ targetIp: scanIp, alive: results.filter((r) => r.isAlive) });
    } else {
      res.status(400).json({ error: "Invalid IPv4 structure" });
    }
  } catch (error) {
    res.status(500).json({ error: "Failed to scan subnet for target" });
  }
});
app.get("/api/net/smb", async (req, res) => {
  const { target } = req.query;
  if (!target || typeof target !== "string") {
    return res.status(400).json({ error: "Target is required" });
  }
  const checkSmb = () => {
    return new Promise((resolve) => {
      const socket = new import_net.default.Socket();
      socket.setTimeout(2500);
      let resolved = false;
      socket.on("connect", () => {
        if (!resolved) {
          resolved = true;
          socket.destroy();
          resolve("open");
        }
      });
      socket.on("error", () => {
        if (!resolved) {
          resolved = true;
          resolve("closed");
        }
      });
      socket.on("timeout", () => {
        socket.destroy();
        if (!resolved) {
          resolved = true;
          resolve("closed");
        }
      });
      let hostIp = target;
      if (target.startsWith("http")) hostIp = target.replace(/^https?:\/\//, "").split("/")[0];
      socket.connect(445, hostIp);
    });
  };
  try {
    const result = await checkSmb();
    res.json({ result });
  } catch (e) {
    res.json({ result: "error" });
  }
});
app.get("/api/net/shell", async (req, res) => {
  const { target } = req.query;
  if (!target || typeof target !== "string") {
    return res.status(400).json({ error: "Target is required" });
  }
  const grabBanner = (port, host, timeout = 3e3) => {
    return new Promise((resolve) => {
      const socket = new import_net.default.Socket();
      let buf = "";
      let tcpError = "";
      socket.setTimeout(timeout);
      socket.on("data", (data) => {
        buf += data.toString();
        if (buf.length > 5) {
          socket.destroy();
        }
      });
      socket.on("connect", () => {
      });
      socket.on("timeout", () => {
        tcpError = "ETIMEDOUT (Connection timed out)";
        socket.destroy();
      });
      socket.on("error", (err) => {
        tcpError = err.code || err.message || "Connection failed";
        socket.destroy();
      });
      socket.on("close", () => {
        resolve({
          open: buf.length > 0 || socket.bytesRead > 0,
          banner: buf.trim(),
          error: tcpError
        });
      });
      try {
        socket.connect(port, host);
      } catch (err) {
        resolve({ open: false, banner: "", error: err.message });
      }
    });
  };
  try {
    const [ssh, ftp] = await Promise.all([
      grabBanner(22, target),
      grabBanner(21, target)
    ]);
    res.json({ ssh, ftp });
  } catch (error) {
    res.status(500).json({ error: "Banner grab failed" });
  }
});
app.get("/api/net/geoip", async (req, res) => {
  const { target } = req.query;
  if (!target || typeof target !== "string") {
    return res.status(400).json({ error: "Target is required" });
  }
  try {
    let lookupTarget = target;
    if (!/^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$/.test(target)) {
      try {
        const lookRes = await import_dns.default.promises.lookup(target);
        lookupTarget = lookRes.address;
      } catch (err) {
        return res.status(404).json({ error: "DNS resolution failed for target host" });
      }
    }
    const geoResponse = await fetch(`http://ip-api.com/json/${lookupTarget}`);
    if (geoResponse.ok) {
      const geoResult = await geoResponse.json();
      if (geoResult.status === "success") {
        res.json({ targetIp: lookupTarget, geo: geoResult });
        return;
      }
    }
    res.status(404).json({ error: "Geolocation data not found" });
  } catch (error) {
    res.status(500).json({ error: "Failed to retrieve IP/Host info" });
  }
});
app.get("/api/net/ping", async (req, res) => {
  const { target } = req.query;
  if (!target || typeof target !== "string") {
    return res.status(400).json({ error: "Target is required" });
  }
  let hostIp = target;
  try {
    const lookRes = await import_dns.default.promises.lookup(target);
    hostIp = lookRes.address;
  } catch (e) {
    return res.status(404).json({ error: "DNS resolution failed." });
  }
  const pingTcp = (port) => {
    return new Promise((resolve) => {
      const start = Date.now();
      const socket = new import_net.default.Socket();
      let connected = false;
      socket.setTimeout(2e3);
      socket.on("connect", () => {
        connected = true;
        socket.destroy();
        resolve(Date.now() - start);
      });
      socket.on("timeout", () => {
        socket.destroy();
        resolve(null);
      });
      socket.on("error", () => {
        socket.destroy();
        if (!connected) resolve(null);
      });
      socket.connect(port, hostIp);
    });
  };
  try {
    const time80 = await pingTcp(80);
    const time443 = await pingTcp(443);
    if (time80 !== null) {
      res.json({ ip: hostIp, port: 80, time: time80 });
    } else if (time443 !== null) {
      res.json({ ip: hostIp, port: 443, time: time443 });
    } else {
      res.status(408).json({ error: "Host unreachable or blocked ICMP/TCP ping requests" });
    }
  } catch (err) {
    res.status(500).json({ error: "Ping failed" });
  }
});
app.get("/api/net/certs", async (req, res) => {
  const { target } = req.query;
  if (!target || typeof target !== "string") {
    return res.status(400).json({ error: "Target is required" });
  }
  const tls = require("tls");
  const options = {
    host: target,
    port: 443,
    servername: target,
    rejectUnauthorized: false
  };
  const socket = tls.connect(options, () => {
    const cert = socket.getPeerCertificate(true);
    socket.destroy();
    if (cert && Object.keys(cert).length > 0) {
      res.json({
        subject: cert.subject,
        issuer: cert.issuer,
        valid_from: cert.valid_from,
        valid_to: cert.valid_to,
        fingerprint: cert.fingerprint,
        fingerprint256: cert.fingerprint256,
        serialNumber: cert.serialNumber
      });
    } else {
      res.status(404).json({ error: "No certificate retrieved" });
    }
  });
  socket.setTimeout(3e3);
  socket.on("timeout", () => {
    socket.destroy();
    res.status(408).json({ error: "Timeout waiting for TLS socket" });
  });
  socket.on("error", (err) => {
    socket.destroy();
    res.status(500).json({ error: err.message || "TLS connection failed" });
  });
});
app.get("/api/net/pwned", async (req, res) => {
  const { email } = req.query;
  if (!email || typeof email !== "string") {
    return res.status(400).json({ error: "Email is required" });
  }
  try {
    const pwnedRes = await fetch(`https://haveibeenpwned.com/api/v3/breachedaccount/${encodeURIComponent(email)}`);
    if (pwnedRes.ok) {
      const data = await pwnedRes.json();
      res.json({ breaches: data });
    } else if (pwnedRes.status === 404) {
      res.json({ breaches: [] });
    } else if (pwnedRes.status === 401) {
      res.status(401).json({ error: "This tool requires a Have I Been Pwned API Key to be configured on the server environment. Provide API key in .env to use." });
    } else {
      res.status(500).json({ error: `HIBP API returned status ${pwnedRes.status}` });
    }
  } catch (error) {
    res.status(500).json({ error: "Failed to contact HIBP registry" });
  }
});
app.get("/api/net/dirscan", async (req, res) => {
  const { target } = req.query;
  if (!target || typeof target !== "string") {
    return res.status(400).json({ error: "Target is required" });
  }
  const commonDirs = [
    "admin",
    "login",
    "dashboard",
    "api",
    "assets",
    "css",
    "js",
    "images",
    "wp-admin",
    "wp-content",
    "wp-includes",
    "robots.txt",
    "sitemap.xml",
    ".git",
    ".git/config",
    ".env",
    "backup",
    "old",
    "test",
    "dev",
    "logs",
    "config",
    "vendor",
    "composer.json",
    "composer.lock",
    "package.json",
    "package-lock.json",
    ".svn",
    ".env.example",
    "README.md",
    "src",
    "pub",
    "public",
    "build",
    "dist",
    "cgi-bin",
    "cache",
    "tmp",
    "secret",
    "temp",
    "users",
    "user",
    "app",
    "core",
    "lib",
    "uploads",
    "download",
    "downloads",
    "media",
    "files",
    "data",
    "database",
    "db",
    "sql",
    "dump.sql",
    "db.sql",
    "backup.sql",
    "phpmyadmin",
    "pma",
    "mysql",
    "adminer",
    "server-status",
    ".htaccess",
    ".htpasswd",
    "crossdomain.xml",
    "phpinfo.php",
    "info.php",
    "test.php",
    "index.php.bak",
    "index.html.bak",
    "config.php",
    "config.inc.php",
    "config.json",
    "config.yml",
    "settings.php",
    "settings.json",
    "web.config",
    "server.js",
    "main.js",
    "app.js",
    "yarn.lock",
    "docker-compose.yml",
    "Dockerfile",
    ".DS_Store",
    "Thumbs.db",
    "LICENSE",
    "changelog.txt",
    "CHANGELOG",
    "LICENSE.txt",
    "administrator",
    "auth",
    "auth/login",
    "account",
    "profile",
    "register",
    "signup",
    "v1",
    "v2",
    "v3",
    "graphql",
    "swagger",
    "swagger-ui",
    "api-docs",
    "docs",
    "api/v1",
    "api/v2",
    "api/v3",
    "api/graphql",
    "api/swagger",
    "api/docs",
    "api/auth",
    "api/login",
    "api/users",
    "api/admin",
    "api/status",
    "api/health",
    "api/healthcheck",
    "health",
    "healthcheck",
    "status",
    "ping",
    "metrics",
    "actuator",
    "actuator/health",
    "actuator/info",
    "actuator/env",
    "actuator/metrics",
    "actuator/prometheus",
    "forum",
    "blog",
    "news",
    "store",
    "shop",
    "cart",
    "checkout",
    "orders",
    "support",
    "help",
    "faq",
    "contact",
    "about",
    "privacy",
    "terms",
    "sitemap",
    "wp-login.php",
    "xmlrpc.php",
    "install.php",
    "setup.php",
    "upgrade.php",
    "server-info",
    "haproxy-status",
    "nginx_status",
    "php-status",
    "solr",
    "appspecs.yml",
    "appsettings.json",
    "web.xml",
    "pom.xml",
    "build.gradle",
    "secrets.yml",
    "database.yml",
    "master.key",
    ".bash_history",
    ".ssh/id_rsa",
    "backups",
    "archives",
    "dump",
    "exports",
    "imports",
    "shared",
    "static",
    "resources",
    "includes",
    "views",
    "templates",
    "components",
    "styles",
    "scripts",
    "plugins",
    "modules",
    "themes",
    "lang",
    "locales",
    "translations",
    "config.js",
    "config.ts",
    "default.conf",
    "nginx.conf",
    "apache2.conf",
    ".DS_Store",
    "error_log",
    "access_log",
    "debug.log",
    "server.log",
    "webmail",
    "cpanel",
    "whm",
    "cp",
    "dl",
    "wp",
    "wpm",
    "mail",
    "exchange",
    "owa",
    "admin",
    "login",
    "portal",
    "dashboard",
    "control",
    "secure",
    "members",
    "documents",
    "Documents",
    "doc",
    "docs",
    "Docs",
    "Doc",
    "pdf",
    "pdfs",
    "xls",
    "xlsx",
    "word",
    "csv",
    "txt",
    "rtf",
    "image",
    "images",
    "img",
    "imgs",
    "pic",
    "pics",
    "picture",
    "pictures",
    "photo",
    "photos",
    "file",
    "files",
    "dl",
    "download",
    "downloads",
    "shared",
    "share",
    "upload",
    "uploads",
    "video",
    "videos",
    "media",
    "audio",
    "music",
    "sound",
    "sounds",
    "movie",
    "movies",
    "forum",
    "forums",
    "board",
    "boards",
    "community",
    "blog",
    "news",
    "article",
    "articles",
    "ajax",
    "xhr",
    "remote-login",
    "cgi",
    "cgi-bin",
    "javascript",
    "ts",
    "jsx",
    "tsx",
    "app",
    "core"
  ];
  let baseUrl = target.replace(/\/$/, "");
  if (!baseUrl.startsWith("http://") && !baseUrl.startsWith("https://")) {
    baseUrl = "http://" + baseUrl;
  }
  try {
    const results = [];
    try {
      const homeCtrl = new AbortController();
      const homeTo = setTimeout(() => homeCtrl.abort(), 4e3);
      const homeRes = await fetch(baseUrl, { headers: { "User-Agent": "Mozilla/5.0" }, signal: homeCtrl.signal });
      clearTimeout(homeTo);
      if (homeRes.ok) {
        const html = await homeRes.text();
        const urlRegex = /(?:href|src|action)\s*=\s*(?:["'])(.*?)(?:["'])/gi;
        let match;
        while ((match = urlRegex.exec(html)) !== null) {
          const extracted = match[1].trim();
          if (!extracted || extracted.startsWith("javascript:") || extracted.startsWith("mailto:") || extracted.startsWith("#") || extracted.startsWith("data:")) continue;
          let path2 = "";
          if (extracted.startsWith("http")) {
            if (extracted.startsWith(baseUrl)) {
              path2 = extracted.replace(baseUrl, "");
            }
          } else if (extracted.startsWith("/")) {
            path2 = extracted;
          } else if (!extracted.startsWith("//")) {
            path2 = "/" + extracted;
          }
          if (path2) {
            path2 = path2.split("?")[0].split("#")[0];
            const firstSegment = path2.split("/")[1];
            if (firstSegment && !firstSegment.includes(".")) {
              commonDirs.push(firstSegment);
            }
          }
        }
      }
    } catch (e) {
    }
    const uniqueDirs = [...new Set(commonDirs)];
    const BATCH_SIZE = 15;
    for (let i = 0; i < uniqueDirs.length; i += BATCH_SIZE) {
      const batch = uniqueDirs.slice(i, i + BATCH_SIZE);
      await Promise.all(batch.map(async (dir) => {
        try {
          const url = `${baseUrl}/${dir}`;
          const controller = new AbortController();
          const timeoutId = setTimeout(() => controller.abort(), 4e3);
          const response = await fetch(url, {
            method: "GET",
            redirect: "follow",
            signal: controller.signal,
            headers: { "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)" }
          });
          clearTimeout(timeoutId);
          const status = response.status;
          if (status === 200 || status === 401 || status === 403) {
            const resUrl = response.url;
            const isCatchAll = resUrl === baseUrl || resUrl === baseUrl + "/" || resUrl.includes("page-not-found") || resUrl.includes("404");
            if (!isCatchAll || status === 401 || status === 403) {
              results.push({ path: `/${dir}`, status: 200 });
            }
          }
        } catch (err) {
        }
      }));
    }
    results.sort((a, b) => a.path.localeCompare(b.path));
    res.json({ results });
  } catch (error) {
    res.status(500).json({ error: "Directory scan failed" });
  }
});
app.get("/api/net/adminfinder", async (req, res) => {
  const { target } = req.query;
  if (!target || typeof target !== "string") return res.status(400).json({ error: "Target is required" });
  const dirs = [
    "admin",
    "login",
    "admin/login.php",
    "administrator",
    "wp-admin",
    "cpanel",
    "config",
    "dashboard",
    "admin.php",
    "admin.html",
    "backend",
    "controlpanel",
    "cp",
    "webadmin",
    "admin/index.php",
    "admin/login",
    "adminarea",
    "panel",
    "manager",
    "admin_login",
    "auth",
    "auth/login",
    "manage",
    "phpmyadmin",
    "pma",
    "adminer",
    "admin/dashboard",
    "admin/admin.php",
    "sysadmin",
    "admin.aspx",
    "admin.jsp",
    "login.jsp",
    "login.aspx",
    "login.html",
    "login.php",
    "admin-console",
    "admin-panel",
    "admin-dashboard",
    "adm",
    "admin_1",
    "admin1",
    "admin2",
    "admin3",
    "admin4",
    "admin5",
    "usuarios",
    "usuario",
    "cms",
    "cms-admin",
    "siteadmin",
    "site-admin",
    "myadmin",
    "my-admin",
    "webmaster",
    "web-master",
    "administratorlogin",
    "administrator-login",
    "adminlogin",
    "admin-login",
    "admin_area",
    "admin_panel",
    "admin_dashboard",
    "administracion",
    "access",
    "auth/admin",
    "superadmin",
    "super-admin",
    "root",
    "staff",
    "system",
    "user",
    "users",
    "members",
    "member",
    "portal",
    "secure",
    "secure/login",
    "webmail",
    "cpanel",
    "whm",
    "cp",
    "dl",
    "wp",
    "wpm",
    "mail",
    "exchange",
    "owa",
    "zimbra",
    "roundcube",
    "squirrelmail",
    "horde",
    "postfixadmin",
    "exim",
    "webmail/",
    "cpanel/",
    "whm/",
    "cp/",
    "dl/",
    "wp/",
    "wpm/",
    "mail/",
    "exchange/",
    "owa/",
    "control-panel",
    "hosting",
    "host",
    "dashboard/login"
  ];
  let baseUrl = target.replace(/\/$/, "");
  if (!baseUrl.startsWith("http://") && !baseUrl.startsWith("https://")) baseUrl = "http://" + baseUrl;
  const results = [];
  try {
    const BATCH_SIZE = 10;
    for (let i = 0; i < dirs.length; i += BATCH_SIZE) {
      const batch = dirs.slice(i, i + BATCH_SIZE);
      await Promise.all(batch.map(async (dir) => {
        try {
          const controller = new AbortController();
          const timeoutId = setTimeout(() => controller.abort(), 4e3);
          const response = await fetch(`${baseUrl}/${dir}`, {
            method: "GET",
            redirect: "follow",
            signal: controller.signal,
            headers: { "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)" }
          });
          clearTimeout(timeoutId);
          const status = response.status;
          if (status === 200 || status === 401 || status === 403) {
            const resUrl = response.url;
            const isCatchAll = resUrl === baseUrl || resUrl === baseUrl + "/" || resUrl.includes("page-not-found") || resUrl.includes("404");
            if (!isCatchAll || status === 401 || status === 403) {
              results.push({ path: `/${dir}`, status: 200 });
            }
          }
        } catch (err) {
        }
      }));
    }
    results.sort((a, b) => a.path.localeCompare(b.path));
    res.json({ results });
  } catch (e) {
    res.status(500).json({ error: "Scan failed" });
  }
});
app.get("/api/net/reactscan", async (req, res) => {
  const { target } = req.query;
  if (!target || typeof target !== "string") return res.status(400).json({ error: "Target is required" });
  let baseUrl = target.replace(/\/$/, "");
  if (!baseUrl.startsWith("http://") && !baseUrl.startsWith("https://")) baseUrl = "https://" + baseUrl;
  const results = [];
  try {
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), 6e3);
    const resNode = await fetch(baseUrl, { method: "GET", signal: controller.signal, headers: { "User-Agent": "Mozilla/5.0" } });
    clearTimeout(timeoutId);
    if (resNode.ok) {
      const html = await resNode.text();
      if (html.includes("__NEXT_DATA__") || html.includes("_next/static")) {
        results.push({ path: "Next.js Framework Signature", status: "Detected" });
      }
      if (html.includes("data-reactroot") || html.includes('id="__next"') || html.includes('id="root"')) {
        results.push({ path: "React DOM Node (Root)", status: "Detected" });
      }
      if (html.includes("window.React") || html.includes(".createElement(")) {
        results.push({ path: "React Global Variable/Signatures", status: "Detected" });
      }
      if (html.includes("static/js/main.") && html.includes(".chunk.js")) {
        results.push({ path: "Create React App Structure", status: "Detected" });
      }
      if (html.includes('content="Astro') || html.includes("astro-island")) {
        results.push({ path: "Astro Framework", status: "Detected" });
      }
      if (html.includes("gatsby-") || html.includes('id="___gatsby"')) {
        results.push({ path: "Gatsby Framework", status: "Detected" });
      }
      if (html.includes("/.remix/") || html.includes("window.__remixContext")) {
        results.push({ path: "Remix Framework", status: "Detected" });
      }
      if (html.match(/@vite\/client|vite-plugin-/)) {
        results.push({ path: "Vite Bundler", status: "Detected" });
      }
      if (results.length === 0) {
        results.push({ path: "No typical modern React/Next signatures found strictly in HTML root.", status: "Undetected" });
      }
    } else {
      results.push({ path: `Error: Received HTTP ${resNode.status}`, status: "Failed" });
    }
    res.json({ results });
  } catch (e) {
    res.status(500).json({ error: "Scan failed to fetch target URL" });
  }
});
app.get("/api/net/js_scan", async (req, res) => {
  const { target } = req.query;
  if (!target || typeof target !== "string") return res.status(400).json({ error: "Target is required" });
  let baseUrl = target.replace(/\/$/, "");
  if (!baseUrl.startsWith("http://") && !baseUrl.startsWith("https://")) baseUrl = "https://" + baseUrl;
  try {
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), 6e3);
    const htmlRes = await fetch(baseUrl, { method: "GET", signal: controller.signal, headers: { "User-Agent": "Mozilla/5.0" } });
    clearTimeout(timeoutId);
    if (!htmlRes.ok) throw new Error("Failed to fetch target page");
    const html = await htmlRes.text();
    const scriptRegex = /<script[^>]+src=["']([^"']+)["']/gi;
    let match;
    const jsLinks = /* @__PURE__ */ new Set();
    while ((match = scriptRegex.exec(html)) !== null) {
      let src = match[1];
      if (src.startsWith("//")) src = "https:" + src;
      else if (src.startsWith("/")) src = baseUrl + src;
      else if (!src.startsWith("http")) src = baseUrl + "/" + src;
      jsLinks.add(src);
    }
    if (jsLinks.size === 0) {
      return res.json({ result: "No external JS files found on the page.", secrets: [], endpoints: [] });
    }
    const secretsFound = [];
    const endpointsFound = /* @__PURE__ */ new Set();
    const secretRegexes = [
      { name: "Google API Key", regex: /AIza[0-9A-Za-z-_]{35}/g },
      { name: "Stripe Secret Key", regex: /sk_live_[0-9a-zA-Z]{24}/g },
      { name: "AWS Access Key", regex: /AKIA[0-9A-Z]{16}/g },
      { name: "Generic Token", regex: /["'](?:token|secret|api_key|password)["']\s*:\s*["']([a-zA-Z0-9\-_+/]{16,})["']/gi }
    ];
    const endpointRegex = /(?:"|')(\/api\/[a-zA-Z0-9_/?&=-]+)(?:"|')/gi;
    const scriptsToFetch = Array.from(jsLinks).slice(0, 5);
    await Promise.all(scriptsToFetch.map(async (src) => {
      try {
        const c = new AbortController();
        const to = setTimeout(() => c.abort(), 4e3);
        const jsRes = await fetch(src, { signal: c.signal, headers: { "User-Agent": "Mozilla/5.0" } });
        clearTimeout(to);
        if (!jsRes.ok) return;
        const jsText = await jsRes.text();
        secretRegexes.forEach(({ name, regex }) => {
          let smatch;
          while ((smatch = regex.exec(jsText)) !== null) {
            secretsFound.push(`[${name}] in JS: ${smatch[0].substring(0, 15)}...`);
          }
        });
        let ematch;
        while ((ematch = endpointRegex.exec(jsText)) !== null) {
          endpointsFound.add(ematch[1]);
        }
      } catch (e) {
      }
    }));
    res.json({
      result: `Scanned ${scriptsToFetch.length} JS files.`,
      secrets: secretsFound,
      endpoints: Array.from(endpointsFound)
    });
  } catch (error) {
    res.status(500).json({ error: "Failed to scan JS files" });
  }
});
app.get("/api/net/cors_scan", async (req, res) => {
  const { target } = req.query;
  if (!target || typeof target !== "string") return res.status(400).json({ error: "Target is required" });
  let baseUrl = target.replace(/\/$/, "");
  if (!baseUrl.startsWith("http://") && !baseUrl.startsWith("https://")) baseUrl = "https://" + baseUrl;
  try {
    const evilOrigin = "https://evilhacker.com";
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), 5e3);
    const response = await fetch(baseUrl, {
      method: "GET",
      signal: controller.signal,
      headers: { "Origin": evilOrigin, "User-Agent": "Mozilla/5.0" }
    });
    clearTimeout(timeoutId);
    const acao = response.headers.get("access-control-allow-origin");
    const acac = response.headers.get("access-control-allow-credentials");
    let vulnStatus = "SAFE";
    let message = "CORS headers seem correctly configured.";
    if (acao === "*") {
      vulnStatus = "WARNING";
      message = "Wildcard (*) Origin allowed. This is low-risk but exposes public APIs.";
    } else if (acao === evilOrigin) {
      vulnStatus = "CRITICAL";
      message = `Target reflected our evil origin (${evilOrigin})!`;
      if (acac === "true") {
        message += " AND allows credentials! Complete CORS bypass.";
      }
    } else if (acao === "null") {
      vulnStatus = "WARNING";
      message = 'Allowed origin is "null", which can sometimes be bypassed via iframes.';
    } else if (!acao) {
      message = "No Access-Control-Allow-Origin header found (Safe).";
    } else {
      message = `Allowed Origin: ${acao}`;
    }
    res.json({ result: message, status: vulnStatus, acao: acao || "none", acac: acac || "none" });
  } catch (error) {
    res.status(500).json({ error: "Failed to perform CORS scan" });
  }
});
app.get("/api/net/phonecrawl", async (req, res) => {
  const { target } = req.query;
  if (!target || typeof target !== "string") return res.status(400).json({ error: "Target is required" });
  let baseUrl = target.replace(/\/$/, "");
  if (!baseUrl.startsWith("http://") && !baseUrl.startsWith("https://")) baseUrl = "http://" + baseUrl;
  try {
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), 5e3);
    const response = await fetch(baseUrl, { signal: controller.signal });
    clearTimeout(timeoutId);
    const text = await response.text();
    const phoneRegex = /(?<!\d)(?:\+?\d{1,3}[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}(?!\d)/g;
    const matches = text.match(phoneRegex) || [];
    const uniqueMatches = [...new Set(matches.map((m) => m.trim()))].filter((m) => {
      const digits = m.replace(/\D/g, "").length;
      return digits >= 10 && digits <= 15;
    });
    res.json({ count: uniqueMatches.length, numbers: uniqueMatches });
  } catch (e) {
    res.status(500).json({ error: "Crawler failed to fetch target" });
  }
});
app.get("/api/net/dos", async (req, res) => {
  const { target } = req.query;
  if (!target || typeof target !== "string") return res.status(400).json({ error: "Target is required" });
  let baseUrl = target.replace(/\/$/, "");
  if (!baseUrl.startsWith("http://") && !baseUrl.startsWith("https://")) baseUrl = "http://" + baseUrl;
  try {
    const promises = Array.from({ length: 100 }).map((_, i) => {
      const controller = new AbortController();
      const timeoutId = setTimeout(() => controller.abort(), 3e3);
      return fetch(`${baseUrl}?st=${Date.now()}${i}`, { mode: "no-cors", cache: "no-store", signal: controller.signal }).catch((e) => null).finally(() => clearTimeout(timeoutId));
    });
    await Promise.all(promises.slice(0, 20));
    res.json({ message: "Stress test burst completed (100 packets)" });
  } catch (e) {
    res.status(500).json({ error: "Failed to complete stress burst" });
  }
});
app.get("/api/net/webfaker", async (req, res) => {
  try {
    const idString = req.query.id;
    const seed = idString ? parseInt(idString) || 1 : Math.floor(Math.random() * 1e4) + 1;
    const random = (s) => {
      let x = Math.sin(s++) * 1e4;
      return x - Math.floor(x);
    };
    const firstNames = ["John", "Jane", "Alex", "Chris", "Katie", "Mike", "Sarah", "Emma", "David", "James", "Mary", "Robert", "Patricia", "Michael", "Linda", "William", "Elizabeth", "Richard", "Barbara", "Joseph", "Susan", "Thomas", "Jessica", "Charles", "Sarah", "Christopher", "Karen", "Daniel", "Nancy", "Matthew", "Lisa", "Anthony", "Betty", "Mark", "Margaret", "Donald", "Sandra", "Steven", "Ashley", "Paul", "Kimberly", "Andrew", "Emily", "Joshua", "Donna", "Kenneth", "Michelle", "Kevin", "Dorothy", "Brian", "Carol", "George", "Amanda", "Edward", "Melissa", "Ronald", "Deborah", "Timothy", "Stephanie", "Jason", "Rebecca", "Jeffrey", "Sharon", "Ryan", "Laura", "Jacob", "Cynthia", "Gary", "Kathleen", "Nicholas", "Amy", "Eric", "Shirley", "Jonathan", "Angela", "Stephen", "Helen", "Larry", "Anna", "Justin", "Brenda", "Scott", "Pamela", "Brandon", "Nicole", "Benjamin", "Emma", "Samuel", "Samantha", "Gregory", "Katherine", "Frank", "Christine", "Alexander", "Debra", "Raymond", "Rachel", "Patrick", "Catherine", "Jack", "Carolyn", "Dennis", "Janet", "Jerry", "Ruth", "Tyler", "Maria", "Aaron", "Heather", "Jose", "Diane", "Adam", "Virginia", "Henry", "Julie", "Nathan", "Joyce", "Douglas", "Victoria", "Zachary", "Olivia", "Peter", "Kelly", "Kyle", "Christina", "Walter", "Lauren", "Ethan", "Joan", "Jeremy", "Evelyn", "Christian", "Judith", "Keith", "Megan", "Roger", "Cheryl", "Terry", "Andrea", "Gerald", "Hannah", "Harold", "Martha", "Sean", "Jacqueline", "Austin", "Frances", "Carl", "Gloria", "Arthur", "Ann", "Lawrence", "Teresa", "Dylan", "Kathryn", "Jesse", "Sara", "Jordan", "Janice", "Bryan", "Jean", "Ralph", "Alice", "Joe", "Madison", "Noah", "Doris", "Bruce", "Abigail", "Billy", "Julia", "Albert", "Judy", "Willie", "Grace", "Gabriel", "Denise", "Logan", "Amber", "Alan", "Marilyn", "Juan", "Beverly", "Wayne", "Danielle", "Roy", "Theresa", "Ralph", "Sophia", "Randy", "Marie", "Eugene", "Diana", "Vincent", "Brittany", "Russell", "Natalie", "Elijah", "Isabella", "Louis", "Charlotte", "Bobby", "Rose", "Philip", "Alexis", "Johnny", "Kayla"];
    const lastNames = ["Smith", "Doe", "Johnson", "Williams", "Brown", "Jones", "Garcia", "Miller", "Davis", "Rodriguez", "Martinez", "Hernandez", "Lopez", "Gonzalez", "Wilson", "Anderson", "Thomas", "Taylor", "Moore", "Jackson", "Martin", "Lee", "Perez", "Thompson", "White", "Harris", "Sanchez", "Clark", "Ramirez", "Lewis", "Robinson", "Walker", "Young", "Allen", "King", "Wright", "Scott", "Torres", "Nguyen", "Hill", "Flores", "Green", "Adams", "Nelson", "Baker", "Hall", "Rivera", "Campbell", "Mitchell", "Carter", "Roberts", "Gomez", "Phillips", "Evans", "Turner", "Diaz", "Parker", "Cruz", "Edwards", "Collins", "Reyes", "Stewart", "Morris", "Morales", "Murphy", "Cook", "Rogers", "Gutierrez", "Ortiz", "Morgan", "Cooper", "Peterson", "Bailey", "Reed", "Kelly", "Howard", "Ramos", "Kim", "Cox", "Ward", "Richardson", "Watson", "Brooks", "Chavez", "Wood", "James", "Bennett", "Gray", "Mendoza", "Ruiz", "Hughes", "Price", "Alvarez", "Castillo", "Sanders", "Patel", "Myers", "Long", "Ross", "Foster", "Jimenez", "Powell", "Jenkins", "Perry", "Russell", "Sullivan", "Bell", "Coleman", "Washington", "Butler", "Barnes"];
    const domains = ["gmail.com", "yahoo.com", "protonmail.com", "outlook.com", "hotmail.com", "icloud.com", "aol.com", "mail.com", "zoho.com", "yandex.com"];
    const streetNames = ["Main St", "Oak St", "Pine St", "Maple Ave", "Cedar Ln", "Elm St", "Washington Blvd", "Park Ave", "Lakeview Dr", "Hillcrest Rd", "Sunset Blvd", "Lincoln Ave"];
    const cities = ["New York", "Los Angeles", "Chicago", "Houston", "Phoenix", "Philadelphia", "San Antonio", "San Diego", "Dallas", "San Jose", "Austin", "Jacksonville", "Fort Worth", "Columbus", "San Francisco", "Charlotte", "Indianapolis", "Seattle", "Denver", "Washington"];
    const states = ["NY", "CA", "IL", "TX", "AZ", "PA", "TX", "CA", "TX", "CA", "TX", "FL", "TX", "OH", "CA", "NC", "IN", "WA", "CO", "DC"];
    const r = (arr, s) => arr[Math.floor(random(s) * arr.length)];
    const first = r(firstNames, seed * 1);
    const last = r(lastNames, seed * 2);
    const domain = r(domains, seed * 3);
    const age = Math.floor(random(seed * 4) * 40) + 18;
    const currentYear = (/* @__PURE__ */ new Date()).getFullYear();
    const birthYear = currentYear - age;
    const birthMonth = Math.floor(random(seed * 5) * 12) + 1;
    const birthDay = Math.floor(random(seed * 6) * 28) + 1;
    const birthdate = `${birthYear}-${birthMonth.toString().padStart(2, "0")}-${birthDay.toString().padStart(2, "0")}`;
    const streetNum = Math.floor(random(seed * 7) * 9e3) + 100;
    const street = r(streetNames, seed * 8);
    const cityIndex = Math.floor(random(seed * 9) * cities.length);
    const city = cities[cityIndex];
    const state = states[cityIndex];
    const zip = Math.floor(random(seed * 10) * 89999) + 1e4;
    const address = `${streetNum} ${street}, ${city}, ${state} ${zip}`;
    let output = `--- Profile ID: ${seed} ---
`;
    output += `Name: ${first} ${last}
`;
    output += `Age: ${age}
`;
    output += `Birthdate: ${birthdate}
`;
    output += `Address: ${address}
`;
    output += `Email: ${first.toLowerCase()}.${last.toLowerCase()}${age}@${domain}
`;
    output += `Phone: +1-${Math.floor(random(seed * 11) * 900) + 100}-${Math.floor(random(seed * 12) * 900) + 100}-${Math.floor(random(seed * 13) * 9e3) + 1e3}
`;
    output += `Username: ${first.toLowerCase()}_${last.toLowerCase()}_${Math.floor(random(seed * 14) * 999)}
`;
    output += `Password: ${first}${last}${Math.floor(random(seed * 15) * 999)}!
`;
    res.json({ content: output });
  } catch (e) {
    res.status(500).json({ error: "Failed to generate fake data" });
  }
});
app.all("/api/net/hackbar", async (req, res) => {
  const target = req.query.target;
  const method = (req.query.method || "GET").toUpperCase();
  const payload = req.query.payload;
  if (!target || typeof target !== "string") return res.status(400).json({ error: "Target is required" });
  let baseUrl = target.replace(/\/$/, "");
  if (!baseUrl.startsWith("http")) baseUrl = "http://" + baseUrl;
  if (method === "GET" && payload) {
    baseUrl += baseUrl.includes("?") ? `&payload=${encodeURIComponent(payload)}` : `?payload=${encodeURIComponent(payload)}`;
  }
  try {
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), 1e4);
    const fetchOptions = {
      method,
      signal: controller.signal
    };
    if (method === "POST" && payload) {
      fetchOptions.body = new URLSearchParams({ payload });
      fetchOptions.headers = { "Content-Type": "application/x-www-form-urlencoded" };
    }
    const response = await fetch(baseUrl, fetchOptions);
    clearTimeout(timeoutId);
    const html = await response.text();
    res.json({
      status: response.status,
      statusText: response.statusText,
      data: html.substring(0, 5e3)
    });
  } catch (e) {
    res.status(500).json({ error: e.message || "Failed to fetch source" });
  }
});
app.get("/api/net/speedtest/download", (req, res) => {
  const size = parseInt(req.query.size) || 1024 * 1024 * 5;
  res.set("Content-Type", "application/octet-stream");
  res.set("Content-Length", size.toString());
  res.set("Cache-Control", "no-cache, no-store, must-revalidate");
  res.set("Pragma", "no-cache");
  res.set("Expires", "0");
  const chunk = Buffer.alloc(1024 * 64, "0");
  let sent = 0;
  const sendData = () => {
    while (sent < size) {
      let toSend = Math.min(chunk.length, size - sent);
      sent += toSend;
      if (!res.write(chunk.slice(0, toSend))) {
        res.once("drain", sendData);
        return;
      }
    }
    res.end();
  };
  sendData();
});
app.post("/api/net/speedtest/upload", (req, res) => {
  let received = 0;
  req.on("data", (chunk) => {
    received += chunk.length;
  });
  req.on("end", () => {
    res.json({ success: true, bytesReceived: received });
  });
});
app.get("/api/net/wpscan", async (req, res) => {
  const { target } = req.query;
  if (!target || typeof target !== "string") return res.status(400).json({ error: "Target is required" });
  let baseUrl = target.replace(/\/$/, "");
  if (!baseUrl.startsWith("http://") && !baseUrl.startsWith("https://")) baseUrl = "https://" + baseUrl;
  const results = { isWordPress: false, version: null, endpoints: {}, themes: [], plugins: [] };
  try {
    const checkPath = async (p) => {
      try {
        const c = new AbortController();
        const t = setTimeout(() => c.abort(), 2e3);
        const r = await fetch(`${baseUrl}${p}`, { method: "GET", signal: c.signal });
        clearTimeout(t);
        return { ok: r.ok, status: r.status, text: r.ok ? await r.text() : "" };
      } catch {
        return { ok: false, status: 0, text: "" };
      }
    };
    const home = await checkPath("/");
    if (home.text.includes("wp-content") || home.text.includes("wp-includes")) {
      results.isWordPress = true;
    }
    const match = home.text.match(/name="generator" content="WordPress (.*?)"/i);
    if (match && match[1]) results.version = match[1];
    if (!results.isWordPress) {
      const login = await checkPath("/wp-login.php");
      if (login.ok && login.text.includes("user_login")) results.isWordPress = true;
    }
    if (results.isWordPress) {
      const endpoints = ["/wp-login.php", "/xmlrpc.php", "/wp-json/"];
      for (const ep of endpoints) {
        const r = await checkPath(ep);
        results.endpoints[ep] = r.status;
      }
      const pluginRegex = /wp-content\/plugins\/([^\/]+)\//g;
      let pMatch;
      const foundP = /* @__PURE__ */ new Set();
      while ((pMatch = pluginRegex.exec(home.text)) !== null) {
        foundP.add(pMatch[1]);
      }
      results.plugins = Array.from(foundP);
      const themeRegex = /wp-content\/themes\/([^\/]+)\//g;
      let tMatch;
      const foundT = /* @__PURE__ */ new Set();
      while ((tMatch = themeRegex.exec(home.text)) !== null) {
        foundT.add(tMatch[1]);
      }
      results.themes = Array.from(foundT);
    }
    res.json(results);
  } catch (e) {
    res.status(500).json({ error: "WP scan fetch failed" });
  }
});
app.get("/api/net/cve/recent", async (req, res) => {
  console.log("HIT RECENT API ENDPOINT!!!");
  try {
    const controller = new AbortController();
    const t = setTimeout(() => controller.abort(), 6e3);
    const end = /* @__PURE__ */ new Date();
    const start = new Date(end.getTime() - 7 * 24 * 60 * 60 * 1e3);
    const url = `https://services.nvd.nist.gov/rest/json/cves/2.0?pubStartDate=${start.toISOString()}&pubEndDate=${end.toISOString()}`;
    const r = await fetch(url, {
      signal: controller.signal,
      headers: { "User-Agent": "Mozilla/5.0" }
    });
    clearTimeout(t);
    if (!r.ok) throw new Error("Fetch failed");
    const nvdData = await r.json();
    if (nvdData?.vulnerabilities) {
      nvdData.vulnerabilities.sort((a, b) => {
        const d1 = new Date(a.cve?.published || 0).getTime();
        const d2 = new Date(b.cve?.published || 0).getTime();
        return d2 - d1;
      });
      const formatted = nvdData.vulnerabilities.slice(0, 15).map((v) => {
        const cve = v.cve;
        const id = cve?.id || "Unknown";
        const summary = cve?.descriptions?.find((d) => d.lang === "en")?.value || "No summary available";
        const cvssData = cve?.metrics?.cvssMetricV31?.[0]?.cvssData || cve?.metrics?.cvssMetricV30?.[0]?.cvssData || cve?.metrics?.cvssMetricV2?.[0]?.cvssData;
        const cvss = cvssData ? cvssData.baseScore : null;
        return { id, cvss, summary };
      });
      return res.json({ vulnerabilities: formatted });
    }
    res.json({ vulnerabilities: [] });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: "CVE fetch failed", fallback: true });
  }
});
var exploitDbCache = null;
var cachePromise = null;
var initExploitDb = async () => {
  if (exploitDbCache) return exploitDbCache;
  if (cachePromise) return cachePromise;
  cachePromise = fetch("https://gitlab.com/exploit-database/exploitdb/-/raw/main/files_exploits.csv").then((r) => r.text()).then((text) => {
    const lines = text.split("\n");
    const data = [];
    for (let i = 1; i < lines.length; i++) {
      const row = lines[i];
      if (!row || row.trim().length === 0) continue;
      const cols = row.split(/,(?=(?:(?:[^"]*"){2})*[^"]*$)/);
      if (cols.length >= 7) {
        data.push({
          id: cols[0],
          file: cols[1],
          description: cols[2].replace(/^"|"$/g, ""),
          author: cols[4].replace(/^"|"$/g, ""),
          type: cols[5].replace(/^"|"$/g, ""),
          platform: cols[6].replace(/^"|"$/g, "")
        });
      }
    }
    exploitDbCache = data;
    cachePromise = null;
    return data;
  }).catch(() => {
    cachePromise = null;
    return [];
  });
  return cachePromise;
};
setTimeout(initExploitDb, 2e3);
app.get("/api/net/exploitdb/search", async (req, res) => {
  const q = (req.query.q || "").toString().toLowerCase();
  if (!q) return res.json({ data: [] });
  try {
    const data = await initExploitDb();
    const results = data.filter(
      (item) => item.description.toLowerCase().includes(q) || item.author.toLowerCase().includes(q) || item.id === q || item.platform.toLowerCase().includes(q)
    ).slice(0, 50);
    const formatted = results.map((r) => ({
      ...r,
      url: `https://www.exploit-db.com/exploits/${r.id}`
    }));
    res.json({ data: formatted });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: "Failed to search exploit db" });
  }
});
app.get("/api/net/cve/search", async (req, res) => {
  const { id } = req.query;
  if (!id || typeof id !== "string") return res.status(400).json({ error: "ID is required" });
  const cid = id.trim().toUpperCase();
  try {
    const tc1 = new AbortController();
    const t1 = setTimeout(() => tc1.abort(), 4e3);
    const res1 = await fetch(`https://cveawg.mitre.org/api/cve/${cid}`, { signal: tc1.signal });
    clearTimeout(t1);
    if (res1.ok) return res.json({ fallback: false, data: await res1.json() });
    const tc2 = new AbortController();
    const t2 = setTimeout(() => tc2.abort(), 4e3);
    const res2 = await fetch(`https://cve.circl.lu/api/cve/${cid}`, { signal: tc2.signal });
    clearTimeout(t2);
    if (res2.ok) return res.json({ fallback: true, data: await res2.json() });
    res.status(404).json({ error: "Not found" });
  } catch (e) {
    res.status(500).json({ error: "Error" });
  }
});
async function startServer() {
  if (process.env.NODE_ENV !== "production") {
    const vite = await (0, import_vite.createServer)({
      server: { middlewareMode: true },
      appType: "spa"
    });
    app.use(vite.middlewares);
  } else {
    const distPath = import_path.default.join(process.cwd(), "dist");
    app.use(import_express.default.static(distPath));
    app.get("*", (req, res) => {
      res.sendFile(import_path.default.join(distPath, "index.html"));
    });
  }
  app.listen(PORT, "0.0.0.0", () => {
    console.log(`Server running on http://0.0.0.0:${PORT}`);
  });
}
startServer();
//# sourceMappingURL=server.cjs.map
