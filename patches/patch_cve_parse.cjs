const fs = require('fs');
let code = fs.readFileSync('server.ts', 'utf8');

const oldParse = `if (nvdData?.vulnerabilities) {
           const formatted = nvdData.vulnerabilities.map((v: any) => {
               const cve = v.cve;
               const id = cve?.id || 'Unknown';
               const summary = cve?.descriptions?.find((d: any) => d.lang === 'en')?.value || 'No summary available';
               const cvssData = cve?.metrics?.cvssMetricV31?.[0]?.cvssData || cve?.metrics?.cvssMetricV30?.[0]?.cvssData || cve?.metrics?.cvssMetricV2?.[0]?.cvssData;
               const cvss = cvssData ? cvssData.baseScore : null;
               
               return { id, cvss, summary };
           });
           return res.json({ vulnerabilities: formatted });
       }`;

const newParse = `if (Array.isArray(nvdData)) {
           const vulns = nvdData.flatMap((x: any) => x.vulnerabilities || []).filter((v: any) => v.cve);
           const formatted = vulns.slice(0, 15).map((v: any) => {
               const id = v.cve || 'Unknown';
               const summary = v.notes?.find((n: any) => n.category === 'description')?.text || v.title || 'No summary available';
               const cvss = v.scores?.[0]?.cvss_v3?.baseScore || v.scores?.[0]?.cvss_v2?.baseScore || null;
               return { id, cvss, summary };
           });
           return res.json({ vulnerabilities: formatted });
       }`;

code = code.replace(oldParse, newParse);
fs.writeFileSync('server.ts', code);
console.log('parsing patched');
