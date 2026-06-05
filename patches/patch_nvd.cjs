const fs = require('fs');
let code = fs.readFileSync('server.ts', 'utf8');

const regex = /try\s*{\s*const controller[\s\S]*?res\.json\(\{ vulnerabilities: \[\] \}\);/m;

const replacement = `try {
       const controller = new AbortController();
       const t = setTimeout(() => controller.abort(), 6000);
       const end = new Date();
       const start = new Date(end.getTime() - 7 * 24 * 60 * 60 * 1000);
       const url = \`https://services.nvd.nist.gov/rest/json/cves/2.0?pubStartDate=\${start.toISOString()}&pubEndDate=\${end.toISOString()}\`;
       
       const r = await fetch(url, { 
           signal: controller.signal,
           headers: { 'User-Agent': 'Mozilla/5.0' }
       });
       clearTimeout(t);
       if (!r.ok) throw new Error('Fetch failed');
       const nvdData = await r.json();
       
       if (nvdData?.vulnerabilities) {
           // Sort by published descending to get the absolute newest first
           nvdData.vulnerabilities.sort((a, b) => {
              const d1 = new Date(a.cve?.published || 0).getTime();
              const d2 = new Date(b.cve?.published || 0).getTime();
              return d2 - d1;
           });
           
           const formatted = nvdData.vulnerabilities.slice(0, 15).map((v: any) => {
               const cve = v.cve;
               const id = cve?.id || 'Unknown';
               const summary = cve?.descriptions?.find((d: any) => d.lang === 'en')?.value || 'No summary available';
               const cvssData = cve?.metrics?.cvssMetricV31?.[0]?.cvssData || cve?.metrics?.cvssMetricV30?.[0]?.cvssData || cve?.metrics?.cvssMetricV2?.[0]?.cvssData;
               const cvss = cvssData ? cvssData.baseScore : null;
               
               return { id, cvss, summary };
           });
           return res.json({ vulnerabilities: formatted });
       }
       res.json({ vulnerabilities: [] });`;

code = code.replace(regex, replacement);
fs.writeFileSync('server.ts', code);
console.log('patched nvd api');
