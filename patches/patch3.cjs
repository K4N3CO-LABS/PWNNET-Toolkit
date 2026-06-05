const fs = require('fs');
let code = fs.readFileSync('server.ts', 'utf8');

const oldCode = `       const r = await fetch('https://services.nvd.nist.gov/rest/json/cves/2.0?resultsPerPage=15', { 
           signal: controller.signal,
           headers: { 'User-Agent': 'Mozilla/5.0' }
       });
       clearTimeout(t);
       if (!r.ok) throw new Error('Fetch failed');
       const nvdData = await r.json();
       
       if (nvdData?.vulnerabilities) {
           const formatted = nvdData.vulnerabilities.map((v: any) => {
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

const newCode = `       const r = await fetch('https://cve.circl.lu/api/last', { 
           signal: controller.signal,
           headers: { 'User-Agent': 'Mozilla/5.0' }
       });
       clearTimeout(t);
       if (!r.ok) throw new Error('Fetch failed');
       const cveData = await r.json();
       
       if (Array.isArray(cveData)) {
           const vulns = cveData.flatMap((x: any) => x.vulnerabilities || []).filter((v: any) => v.cve);
           const formatted = vulns.slice(0, 15).map((v: any) => {
               const id = v.cve || 'Unknown';
               const summary = v.notes?.find((n: any) => n.category === 'description')?.text || v.title || 'No summary available';
               const cvss = v.scores?.[0]?.cvss_v3?.baseScore || v.scores?.[0]?.cvss_v2?.baseScore || null;
               return { id, cvss, summary };
           });
           return res.json({ vulnerabilities: formatted });
       }
       res.json({ vulnerabilities: [] });`;

if (code.includes('https://services.nvd.nist.gov/rest/json/cves/2.0?resultsPerPage=15')) {
  code = code.replace(oldCode, newCode);
  fs.writeFileSync('server.ts', code);
  console.log('patched');
} else {
  console.log('not found');
}
