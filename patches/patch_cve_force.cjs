const fs = require('fs');
let code = fs.readFileSync('server.ts', 'utf8');

const startStr = "app.get('/api/net/cve/recent', async (req, res) => {";
const endStr = "  app.get('/api/net/cve/search', async (req, res) => {";

const startIndex = code.indexOf(startStr);
const endIndex = code.indexOf(endStr);

if (startIndex !== -1 && endIndex !== -1) {
  const newBlock = `app.get('/api/net/cve/recent', async (req, res) => {
    try {
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
           nvdData.vulnerabilities.sort((a: any, b: any) => {
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
       res.json({ vulnerabilities: [] });
    } catch (e) {
       console.error(e);
       res.status(500).json({ error: 'CVE fetch failed', fallback: true });
    }
  });\n\n`;

  code = code.substring(0, startIndex) + newBlock + code.substring(endIndex);
  fs.writeFileSync('server.ts', code);
  console.log('patched');
} else {
  console.log('not found');
}
