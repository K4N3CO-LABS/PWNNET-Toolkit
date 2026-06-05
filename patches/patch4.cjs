const fs = require('fs');
let code = fs.readFileSync('server.ts', 'utf8');

const replacement = `       const r = await fetch('https://cve.circl.lu/api/last', { 
           signal: controller.signal,
           headers: { 'User-Agent': 'Mozilla/5.0' }
       });
       clearTimeout(t);
       if (!r.ok) throw new Error('Fetch failed');
       const nvdData = await r.json();
       
       if (Array.isArray(nvdData)) {
           const vulns = nvdData.flatMap((x) => x.vulnerabilities || []).filter((v) => v.cve);
           const formatted = vulns.slice(0, 15).map((v) => {
               const id = v.cve || 'Unknown';
               const summary = v.notes?.find((n) => n.category === 'description')?.text || v.title || 'No summary available';
               const cvss = v.scores?.[0]?.cvss_v3?.baseScore || v.scores?.[0]?.cvss_v2?.baseScore || null;
               return { id, cvss, summary };
           });
           return res.json({ vulnerabilities: formatted });
       }
       res.json({ vulnerabilities: [] });`;

// Use regex to replace the entire try block contents after `const t = setTimeout(() => controller.abort(), 6000);` 
// up to `res.json({ vulnerabilities: [] });`

const re = /const r = await fetch\('https:\/\/services\.nvd\.nist\.gov\/rest\/json\/cves\/2\.0\?resultsPerPage=15'[\s\S]*?res\.json\(\{ vulnerabilities: \[\] \}\);/;
code = code.replace(re, replacement);

fs.writeFileSync('server.ts', code);
console.log('patched cve api endpoint');
