export default {
  async fetch(request, env) {
    try {
      const url = new URL(request.url);
      const ip = url.searchParams.get("ip");

      if (!ip) {
        return json({ error: "Missing IP parameter. Use ?ip=8.8.8.8" }, 400);
      }

      const cached = await env.THREAT_CACHE?.get(ip);
      if (cached) return json(JSON.parse(cached));

      const [vt, abuse, otx, shodan] = await Promise.all([
        virusTotal(ip, env),
        abuseIPDB(ip, env),
        otxLookup(ip, env),
        shodanLookup(ip, env)
      ]);

      const score = calculateScore(vt, abuse, otx, shodan);
      const verdict = classify(score);
      const confidence = calculateConfidence(vt, abuse, otx, shodan);

      const result = {
        ip,
        verdict,
        threat_score: score,
        confidence,
        sources: {
          virustotal: vt,
          abuseipdb: abuse,
          otx: otx,
          shodan: shodan
        }
      };

      await env.THREAT_CACHE?.put(ip, JSON.stringify(result), { expirationTtl: 3600 });

      return json(result);

    } catch (err) {
      return json({ error: "Internal error", detail: err.message }, 500);
    }
  }
};

/* ================= HELPERS ================= */

function json(data, status = 200) {
  return new Response(JSON.stringify(data, null, 2), {
    status,
    headers: { "content-type": "application/json" }
  });
}

/* ================= VIRUSTOTAL ================= */

async function virusTotal(ip, env) {
  try {
    const r = await fetch(`https://www.virustotal.com/api/v3/ip_addresses/${ip}`, {
      headers: { "x-apikey": env.VIRUSTOTAL_API_KEY }
    });
    const j = await r.json();
    const s = j.data.attributes.last_analysis_stats;
    return {
      malicious: s.malicious,
      suspicious: s.suspicious,
      country: j.data.attributes.country,
      asn: j.data.attributes.asn
    };
  } catch {
    return { malicious: 0, suspicious: 0 };
  }
}

/* ================= ABUSEIPDB ================= */

async function abuseIPDB(ip, env) {
  try {
    const r = await fetch(`https://api.abuseipdb.com/api/v2/check?ipAddress=${ip}`, {
      headers: { Key: env.ABUSEIPDB_API_KEY, Accept: "application/json" }
    });
    const j = await r.json();
    return {
      score: j.data.abuseConfidenceScore,
      country: j.data.countryCode
    };
  } catch {
    return { score: 0 };
  }
}

/* ================= OTX ================= */

async function otxLookup(ip, env) {
  try {
    const r = await fetch(`https://otx.alienvault.com/api/v1/indicators/IPv4/${ip}/general`, {
      headers: { "X-OTX-API-KEY": env.OTX_API_KEY }
    });
    const j = await r.json();
    return { pulses: j.pulse_info.count };
  } catch {
    return { pulses: 0 };
  }
}

/* ================= SHODAN ================= */

async function shodanLookup(ip, env) {
  try {
    const r = await fetch(`https://api.shodan.io/shodan/host/${ip}?key=${env.SHODAN_API_KEY}`);
    const j = await r.json();
    return {
      ports: j.ports || [],
      isp: j.isp || null,
      org: j.org || null
    };
  } catch {
    return { ports: [] };
  }
}

/* ================= SCORING ENGINE ================= */

function calculateScore(vt, abuse, otx, shodan) {
  let score = 0;
  score += (vt.malicious * 20) + (vt.suspicious * 10);
  score += abuse.score;
  score += otx.pulses * 5;
  score += (shodan.ports?.length || 0) * 2;
  return Math.min(100, score);
}

function classify(score) {
  if (score >= 70) return "High Risk";
  if (score >= 30) return "Medium Risk";
  return "Low Risk";
}

function calculateConfidence(vt, abuse, otx, shodan) {
  let sources = 0;
  if (vt) sources++;
  if (abuse) sources++;
  if (otx) sources++;
  if (shodan) sources++;
  return Math.min(100, sources * 25);
}
