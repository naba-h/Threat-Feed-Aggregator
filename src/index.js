export default {
  async fetch(request, env) {
    const headers = {
      "content-type": "application/json",
      "access-control-allow-origin": "*",
      "access-control-allow-methods": "GET",
      "access-control-allow-headers": "*"
    };

    try {
      const url = new URL(request.url);
      const ip = url.searchParams.get("ip");

      if (!ip) {
        return new Response(JSON.stringify({
          error: "Missing IP. Use ?ip=8.8.8.8"
        }), { status: 400, headers });
      }

      // Safe demo threat engine (no API keys required)
      const last = parseInt(ip.split(".").pop());

      let score = (last * 7) % 100;

      let verdict =
        score > 70 ? "High Risk" :
        score > 40 ? "Medium Risk" :
        "Low Risk";

      const data = {
        ip,
        verdict,
        threat_score: score,
        confidence: Math.min(100, score + 15),
        sources: {
          virustotal: { country: "Unknown", malicious: score > 60 ? 3 : 0 },
          abuseipdb: { score },
          shodan: {
            isp: "Simulated Network",
            ports: score > 60 ? [22, 3389] : [80, 443]
          }
        }
      };

      return new Response(JSON.stringify(data, null, 2), { headers });

    } catch (e) {
      return new Response(JSON.stringify({
        error: "Worker failure",
        details: e.toString()
      }), { status: 500, headers });
    }
  }
};
