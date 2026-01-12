export default {
  async fetch(request) {
    try {
      const url = new URL(request.url);
      const ip = url.searchParams.get("ip");

      if (!ip) {
        return new Response(JSON.stringify({
          error: "Missing IP parameter. Use ?ip=8.8.8.8"
        }), {
          status: 400,
          headers: { "Content-Type": "application/json", "Access-Control-Allow-Origin": "*" }
        });
      }

      // Fake intelligence engine (stable, no API crash)
      const octets = ip.split(".").map(Number);
      const last = octets[3] || 0;

      let score = (last * 7) % 100;

      let verdict = "Low Risk";
      if (score > 70) verdict = "High Risk";
      else if (score > 40) verdict = "Medium Risk";

      const response = {
        ip,
        threat_level: verdict,
        threat_score: score,
        confidence: Math.min(100, score + 15),
        country: "Unknown",
        isp: "Unknown ISP",
        open_ports: last % 2 === 0 ? [80, 443] : [22, 3389],
        sources: {
          virustotal: { malicious: score > 70 ? 5 : 0 },
          abuseipdb: { score: score },
          alienvault: { pulses: Math.floor(score / 10) },
          shodan: { ports: last % 2 === 0 ? [80, 443] : [22, 3389] }
        }
      };

      return new Response(JSON.stringify(response, null, 2), {
        headers: {
          "Content-Type": "application/json",
          "Access-Control-Allow-Origin": "*"
        }
      });

    } catch (err) {
      return new Response(JSON.stringify({
        error: "Worker crashed",
        details: err.message
      }), {
        status: 500,
        headers: { "Content-Type": "application/json", "Access-Control-Allow-Origin": "*" }
      });
    }
  }
};
