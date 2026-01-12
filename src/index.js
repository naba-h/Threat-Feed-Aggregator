export default {
  async fetch(request) {
    const headers = {
      "content-type": "application/json",
      "access-control-allow-origin": "*",
      "cache-control": "no-store",
      "x-content-type-options": "nosniff"
    };

    try {
      const url = new URL(request.url);
      const ip = url.searchParams.get("ip");

      if (!ip) {
        return new Response(JSON.stringify({
          error: "Missing IP. Use ?ip=8.8.8.8"
        }), { status: 400, headers });
      }

      // Fake but realistic scoring engine
      const last = parseInt(ip.split(".").pop()) || 1;
      const score = (last * 7) % 100;

      let threat =
        score > 70 ? "High Risk" :
        score > 40 ? "Medium Risk" :
        "Low Risk";

      const response = {
        ip: ip,
        threat_level: threat,
        threat_score: score,
        confidence: Math.floor(score * 0.9),
        country: "Global",
        isp: "Cloudflare Network",
        open_ports: [80, 443, 22]
      };

      return new Response(JSON.stringify(response), { headers });

    } catch (e) {
      return new Response(JSON.stringify({
        error: "Backend failure",
        details: e.message
      }), { status: 500, headers });
    }
  }
};
