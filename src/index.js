export default {
  async fetch(request) {
    return new Response(JSON.stringify({
      status: "online",
      app: "Threat Feed Aggregator",
      owner: "Naba Hanfi",
      feeds: [
        "AlienVault OTX",
        "AbuseIPDB",
        "VirusTotal",
        "Shodan"
      ]
    }, null, 2), {
      headers: { "content-type": "application/json" }
    });
  }
}
