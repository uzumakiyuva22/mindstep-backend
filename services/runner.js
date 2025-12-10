const fetch = global.fetch || require("node-fetch");
const { jdClientId, jdClientSecret, jdVersionIndex } = require("../config");

async function runCodeRemote(language, script) {
  const jdLang = language === "python" ? "python3" : (language === "javascript" ? "nodejs" : (language === "java" ? "java" : language));

  // JDoodle if available
  if (jdClientId && jdClientSecret) {
    try {
      const payload = {
        clientId: jdClientId,
        clientSecret: jdClientSecret,
        script,
        language: jdLang,
        versionIndex: jdVersionIndex || "0"
      };
      const r = await fetch("https://api.jdoodle.com/v1/execute", {
        method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(payload)
      });
      const j = await r.json();
      if (j && (j.output || j.result)) return String(j.output || j.result).trim();
    } catch (e) {
      console.warn("JDoodle failed:", e.message || e);
    }
  }

  // Piston fallback
  try {
    const files = [{ name: language === "java" ? "Main.java" : (language === "python" ? "script.py" : "script.js"), content: script }];
    const resp = await fetch("https://emkc.org/api/v2/piston/execute", {
      method: "POST", headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ language, version: "latest", files })
    });
    const data = await resp.json();
    const out = data.run?.stdout || data.run?.output || data.run?.stderr || "";
    return String(out).trim();
  } catch (e) {
    console.error("Piston failed:", e);
    throw new Error("Runner failed");
  }
}

module.exports = { runCodeRemote };
