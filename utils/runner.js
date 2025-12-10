const fetch = global.fetch || require('node-fetch');

const JD_ID = process.env.JDOODLE_CLIENT_ID || null;
const JD_SECRET = process.env.JDOODLE_CLIENT_SECRET || null;
const JD_JAVA_VERSION_INDEX = process.env.JDOODLE_JAVA_VERSION_INDEX || '0';

async function runCodeRemote(language, script) {
  const jdLang = language === 'python' ? 'python3' : (language === 'javascript' ? 'nodejs' : language);

  // JDoodle if configured
  if (JD_ID && JD_SECRET) {
    try {
      const payload = { clientId: JD_ID, clientSecret: JD_SECRET, script, language: jdLang, versionIndex: JD_JAVA_VERSION_INDEX };
      const r = await fetch('https://api.jdoodle.com/v1/execute', {
        method: 'POST', headers: { 'Content-Type':'application/json' }, body: JSON.stringify(payload)
      });
      const j = await r.json();
      if (j && (j.output || j.result)) return String(j.output || j.result).trim();
    } catch (e) {
      console.warn('JDoodle failed, fallback to Piston:', e && e.message ? e.message : e);
    }
  }

  // Piston fallback
  try {
    const files = [{ name: language === 'java' ? 'Main.java' : (language === 'python' ? 'script.py' : 'script.js'), content: script }];
    const resp = await fetch('https://emkc.org/api/v2/piston/execute', {
      method:'POST', headers:{ 'Content-Type':'application/json' }, body: JSON.stringify({ language, version:'latest', files })
    });
    const data = await resp.json();
    const out = data.run?.stdout || data.run?.output || data.run?.stderr || '';
    return String(out).trim();
  } catch (e) {
    console.error('Piston runner failed:', e);
    throw new Error('Remote runner error');
  }
}

module.exports = { runCodeRemote };
