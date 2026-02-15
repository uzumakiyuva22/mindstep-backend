const { spawn } = require("child_process");
const fs = require("fs");
const path = require("path");
const { v4: uuidv4 } = require("uuid");

const TEMP_DIR = path.join(__dirname, "../temp");
if (!fs.existsSync(TEMP_DIR)) fs.mkdirSync(TEMP_DIR, { recursive: true });

module.exports = function runJavaScript(code, stdin = "") {
  return new Promise((resolve) => {
    const filename = `${uuidv4()}.js`;
    const filepath = path.join(TEMP_DIR, filename);
    fs.writeFileSync(filepath, code || "", "utf8");

    const child = spawn("node", [filepath], { windowsHide: true });
    let stdout = "";
    let stderr = "";
    let timedOut = false;
    const timeoutMs = Number(process.env.JS_EXEC_TIMEOUT_MS || 8000);

    const timer = setTimeout(() => {
      timedOut = true;
      child.kill("SIGKILL");
    }, timeoutMs);

    child.stdout.on("data", (d) => {
      stdout += d.toString();
    });
    child.stderr.on("data", (d) => {
      stderr += d.toString();
    });

    child.on("error", (err) => {
      clearTimeout(timer);
      try { fs.unlinkSync(filepath); } catch (_) {}
      resolve({
        output: `Runtime Error: ${err.message}`,
        stdout: "",
        stderr: err.message,
        success: false,
        timedOut: false
      });
    });

    child.on("close", (code) => {
      clearTimeout(timer);
      try { fs.unlinkSync(filepath); } catch (_) {}

      if (timedOut) {
        return resolve({
          output: "Runtime Error: Execution Timed Out",
          stdout,
          stderr: stderr || "Execution timed out",
          success: false,
          timedOut: true
        });
      }

      const output = [stdout.trim(), stderr.trim()].filter(Boolean).join("\n");
      return resolve({
        output: output || "Execution finished.",
        stdout,
        stderr,
        success: code === 0,
        timedOut: false
      });
    });

    const payload = String(stdin || "");
    if (payload.length > 0) {
      child.stdin.write(payload.endsWith("\n") ? payload : `${payload}\n`);
    }
    child.stdin.end();
  });
};
