const { exec } = require("child_process");
const fs = require("fs");
const path = require("path");
const { v4: uuidv4 } = require("uuid");

const TEMP_DIR = path.join(__dirname, "../temp");
if (!fs.existsSync(TEMP_DIR)) fs.mkdirSync(TEMP_DIR);

module.exports = function runPython(code) {
  return new Promise((resolve, reject) => {
    const filename = `${uuidv4()}.py`;
    const filepath = path.join(TEMP_DIR, filename);

    fs.writeFileSync(filepath, code);

    // Try 'python3' first, fallback to 'python' if needed
    const pythonCmd = process.platform === "win32" ? "python" : "python3";

    exec(`${pythonCmd} "${filepath}"`, { timeout: 5000 }, (error, stdout, stderr) => {
      try { fs.unlinkSync(filepath); } catch (e) {}

      if (error && error.killed) {
        return resolve({ output: "Error: Time Limit Exceeded" });
      }

      const output = stderr ? `${stdout}\n${stderr}` : stdout;
      resolve({ output });
    });
  });
};