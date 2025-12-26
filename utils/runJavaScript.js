const { exec } = require("child_process");
const fs = require("fs");
const path = require("path");
const { v4: uuidv4 } = require("uuid");

const TEMP_DIR = path.join(__dirname, "../temp");
if (!fs.existsSync(TEMP_DIR)) fs.mkdirSync(TEMP_DIR);

module.exports = function runJavaScript(code) {
  return new Promise((resolve, reject) => {
    const filename = `${uuidv4()}.js`;
    const filepath = path.join(TEMP_DIR, filename);

    fs.writeFileSync(filepath, code);

    // Run with Node.js
    exec(`node "${filepath}"`, { timeout: 5000 }, (error, stdout, stderr) => {
      // Cleanup
      try { fs.unlinkSync(filepath); } catch (e) {}

      if (error && error.killed) {
        return resolve({ output: "Error: Time Limit Exceeded" });
      }
      
      // Combine stdout and stderr so user sees errors too
      const output = stderr ? `${stdout}\nError:\n${stderr}` : stdout;
      resolve({ output });
    });
  });
};