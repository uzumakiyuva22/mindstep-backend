const { exec } = require("child_process");
const fs = require("fs");
const path = require("path");
const { v4: uuidv4 } = require("uuid");

const TEMP_DIR = path.join(__dirname, "../temp");
// Ensure temp directory exists
if (!fs.existsSync(TEMP_DIR)) fs.mkdirSync(TEMP_DIR, { recursive: true });

module.exports = function runPython(code) {
  return new Promise((resolve, reject) => {
    const filename = `${uuidv4()}.py`;
    const filepath = path.join(TEMP_DIR, filename);

    fs.writeFileSync(filepath, code);

    // ✅ SMART FIX: Use 'py' for Windows, 'python3' for Mac/Linux
    // Windows usually installs the 'py' launcher by default, even if 'python' isn't in PATH.
    const isWindows = process.platform === "win32";
    const command = isWindows ? "py" : "python3";

    exec(`${command} "${filepath}"`, { timeout: 5000 }, (error, stdout, stderr) => {
      // Cleanup temp file
      try { fs.unlinkSync(filepath); } catch (e) {}

      // Check for "not recognized" error specifically
      if (error && (stderr.includes("not recognized") || stderr.includes("not found"))) {
        return resolve({ 
          output: "❌ CONFIGURATION ERROR:\nPython is not found on this computer.\n\n1. Install Python from python.org\n2. During install, check 'Add Python to PATH'\n3. Restart your code editor." 
        });
      }

      if (error && error.killed) {
        return resolve({ output: "Error: Time Limit Exceeded" });
      }

      // Return output (combine stdout and stderr)
      const output = stderr ? `${stdout}\n${stderr}` : stdout;
      resolve({ output });
    });
  });
};