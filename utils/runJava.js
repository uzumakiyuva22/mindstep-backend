const { exec } = require("child_process");
const fs = require("fs");
const path = require("path");
const { v4: uuidv4 } = require("uuid");

const TEMP_DIR = path.join(__dirname, "../temp");
if (!fs.existsSync(TEMP_DIR)) fs.mkdirSync(TEMP_DIR);

module.exports = function runJava(code) {
  return new Promise((resolve, reject) => {
    // Java requires file name to match class. We assume class is 'Main' or user didn't change it.
    // Safest bet: Create a unique folder, name file Main.java
    const folderName = uuidv4();
    const folderPath = path.join(TEMP_DIR, folderName);
    
    if (!fs.existsSync(folderPath)) fs.mkdirSync(folderPath);
    
    // We try to grab class name, or default to Main
    let className = "Main";
    const match = code.match(/public\s+class\s+(\w+)/);
    if (match && match[1]) {
        className = match[1];
    }
    
    const filepath = path.join(folderPath, `${className}.java`);

    fs.writeFileSync(filepath, code);

    // Compile then Run
    exec(`javac "${filepath}" && java -cp "${folderPath}" ${className}`, { timeout: 10000 }, (error, stdout, stderr) => {
      // Cleanup: remove folder and files
      try {
        fs.rmSync(folderPath, { recursive: true, force: true });
      } catch (e) {}

      if (error && error.killed) {
        return resolve({ output: "Error: Time Limit Exceeded" });
      }

      const output = stderr ? `${stdout}\n${stderr}` : stdout;
      resolve({ output });
    });
  });
};