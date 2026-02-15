const { exec, spawn } = require("child_process");
const fs = require("fs");
const path = require("path");
const { v4: uuidv4 } = require("uuid");

const TEMP_DIR = path.join(__dirname, "../temp");
if (!fs.existsSync(TEMP_DIR)) fs.mkdirSync(TEMP_DIR, { recursive: true });

module.exports = function runJava(code, stdin = "") {
  return new Promise((resolve) => {
    const folderName = uuidv4();
    const folderPath = path.join(TEMP_DIR, folderName);
    if (!fs.existsSync(folderPath)) fs.mkdirSync(folderPath, { recursive: true });

    let className = "Main";
    const match = String(code || "").match(/public\s+class\s+(\w+)/);
    if (match && match[1]) className = match[1];

    const filepath = path.join(folderPath, `${className}.java`);
    fs.writeFileSync(filepath, code || "", "utf8");

    const compileTarget = process.env.JAVA_COMPILE_TARGET || "8";
    const compileWithReleaseCmd = `javac -Xlint:-options --release ${compileTarget} "${filepath}"`;
    const compileWithSourceTargetCmd = `javac -Xlint:-options -source ${compileTarget} -target ${compileTarget} "${filepath}"`;

    const cleanup = () => {
      try {
        fs.rmSync(folderPath, { recursive: true, force: true });
      } catch (_) {}
    };

    const executeProgram = (compileStderr = "") => {
      const child = spawn("java", ["-cp", folderPath, className], { windowsHide: true });
      let stdout = "";
      let stderr = String(compileStderr || "");
      let timedOut = false;

      const timeoutMs = Number(process.env.JAVA_EXEC_TIMEOUT_MS || 10000);
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
        cleanup();
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
        cleanup();

        if (timedOut) {
          return resolve({
            output: "Runtime Error: Execution Timed Out",
            stdout,
            stderr: stderr || "Execution timed out",
            success: false,
            timedOut: true
          });
        }

        const merged = [stdout.trim(), String(stderr || "").trim()].filter(Boolean).join("\n");
        return resolve({
          output: merged || "Execution finished.",
          stdout,
          stderr: String(stderr || ""),
          success: code === 0,
          timedOut: false
        });
      });

      const scannerUsed = /\bScanner\b/.test(String(code || ""));
      const supplied = String(stdin || "");
      const payload = supplied.length > 0 ? supplied : (scannerUsed ? "\n" : "");
      if (payload.length > 0) {
        child.stdin.write(payload.endsWith("\n") ? payload : `${payload}\n`);
      }
      child.stdin.end();
    };

    exec(compileWithReleaseCmd, { timeout: 10000 }, (compileError, _compileStdout, compileStderr) => {
      if (!compileError) {
        return executeProgram(compileStderr);
      }

      exec(compileWithSourceTargetCmd, { timeout: 10000 }, (fallbackError, fallbackStdout, fallbackStderr) => {
        if (fallbackError && fallbackError.killed) {
          cleanup();
          return resolve({
            output: "Runtime Error: Compilation Timed Out",
            stdout: "",
            stderr: "Compilation timed out",
            success: false,
            timedOut: true
          });
        }

        if (fallbackError) {
          cleanup();
          const stderr = String(fallbackStderr || "");
          const stdout = String(fallbackStdout || "");
          return resolve({
            output: [stdout.trim(), stderr.trim()].filter(Boolean).join("\n") || "Compilation failed",
            stdout,
            stderr,
            success: false,
            timedOut: false
          });
        }

        executeProgram(fallbackStderr);
      });
    });
  });
};
