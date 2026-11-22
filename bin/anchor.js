const { spawn } = require("node:child_process");
const path = require("node:path");

const script = path.join(__dirname, "..", "scripts", "anchor.py");
const python = process.platform === "win32" ? "python" : "python3";

const child = spawn(python, [script, ...process.argv.slice(2)], {
  stdio: "inherit",
});

child.on("exit", (code, signal) => {
  if (signal) process.kill(process.pid, signal);
  else process.exit(code ?? 1);
});
