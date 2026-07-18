import { copyFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { resolve, join } from "node:path";
import process from "node:process";
import { spawnSync } from "node:child_process";

const source = process.argv[2] === undefined
  ? resolve(process.platform === "win32" ? "target/release/certael_node.dll"
    : process.platform === "darwin" ? "target/release/libcertael_node.dylib"
      : "target/release/libcertael_node.so")
  : resolve(process.argv[2]);
const temporary = join(tmpdir(), `certael-node-smoke-${process.pid}.node`);
try {
  copyFileSync(source, temporary);
  const child = spawnSync(process.execPath, ["-e",
    "const a=require(process.argv[1]);if(a.certaelNodeAbiVersion()!==2||typeof a.verifyActionEnvelope!=='function'||typeof a.evaluateWasmRule!=='function')throw new Error('invalid Certael Node ABI');process.stdout.write('Certael Node ABI v2 loaded successfully\\n')",
    temporary], { stdio: "inherit" });
  if (child.status !== 0) throw new Error("Certael Node ABI smoke process failed");
} finally {
  rmSync(temporary, { force: true });
}
