import { copyFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { resolve, join } from "node:path";
import process from "node:process";
import { spawnSync } from "node:child_process";

const addon = resolve(process.argv[2] ?? (process.platform === "win32"
  ? "target/release/certael_node.dll" : process.platform === "darwin"
    ? "target/release/libcertael_node.dylib" : "target/release/libcertael_node.so"));
const modulePath = resolve(process.argv[3]
  ?? "target/wasm32-unknown-unknown/release/certael_reference_repeated_reward_rule.wasm");
const temporary = join(tmpdir(), `certael-node-wasm-${process.pid}.node`);
try {
  copyFileSync(addon, temporary);
  const program = String.raw`
    const fs=require('node:fs');
    const a=require(process.argv[1]);
    const module=fs.readFileSync(process.argv[2]);
    const input=Buffer.from([8,1,18,6,116,101,110,97,110,116,26,4,103,97,109,101,
      34,4,112,114,111,100,42,15,114,101,119,97,114,100,46,114,101,112,101,97,
      116,101,100,50,1,49,58,1,4,66,0]);
    const expected=Buffer.from([8,1,16,2,26,15,82,69,80,69,65,84,69,68,95,82,
      69,87,65,82,68,32,80,42,14,10,9,116,104,114,101,115,104,111,108,100,18,1,51]);
    const result=Buffer.from(a.evaluateWasmRule(module,input));
    if(!result.equals(expected))throw new Error('unexpected Certael WASM decision');
    process.stdout.write('Certael Node WASM ABI v1 verified\n');`;
  const child = spawnSync(process.execPath, ["-e", program, temporary, modulePath],
    { stdio: "inherit" });
  if (child.status !== 0) throw new Error("Certael Node WASM smoke process failed");
} finally {
  rmSync(temporary, { force: true });
}
