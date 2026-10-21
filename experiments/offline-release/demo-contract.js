"use strict";
const { canonical, Preview } = require("../browser-preview/preview");
const { canonicalJson, sha256Text } = require("../../broker/providers/approval-core");
function validate(text) {
  if (Buffer.byteLength(text,"utf8") > 262144) throw Error("DEMO_OVERSIZED");
  const root = JSON.parse(text);
  if (canonicalJson(root)+"\n" !== text || root.reviewFileSchemaVersion !== 1 || root.designation !== "SYNTHETIC_DESIGN_ONLY" || root.producerAuthentication !== "NONE") throw Error("DEMO_FRAMING_INVALID");
  const { contextSha256, ...payload } = root.context;
  if (sha256Text(canonicalJson(payload)) !== contextSha256 || payload.authorized !== false || payload.productionAuthorization !== "DEFAULT_DENY" || payload.expiresAt - payload.createdAt !== 300000) throw Error("DEMO_BINDING_INVALID");
  for (const target of payload.targets) if (sha256Text(target.task) !== target.taskSha256 || target.wire.messages[0].content !== target.task) throw Error("DEMO_TASK_INVALID");
  return {status:"SYNTHETIC_CONSISTENCY_ONLY",authorized:false,productionAuthorization:"DEFAULT_DENY"};
}
function response(text) { const p=new Preview(); const now=Date.now(); p.load(text,now); return p.respond("GRANT",now); }
if(require.main===module) {
  let input="";process.stdin.setEncoding("utf8");
  process.stdin.on("data",chunk=>{input+=chunk;if(Buffer.byteLength(input,"utf8")>262144)process.exit(2)});
  process.stdin.on("end",()=>{try{const mode=process.argv[2];if(mode==="--validate")process.stdout.write(JSON.stringify(validate(input)));else if(mode==="--response")process.stdout.write(response(input));else process.exitCode=64}catch{process.stderr.write("DEMO_CONTRACT_INVALID\n");process.exitCode=2}});
}
module.exports={validate,response};
