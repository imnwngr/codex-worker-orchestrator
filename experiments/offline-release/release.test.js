"use strict";
const test=require("node:test"),assert=require("node:assert/strict"),fs=require("node:fs"),path=require("node:path");
const {validate,response}=require("./demo-contract");
const {pending}=require("../browser-preview/vector-cli");
const {canonicalJson}=require("../../broker/providers/approval-core");
const {fixtureContext}=require("../integration-contracts/export-review-cli");
const {serializeReview}=require("../integration-contracts/export-review");
test("release demo Node validates canonical bound synthetic fixture",()=>{const {context,now}=fixtureContext(true);assert.equal(validate(serializeReview(context,now).toString()).productionAuthorization,"DEFAULT_DENY")});
test("release demo Node rejects tampered task, digest, authority and framing",()=>{
 const {context,now}=fixtureContext(true),text=serializeReview(context,now).toString();
 for(const change of [r=>r.context.authorized=true,r=>r.context.contextSha256="a".repeat(64),r=>r.context.targets[0].task="forged",r=>r.producerAuthentication="VERIFIED"]){const r=JSON.parse(text);change(r);assert.throws(()=>validate(canonicalJson(r)+"\n"))}
 assert.throws(()=>validate(text+" "));assert.throws(()=>validate("x".repeat(262145)));
});
test("release browser demo response rejects historical expired request",()=>{assert.throws(()=>response(pending().package))});
test("release package allowlist excludes tests and production broker",()=>{
 const common=fs.readFileSync(path.join(__dirname,"Release.Common.ps1"),"utf8");
 const names=[...common.matchAll(/'(app\/[^']+|browser\/[^']+|tools\/[^']+|QUICKSTART.md)'/g)].map(m=>m[1]);
 assert.equal(names.length,11);assert.equal(new Set(names).size,11);
 assert.ok(names.every(n=>!n.includes("test")&&!n.includes("broker")&&!n.endsWith(".pdb")));
});
