"use strict";
const fs = require("node:fs"), path = require("node:path"), os = require("node:os");
const { spawnSync } = require("node:child_process");
const { hash, safeRoot } = require("../../broker/desktop/evidence");
const repository = path.resolve(__dirname, "../..");
function run(exe, args, logFile) {
  const result = spawnSync(exe, args, { cwd: repository, encoding: "utf8", windowsHide: true, maxBuffer: 16 * 1024 * 1024 });
  if (logFile) fs.writeFileSync(logFile, (result.stdout || "") + (result.stderr || ""), { flag: "wx" });
  if (result.error || result.status !== 0) throw new Error("BUILD_COMMAND_FAILED");
  return result.stdout.trim();
}
function sourceIdentity() {
  const names = run("git", ["ls-files", "-z", "--cached", "--others", "--exclude-standard"]).split("\0").filter(Boolean).sort();
  const files = [...new Set(names)].map(name => {
    const full = path.join(repository, name);
    if (!fs.existsSync(full)) return { path: name, deleted: true };
    if (!fs.lstatSync(full).isFile() || fs.lstatSync(full).isSymbolicLink()) throw new Error("UNSAFE_SOURCE");
    return { path: name, bytes: fs.statSync(full).size, sha256: hash(fs.readFileSync(full)) };
  });
  return { revision: run("git", ["rev-parse", "HEAD"]), tree: run("git", ["rev-parse", "HEAD^{tree}"]),
    dirty: !!run("git", ["status", "--porcelain"]), algorithm: "SHA256_SORTED_JSON_RAW_WORKING_FILES_V1",
    sha256: hash(Buffer.from(JSON.stringify(files))), files };
}
function inventory(root, prefix = "") {
  const files = [];
  for (const name of fs.readdirSync(path.join(root, prefix)).sort()) {
    const relative = prefix ? prefix + "/" + name : name, full = path.join(root, relative), stat = fs.lstatSync(full);
    if (stat.isSymbolicLink()) throw new Error("REPARSE_DENIED");
    if (stat.isDirectory()) files.push(...inventory(root, relative));
    else {
      if (!stat.isFile() || stat.size > 64 * 1024 * 1024 || files.length > 256) throw new Error("ARTIFACT_LIMIT");
      files.push({ path: relative, bytes: stat.size, sha256: hash(fs.readFileSync(full)) });
    }
  }
  return files;
}
function verifyPackage(root, expectedManifestSha256) {
  safeRoot(root);
  const bytes = fs.readFileSync(path.join(root, "manifest.json"));
  if (!/^[a-f0-9]{64}$/.test(expectedManifestSha256 || "") || hash(bytes) !== expectedManifestSha256)
    throw new Error("MANIFEST_PIN_MISMATCH");
  const manifest = JSON.parse(bytes);
  if (manifest.version !== 1 || manifest.authorized !== false || manifest.production !== "DEFAULT_DENY" ||
      !Array.isArray(manifest.artifacts)) throw new Error("INVALID_MANIFEST");
  const actual = inventory(path.join(root, "payload"));
  if (JSON.stringify(actual) !== JSON.stringify(manifest.artifacts)) throw new Error("PACKAGE_INTEGRITY_FAILED");
  return manifest;
}
function build(root) {
  root = safeRoot(root);
  if (root === repository || root.startsWith(repository + path.sep)) throw new Error("BUILD_OUTSIDE_SOURCE_REQUIRED");
  fs.mkdirSync(root);
  const source = sourceIdentity();
  const projects = {
    agent: "desktop-agent/DesktopAgent.Windows",
    fixture: "desktop-agent/DesktopAgent.Fixture",
    approval: "approval-agent/ApprovalAgent.Mock"
  };
  for (const output of ["payload", "rebuild"]) {
    const artifactsRoot = path.join(root, "intermediates-" + output);
    for (const [name, project] of Object.entries(projects)) {
      run("dotnet", ["publish", project, "-c", "Release", "--no-self-contained", "--artifacts-path", artifactsRoot,
        "-p:ContinuousIntegrationBuild=true", "-p:Deterministic=true", "-p:DebugType=None", "-p:DebugSymbols=false",
        "-p:PathMap=" + repository + "=/_/orchestrator%2C" + artifactsRoot + "=/_/artifacts", "-o", path.join(root, output, name)],
        path.join(root, output + "-" + name + ".log"));
    }
  }
  for (const output of ["payload", "rebuild"]) {
    fs.mkdirSync(path.join(root, output, "browser"));
    for (const name of ["index.html", "preview.css", "preview.js", "ui.js"])
      fs.copyFileSync(path.join(repository, "experiments/browser-preview", name), path.join(root, output, "browser", name), fs.constants.COPYFILE_EXCL);
  }
  if (sourceIdentity().sha256 !== source.sha256) throw new Error("SOURCE_CHANGED_DURING_BUILD");
  const artifacts = inventory(path.join(root, "payload")), repeat = inventory(path.join(root, "rebuild"));
  const binaryEquivalent = JSON.stringify(artifacts) === JSON.stringify(repeat);
  const manifest = { version: 1, designation: "PHASE15_UNSIGNED_DEVELOPMENT_REVIEW", authorized: false,
    production: "DEFAULT_DENY", source, configuration: "Release; deterministic; framework-dependent; PathMap",
    environment: { os: os.platform(), release: os.release(), architecture: os.arch(),
      sdk: run("dotnet", ["--version"]), node: process.version, git: run("git", ["--version"]) },
    artifacts, reproducibility: { sameHostTwoBuilds: binaryEquivalent, independentIntermediateDirectories: true, crossHost: "NOT_VERIFIED" },
    sourceEquivalence: source.dirty ? "WORKING_TREE_INVENTORY_ONLY" : "CLEAN_HEAD_RAW_WORKTREE",
    phase14PackageEquivalence: "NOT_VERIFIED_NO_RETAINED_PINNED_PACKAGE" };
  fs.writeFileSync(path.join(root, "manifest.json"), JSON.stringify(manifest, null, 2) + "\n", { flag: "wx" });
  const pin = hash(fs.readFileSync(path.join(root, "manifest.json")));
  fs.writeFileSync(path.join(root, "SHA256SUMS.txt"), pin + "  manifest.json\n", { flag: "wx" });
  verifyPackage(root, pin);
  if (!binaryEquivalent) throw new Error("BINARY_REPRODUCIBILITY_MISMATCH");
  return { status: "VERIFIED_DEVELOPMENT_PACKAGE", manifestSha256: pin, artifacts: artifacts.length,
    sameHostBinaryEquivalent: binaryEquivalent, sourceSha256: source.sha256, sourceRevision: source.revision };
}
if (require.main === module) {
  try {
    const [mode, root, pin] = process.argv.slice(2);
    const result = mode === "build" ? build(root) : mode === "verify" ? verifyPackage(root, pin) : (() => { throw new Error("INVALID_MODE"); })();
    console.log(JSON.stringify(result, null, 2));
  } catch (error) { console.error(/^[A-Z_]+$/.test(error.message) ? error.message : "PROVENANCE_FAILED"); process.exitCode = 1; }
}
module.exports = { build, verifyPackage, inventory, sourceIdentity };
