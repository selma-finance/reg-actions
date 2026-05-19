import { createHash } from "node:crypto";
import { createReadStream, chmodSync, mkdirSync, readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import * as core from "@actions/core";
import * as actionsExec from "@actions/exec";
import * as io from "@actions/io";
import * as tc from "@actions/tool-cache";

// `@actions/exec` is execFile-style (no shell), safe to use with args array.
const runProcess = actionsExec.exec;

type Target = { triple: string; ext: string };

function resolveTarget(): Target {
  let osPart: string;
  let ext = "";
  switch (process.platform) {
    case "linux":
      osPart = "unknown-linux-gnu";
      break;
    case "darwin":
      osPart = "apple-darwin";
      break;
    case "win32":
      osPart = "pc-windows-msvc";
      ext = ".exe";
      break;
    default:
      throw new Error(`Unsupported OS: ${process.platform}`);
  }
  let archPart: string;
  switch (process.arch) {
    case "x64":
      archPart = "x86_64";
      break;
    case "arm64":
      archPart = "aarch64";
      break;
    default:
      throw new Error(`Unsupported arch: ${process.arch}`);
  }
  return { triple: `${archPart}-${osPart}`, ext };
}

async function sha256(file: string): Promise<string> {
  const hash = createHash("sha256");
  await new Promise<void>((resolve, reject) => {
    const stream = createReadStream(file);
    stream.on("data", (chunk) => hash.update(chunk));
    stream.on("end", () => resolve());
    stream.on("error", reject);
  });
  return hash.digest("hex");
}

function expectedShaFor(checksumsFile: string, tarballName: string): string {
  const line = readFileSync(checksumsFile, "utf8")
    .split("\n")
    .map((l) => l.trim())
    .find((l) => l.endsWith(tarballName) && /^[0-9a-f]{64}\s/.test(l));
  if (!line) {
    throw new Error(`checksums.txt has no entry for ${tarballName}`);
  }
  return line.split(/\s+/)[0]!;
}

async function maybeVerifyCosign(
  base: string,
  checksumsFile: string,
  workdir: string,
): Promise<void> {
  let cosign: string;
  try {
    cosign = await io.which("cosign", true);
  } catch {
    core.notice(
      "cosign not found on PATH; skipping signature verification (sha256 still verified). " +
        "Install sigstore/cosign-installer in your workflow to enable.",
    );
    return;
  }
  const sig = await tc.downloadTool(
    `${base}/checksums.txt.sig`,
    join(workdir, "checksums.txt.sig"),
  );
  const cert = await tc.downloadTool(
    `${base}/checksums.txt.pem`,
    join(workdir, "checksums.txt.pem"),
  );
  await runProcess(cosign, [
    "verify-blob",
    "--signature",
    sig,
    "--certificate",
    cert,
    "--certificate-identity-regexp",
    "https://github\\.com/reg-viz/reg-actions/\\.github/workflows/release\\.yml@.*",
    "--certificate-oidc-issuer",
    "https://token.actions.githubusercontent.com",
    checksumsFile,
  ]);
}

async function run(): Promise<void> {
  const { triple, ext } = resolveTarget();
  const ref = process.env.GITHUB_ACTION_REF || "main";
  const repo = process.env.GITHUB_ACTION_REPOSITORY || "reg-viz/reg-actions";
  const base = `https://github.com/${repo}/releases/download/${ref}`;
  const tarballName = `reg-actions-${triple}.tar.gz`;
  const tarballUrl = `${base}/${tarballName}`;
  const checksumsUrl = `${base}/checksums.txt`;

  const workdir = join(
    process.env.RUNNER_TEMP || tmpdir(),
    "reg-actions-bin",
  );
  mkdirSync(workdir, { recursive: true });

  core.info(`Downloading ${tarballUrl}`);
  const tarball = await tc.downloadTool(tarballUrl, join(workdir, tarballName));
  const checksumsFile = await tc.downloadTool(
    checksumsUrl,
    join(workdir, "checksums.txt"),
  );

  const expected = expectedShaFor(checksumsFile, tarballName);
  const actual = await sha256(tarball);
  if (actual !== expected) {
    throw new Error(
      `SHA256 mismatch for ${tarballName}: expected ${expected}, got ${actual}`,
    );
  }

  await maybeVerifyCosign(base, checksumsFile, workdir);

  const extracted = await tc.extractTar(tarball, workdir);
  const binary = join(extracted, `reg-actions${ext}`);
  chmodSync(binary, 0o755);

  // The runner exposes inputs as `INPUT_<NAME>` with hyphens preserved
  // (e.g. `INPUT_GITHUB-TOKEN`), matching @actions/core's getInput() lookup.
  // The Rust binary expects the underscore form (`INPUT_GITHUB_TOKEN`), which
  // is what the old composite action.yml explicitly forwarded. Bridge the
  // convention gap here so the binary sees the env vars it expects.
  const env: Record<string, string> = {};
  for (const [key, value] of Object.entries(process.env)) {
    if (value === undefined) continue;
    env[key] = value;
    if (key.startsWith("INPUT_") && key.includes("-")) {
      env[key.replace(/-/g, "_")] = value;
    }
  }
  // ACTIONS_RUNTIME_TOKEN / ACTIONS_RESULTS_URL flow through env inheritance —
  // this is the whole reason for the JS shim.
  await runProcess(binary, [], { env });
}

run().catch((err: unknown) => {
  core.setFailed(err instanceof Error ? err.message : String(err));
});
