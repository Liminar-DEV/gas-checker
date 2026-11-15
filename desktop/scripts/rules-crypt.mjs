// Encrypts / decrypts the private detection rules. Plain node, built-in crypto only.
//   node scripts/rules-crypt.mjs genkey            new key (64 hex) to stdout, written nowhere
//   node scripts/rules-crypt.mjs encrypt           private/rules_private.rs -> rules/rules_private.rs.enc
//   node scripts/rules-crypt.mjs decrypt [outfile] rules/rules_private.rs.enc -> stdout or outfile
// The key comes from GASCHECKER_RULES_KEY. Format (same as build.rs): 12-byte nonce || ciphertext || 16-byte tag.
import { createCipheriv, createDecipheriv, randomBytes } from "node:crypto";
import { mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const root = join(dirname(fileURLToPath(import.meta.url)), "..", "src-tauri");
const plainPath = join(root, "private", "rules_private.rs");
const encPath = join(root, "rules", "rules_private.rs.enc");

function fail(message) {
  console.error(message);
  process.exit(1);
}

function key() {
  const hex = (process.env.GASCHECKER_RULES_KEY ?? "").trim();
  if (!/^[0-9a-fA-F]{64}$/.test(hex)) fail("GASCHECKER_RULES_KEY must be 64 hex characters (run `npm run rules:genkey`).");
  return Buffer.from(hex, "hex");
}

const [command, outfile] = process.argv.slice(2);

if (command === "genkey") {
  console.log(randomBytes(32).toString("hex"));
} else if (command === "encrypt") {
  const nonce = randomBytes(12);
  const cipher = createCipheriv("aes-256-gcm", key(), nonce);
  const body = Buffer.concat([cipher.update(readFileSync(plainPath)), cipher.final()]);
  mkdirSync(dirname(encPath), { recursive: true });
  writeFileSync(encPath, Buffer.concat([nonce, body, cipher.getAuthTag()]));
  console.error(`written ${encPath}`);
} else if (command === "decrypt") {
  const blob = readFileSync(encPath);
  if (blob.length < 28) fail("rules_private.rs.enc is too short");
  const decipher = createDecipheriv("aes-256-gcm", key(), blob.subarray(0, 12));
  decipher.setAuthTag(blob.subarray(blob.length - 16));
  let plain;
  try {
    plain = Buffer.concat([decipher.update(blob.subarray(12, blob.length - 16)), decipher.final()]);
  } catch {
    fail("wrong key or corrupted file");
  }
  if (outfile) writeFileSync(outfile, plain);
  else process.stdout.write(plain);
} else {
  fail("usage: rules-crypt.mjs genkey | encrypt | decrypt [outfile]");
}
