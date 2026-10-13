"use strict";

const crypto = require("node:crypto");

const LIMITS = Object.freeze({
  cborBytes: 16384,
  clientDataBytes: 8192,
  credentialIdBytes: 512,
  minimumCredentialIdBytes: 16,
  cborItems: 256,
  cborDepth: 8,
  cborContainerItems: 64,
  coseCoordinateBytes: 32,
  rsaMinimumBits: 2048,
  rsaMaximumBits: 4096
});

class ContractError extends Error {
  constructor(code) {
    super(`WebAuthn contract rejected: ${code}`);
    this.name = "ContractError";
    this.code = code;
  }
}

function reject(code) {
  throw new ContractError(code);
}

function readCborLength(bytes, state, additional) {
  if (additional < 24) return additional;
  const sizes = new Map([[24, 1], [25, 2], [26, 4], [27, 8]]);
  const size = sizes.get(additional);
  if (!size) reject("indefinite_or_reserved_cbor_length");
  if (state.offset + size > bytes.length) reject("truncated_cbor");
  let value = 0n;
  for (let index = 0; index < size; index++) {
    value = (value << 8n) | BigInt(bytes[state.offset++]);
  }
  if (value > BigInt(Number.MAX_SAFE_INTEGER)) reject("cbor_length_overflow");
  const number = Number(value);
  if ((size === 1 && number < 24) ||
      (size === 2 && number <= 0xff) ||
      (size === 4 && number <= 0xffff) ||
      (size === 8 && number <= 0xffffffff)) {
    reject("non_minimal_cbor_integer");
  }
  return number;
}

function decodeCborStrict(input) {
  const bytes = Buffer.from(input);
  if (bytes.length < 1 || bytes.length > LIMITS.cborBytes) {
    reject("cbor_input_length");
  }
  const state = { offset: 0, items: 0 };

  function decode(depth) {
    if (depth > LIMITS.cborDepth) reject("cbor_nesting_limit");
    if (++state.items > LIMITS.cborItems) reject("cbor_item_limit");
    if (state.offset >= bytes.length) reject("truncated_cbor");
    const initial = bytes[state.offset++];
    const major = initial >> 5;
    const additional = initial & 31;

    if (major === 7) {
      if (additional === 20) return false;
      if (additional === 21) return true;
      if (additional === 22) return null;
      reject("unsupported_cbor_simple_value");
    }

    const length = readCborLength(bytes, state, additional);
    if (major === 0 || major === 1) {
      return major === 0 ? length : -1 - length;
    }
    if (major === 2 || major === 3) {
      if (length > LIMITS.cborBytes || state.offset + length > bytes.length) {
        reject("truncated_or_oversized_cbor_string");
      }
      const part = bytes.subarray(state.offset, state.offset + length);
      state.offset += length;
      if (major === 2) return Buffer.from(part);
      try {
        return new TextDecoder("utf-8", { fatal: true }).decode(part);
      } catch {
        reject("invalid_cbor_utf8");
      }
    }
    if (major === 4) {
      if (length > LIMITS.cborContainerItems) reject("cbor_array_limit");
      return Array.from({ length }, () => decode(depth + 1));
    }
    if (major === 5) {
      if (length > LIMITS.cborContainerItems) reject("cbor_map_limit");
      const result = new Map();
      const seen = new Set();
      for (let index = 0; index < length; index++) {
        const key = decode(depth + 1);
        if (!(typeof key === "string" || Number.isSafeInteger(key))) {
          reject("unsupported_cbor_map_key");
        }
        const identity = `${typeof key}:${String(key)}`;
        if (seen.has(identity)) reject("duplicate_cbor_map_key");
        seen.add(identity);
        result.set(key, decode(depth + 1));
      }
      return result;
    }
    reject("unsupported_cbor_type");
  }

  const value = decode(0);
  if (state.offset !== bytes.length) reject("trailing_cbor_bytes");
  return value;
}

function strictBase64Url(value, minimum, maximum) {
  if (typeof value !== "string" || !/^[A-Za-z0-9_-]+$/.test(value) ||
      value.length > Math.ceil(maximum * 4 / 3) + 2) {
    reject("invalid_base64url");
  }
  const bytes = Buffer.from(value, "base64url");
  if (bytes.length < minimum || bytes.length > maximum ||
      bytes.toString("base64url") !== value) reject("invalid_base64url");
  return bytes;
}

function parseCredentialId(value) {
  return strictBase64Url(value, LIMITS.minimumCredentialIdBytes,
    LIMITS.credentialIdBytes);
}

function requiredMapKeys(map, keys, code) {
  if (!(map instanceof Map) || map.size !== keys.length ||
      keys.some(key => !map.has(key))) reject(code);
}

function b64url(bytes) {
  return Buffer.from(bytes).toString("base64url");
}

function parseCosePublicKey(cose) {
  if (!(cose instanceof Map)) reject("cose_key_not_map");
  const kty = cose.get(1);
  const algorithm = cose.get(3);

  if (kty === 2 && algorithm === -7) {
    requiredMapKeys(cose, [1, 3, -1, -2, -3], "invalid_es256_cose_key");
    const curve = cose.get(-1);
    const x = cose.get(-2);
    const y = cose.get(-3);
    if (curve !== 1 || !Buffer.isBuffer(x) || !Buffer.isBuffer(y) ||
        x.length !== LIMITS.coseCoordinateBytes ||
        y.length !== LIMITS.coseCoordinateBytes) reject("invalid_es256_curve_or_coordinates");
    let key;
    try {
      key = crypto.createPublicKey({
        key: { kty: "EC", crv: "P-256", x: b64url(x), y: b64url(y) },
        format: "jwk"
      });
    } catch {
      reject("invalid_es256_point");
    }
    return { algorithm, publicKey: key.export({ type: "spki", format: "pem" }) };
  }

  if (kty === 3 && algorithm === -257) {
    requiredMapKeys(cose, [1, 3, -1, -2], "invalid_rs256_cose_key");
    const modulus = cose.get(-1);
    const exponent = cose.get(-2);
    if (!Buffer.isBuffer(modulus) || !Buffer.isBuffer(exponent) ||
        modulus.length < LIMITS.rsaMinimumBits / 8 ||
        modulus.length > LIMITS.rsaMaximumBits / 8 ||
        modulus[0] === 0 || exponent.length < 1 || exponent.length > 4 ||
        exponent[0] === 0) reject("invalid_rs256_key_size");
    const bits = (modulus.length - 1) * 8 +
      (32 - Math.clz32(modulus[0]));
    const exponentValue = exponent.reduce((value, byte) => value * 256 + byte, 0);
    if (bits < LIMITS.rsaMinimumBits || bits > LIMITS.rsaMaximumBits ||
        exponentValue < 3 || exponentValue % 2 !== 1 ||
        !Number.isSafeInteger(exponentValue)) reject("invalid_rs256_parameters");
    let key;
    try {
      key = crypto.createPublicKey({
        key: { kty: "RSA", n: b64url(modulus), e: b64url(exponent) },
        format: "jwk"
      });
    } catch {
      reject("invalid_rs256_public_key");
    }
    return { algorithm, publicKey: key.export({ type: "spki", format: "pem" }) };
  }

  reject("unsupported_cose_algorithm_or_key_type");
}

function parseRegistrationClientData(input, expected) {
  const bytes = Buffer.from(input);
  if (bytes.length < 2 || bytes.length > LIMITS.clientDataBytes) {
    reject("client_data_length");
  }
  let value;
  try {
    value = JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(bytes));
  } catch {
    reject("invalid_client_data_json");
  }
  if (!value || Array.isArray(value) || typeof value !== "object" ||
      value.type !== "webauthn.create" ||
      value.challenge !== expected.challenge ||
      value.origin !== expected.origin ||
      (value.crossOrigin !== undefined && value.crossOrigin !== false) ||
      Object.keys(value).some(key =>
        !["type", "challenge", "origin", "crossOrigin"].includes(key))) {
    reject("registration_client_data_mismatch");
  }
  return { bytes, value };
}

function parseRegistration(input, expected) {
  if (!input || !Buffer.isBuffer(input.clientDataJSON) ||
      !Buffer.isBuffer(input.attestationObject) ||
      typeof expected?.rpId !== "string" ||
      typeof expected?.origin !== "string" ||
      typeof expected?.challenge !== "string") reject("invalid_registration_input");

  const client = parseRegistrationClientData(input.clientDataJSON, expected);
  const attestation = decodeCborStrict(input.attestationObject);
  requiredMapKeys(attestation, ["fmt", "attStmt", "authData"],
    "invalid_attestation_object");
  if (attestation.get("fmt") !== "none" ||
      !(attestation.get("attStmt") instanceof Map) ||
      attestation.get("attStmt").size !== 0) reject("unsupported_attestation_format");

  const auth = attestation.get("authData");
  if (!Buffer.isBuffer(auth) || auth.length < 55 || auth.length > LIMITS.cborBytes) {
    reject("authenticator_data_length");
  }
  const expectedRpHash = crypto.createHash("sha256").update(expected.rpId, "utf8").digest();
  if (!crypto.timingSafeEqual(auth.subarray(0, 32), expectedRpHash)) {
    reject("registration_rp_id_hash_mismatch");
  }
  const flags = auth[32];
  if ((flags & 0x05) !== 0x05 || (flags & 0x40) === 0 || (flags & 0x80) !== 0) {
    reject("registration_flags");
  }
  const credentialLength = auth.readUInt16BE(53);
  const credentialStart = 55;
  const credentialEnd = credentialStart + credentialLength;
  if (credentialLength < LIMITS.minimumCredentialIdBytes ||
      credentialLength > LIMITS.credentialIdBytes ||
      credentialEnd >= auth.length) reject("registration_credential_id_length");
  const credentialId = Buffer.from(auth.subarray(credentialStart, credentialEnd));
  const cose = decodeCborStrict(auth.subarray(credentialEnd));
  const key = parseCosePublicKey(cose);

  return Object.freeze({
    credentialId: credentialId.toString("base64url"),
    algorithm: key.algorithm,
    publicKey: key.publicKey,
    clientDataJSON: Buffer.from(client.bytes),
    rpId: expected.rpId
  });
}

module.exports = {
  ContractError,
  LIMITS,
  decodeCborStrict,
  parseCredentialId,
  parseCosePublicKey,
  parseRegistration
};
