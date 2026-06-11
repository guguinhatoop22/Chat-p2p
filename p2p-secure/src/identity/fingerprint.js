/**
 * src/identity/fingerprint.js — Verificação de identidade via QR
 *
 * Permite que dois usuários verifiquem identidade via QR code
 * ou sequência de palavras — igual ao Signal Safety Numbers.
 * Se o fingerprint não bater: MITM ativo.
 *
 * Algoritmo:
 *   fingerprint = SHA-256(sort(pubKeyA, pubKeyB) || sessionId)[0:15]
 *   → Base32 (RFC 4648) → grupos de 5 chars → QR code
 *
 * UX crítica: alerta BLOQUEANTE se identidade do peer mudar entre sessões.
 */
"use strict";

const { createHash }  = require("node:crypto");
const QRCode          = require("qrcode");
const sodium          = require("libsodium-wrappers");

const B32 = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

function _toBase32(buf) {
  let out = "", bits = 0, val = 0;
  for (const b of buf) {
    val  = (val << 8) | b;
    bits += 8;
    while (bits >= 5) { out += B32[(val >>> (bits - 5)) & 31]; bits -= 5; }
  }
  return out;
}

/**
 * Gera fingerprint de segurança para um par de peers.
 * Ambos os lados chegam ao mesmo resultado (ordem-independente).
 * @param {string} pubKeyA — hex
 * @param {string} pubKeyB — hex
 * @param {string} sessionId
 * @returns {string} ex: "ABCDE FGHIJ KLMNO PQRST UVWXY"
 */
function generateFingerprint(pubKeyA, pubKeyB, sessionId) {
  const [lo, hi] = [pubKeyA, pubKeyB].sort(); // ordem determinística
  const hash = createHash("sha256").update(lo).update(hi).update(sessionId).digest();
  return _toBase32(hash.slice(0, 15)).match(/.{1,5}/g).join(" ");
}

/**
 * Gera QR code com o fingerprint para scan entre peers.
 * @param {string} fingerprint
 * @returns {Promise<string>} data URL PNG
 */
async function generateFingerprintQR(fingerprint) {
  return QRCode.toDataURL(fingerprint, { errorCorrectionLevel: "H", width: 300, margin: 2 });
}

/**
 * Comparação constant-time via sodium.memcmp.
 * Evita timing attack na verificação de identidade.
 * Fallback manual constant-time se sodium não estiver disponível.
 * @param {string} fpA
 * @param {string} fpB
 * @returns {Promise<boolean>}
 */
async function compareFingerprints(fpA, fpB) {
  if (!fpA || !fpB || fpA.length !== fpB.length) return false;
  const bufA = Buffer.from(fpA, "utf8");
  const bufB = Buffer.from(fpB, "utf8");
  try {
    await sodium.ready;
    return sodium.memcmp(bufA, bufB); // constant-time
  } catch {
    // Fallback: comparação byte-a-byte constant-time manual
    let diff = 0;
    for (let i = 0; i < bufA.length; i++) diff |= bufA[i] ^ bufB[i];
    return diff === 0;
  }
}

module.exports = { generateFingerprint, generateFingerprintQR, compareFingerprints };
