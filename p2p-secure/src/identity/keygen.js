/**
 * src/identity/keygen.js — Geração de chaves X3DH via libsodium
 *
 * Protocolo X3DH (Extended Triple Diffie-Hellman):
 *   IK  — Identity Key:     longo prazo (persistida)
 *   SPK — Signed PreKey:    médio prazo (rotacionada por epoch)
 *   OPK — One-Time PreKey:  uso único por sessão
 *
 * Segurança:
 *   - RNG health-checked (via rng.js)
 *   - Delay aleatório no keygen (mitiga timing side-channel)
 *   - Libsodium para todas as operações (constant-time)
 *   - Math.random() proibido por lint rule
 *
 * TODO (Etapa 2): integrar @signalapp/libsignal-client para
 *   implementação completa e auditada do X3DH com Ed25519.
 */
"use strict";

const sodium             = require("libsodium-wrappers");
const { secureRandomBytes, randomInt } = require("../crypto/rng.js");
const { zeroizeAll }     = require("../crypto/memory.js");

/** Delay aleatório 10–60ms para mitigar timing side-channel em keygen */
async function _secureDelay() {
  await new Promise((r) => setTimeout(r, 10 + randomInt(50)));
}

/**
 * Gera par de chaves Curve25519.
 * @returns {{ publicKey: Uint8Array, privateKey: Uint8Array }}
 */
async function generateKeyPair() {
  await sodium.ready;
  await _secureDelay();
  return sodium.crypto_kx_keypair();
}

/**
 * Gera conjunto completo de chaves X3DH para uma identidade.
 * @returns {object} IK + SPK (com assinatura) + 10 OPKs
 */
async function generateIdentityKeys() {
  await sodium.ready;
  console.log("[Keygen] Gerando chaves de identidade X3DH...");

  const ik   = await generateKeyPair(); // Identity Key (Curve25519 para ECDH)
  const spk  = await generateKeyPair(); // Signed PreKey
  const opks = await Promise.all(       // 10 One-Time PreKeys
    Array.from({ length: 10 }, () => generateKeyPair())
  );

  // Assinar SPK com IK: usa um par Ed25519 separado derivado da IK privada
  // crypto_kx_keypair retorna Curve25519 (32 bytes priv) — não compatível com crypto_sign_detached
  // Solução: gerar par Ed25519 de assinatura separado
  const ikSign = sodium.crypto_sign_keypair(); // Ed25519
  const spkSig = sodium.crypto_sign_detached(spk.publicKey, ikSign.privateKey);

  const result = {
    identityKey: {
      publicKey:  Buffer.from(ik.publicKey).toString("hex"),
      privateKey: Buffer.from(ik.privateKey).toString("hex"),
    },
    signedPreKey: {
      publicKey:  Buffer.from(spk.publicKey).toString("hex"),
      privateKey: Buffer.from(spk.privateKey).toString("hex"),
      signature:  Buffer.from(spkSig).toString("hex"),
    },
    oneTimePreKeys: opks.map((kp, i) => ({
      id:         i,
      publicKey:  Buffer.from(kp.publicKey).toString("hex"),
      privateKey: Buffer.from(kp.privateKey).toString("hex"),
    })),
    createdAt: Date.now(),
  };

  // Zeroizar cópias temporárias das chaves privadas após serialização
  zeroizeAll(ik.privateKey, spk.privateKey, ikSign.privateKey);
  opks.forEach((kp) => zeroizeAll(kp.privateKey));

  console.log("[Keygen] Chaves de identidade geradas ✓");
  return result;
}

module.exports = { generateIdentityKeys, generateKeyPair };
