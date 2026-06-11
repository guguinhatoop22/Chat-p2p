"use strict";

/**
 * src/crypto/x3dh.js — Extended Triple Diffie-Hellman (simplificado)
 *
 * Deriva um segredo compartilhado de 32 bytes entre dois peers.
 * Ambos os lados chegam ao mesmo SharedSecret sem nunca transmiti-lo.
 *
 * Protocolo usado (versão simplificada sobre Curve25519 via libsodium):
 *
 *   Initiator tem:  IK_i (identity), EK_i (ephemeral — gerada na hora)
 *   Responder tem:  IK_r (identity), SPK_r (signed pre-key)
 *
 *   DH1 = DH(IK_i.priv, SPK_r.pub)   — autenticidade longo-prazo
 *   DH2 = DH(EK_i.priv, IK_r.pub)    — forward secrecy longo-prazo
 *   DH3 = DH(EK_i.priv, SPK_r.pub)   — forward secrecy curto-prazo
 *
 *   sharedSecret = HKDF-SHA256(DH1 || DH2 || DH3, salt="P2PSecureX3DH")
 *
 * Nota:
 *   crypto_kx_* do libsodium usa X25519 (ECDH sobre Curve25519).
 *   Não tem OPK nesta etapa — adicionado na Etapa 4 com libsignal.
 */

const sodium         = require("libsodium-wrappers");
const { createHmac } = require("node:crypto");
const { zeroizeAll } = require("./memory.js");

const HKDF_INFO = Buffer.from("P2PSecureX3DH-v1");
const HKDF_SALT = Buffer.from("P2PSecureChat-X3DH-2026", "utf8");

async function _ensureSodium() {
  await sodium.ready;
}

/**
 * HKDF-SHA256 simplificado (Extract+Expand, 32 bytes de saída).
 * @param {Uint8Array} ikm    — input keying material (concatenação dos DHs)
 * @param {Buffer}     salt
 * @param {Buffer}     info
 * @returns {Buffer} 32 bytes
 */
function _hkdf32(ikm, salt, info) {
  // Extract
  const prk = createHmac("sha256", salt).update(ikm).digest();
  // Expand (1 bloco = 32 bytes, suficiente)
  const okm = createHmac("sha256", prk)
    .update(Buffer.concat([info, Buffer.from([0x01])]))
    .digest();
  return okm;
}

/**
 * ECDH Curve25519 entre duas chaves (formato libsodium crypto_kx).
 * Retorna 32 bytes do ponto compartilhado.
 */
function _dh(myPriv, theirPub) {
  // crypto_scalarmult: multiplicação X25519
  return sodium.crypto_scalarmult(myPriv, theirPub);
}

/**
 * Initiator: gera EK efêmera e calcula segredo compartilhado.
 *
 * @param {object} myIdentityKey      — { privateKey: hex, publicKey: hex }
 * @param {object} theirIdentityKey   — { publicKey: hex }
 * @param {object} theirSignedPreKey  — { publicKey: hex }
 * @returns {{ sharedSecret: Buffer, ephemeralPublicKey: string }}
 */
async function x3dhInitiator(myIdentityKey, theirIdentityKey, theirSignedPreKey, ephemeralKeyPair = null) {
  await _ensureSodium();

  // Usa EK fornecida (do handshake) ou gera uma nova
  const ek = ephemeralKeyPair ?? sodium.crypto_kx_keypair();

  const ikPriv  = Buffer.from(myIdentityKey.privateKey,     "hex");
  const ikrPub  = Buffer.from(theirIdentityKey.publicKey,   "hex");
  const spkrPub = Buffer.from(theirSignedPreKey.publicKey,  "hex");

  const dh1 = _dh(ikPriv,        spkrPub); // IK_i × SPK_r
  const dh2 = _dh(ek.privateKey, ikrPub);  // EK_i × IK_r
  const dh3 = _dh(ek.privateKey, spkrPub); // EK_i × SPK_r

  const ikm = Buffer.concat([
    Buffer.from(dh1),
    Buffer.from(dh2),
    Buffer.from(dh3),
  ]);

  const sharedSecret = _hkdf32(ikm, HKDF_SALT, HKDF_INFO);

  // Zeroizar material sensível imediatamente
  zeroizeAll(ikPriv, ek.privateKey, dh1, dh2, dh3, ikm);

  return {
    sharedSecret,
    ephemeralPublicKey: Buffer.from(ek.publicKey).toString("hex"),
  };
}

/**
 * Responder: calcula o mesmo segredo compartilhado com a EK recebida.
 *
 * @param {object} myIdentityKey     — { privateKey: hex, publicKey: hex }
 * @param {object} mySignedPreKey    — { privateKey: hex, publicKey: hex }
 * @param {object} theirIdentityKey  — { publicKey: hex }
 * @param {string} ephemeralPublicKey — hex (vem do handshake)
 * @returns {Buffer} sharedSecret 32 bytes
 */
async function x3dhResponder(myIdentityKey, mySignedPreKey, theirIdentityKey, ephemeralPublicKey) {
  await _ensureSodium();

  const spkPriv = Buffer.from(mySignedPreKey.privateKey,   "hex");
  const ikPriv  = Buffer.from(myIdentityKey.privateKey,    "hex");
  const ikiPub  = Buffer.from(theirIdentityKey.publicKey,  "hex");
  const ekiPub  = Buffer.from(ephemeralPublicKey,          "hex");

  const dh1 = _dh(spkPriv, ikiPub);  // SPK_r × IK_i
  const dh2 = _dh(ikPriv,  ekiPub);  // IK_r  × EK_i
  const dh3 = _dh(spkPriv, ekiPub);  // SPK_r × EK_i

  const ikm = Buffer.concat([
    Buffer.from(dh1),
    Buffer.from(dh2),
    Buffer.from(dh3),
  ]);

  const sharedSecret = _hkdf32(ikm, HKDF_SALT, HKDF_INFO);

  zeroizeAll(spkPriv, ikPriv, dh1, dh2, dh3, ikm);

  return sharedSecret;
}

module.exports = { x3dhInitiator, x3dhResponder };
