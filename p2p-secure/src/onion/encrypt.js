/**
 * src/onion/encrypt.js — Criptografia em camadas (onion)
 *
 * Cada hop do circuito adiciona/remove uma camada de criptografia.
 * Resultado: cada relay vê apenas a próxima instrução de roteamento.
 * Nenhum relay vê origem + destino simultaneamente.
 *
 * Encrypt: payload → encrypt(hopN) → ... → encrypt(hop1) → wire
 * Decrypt: wire → decrypt(hop1) → ... → decrypt(hopN) → plaintext
 *
 * Usa XSalsa20-Poly1305 via libsodium (constant-time) para cada camada.
 *
 * TODO (Etapa 5): integrar com path-key.js para chaves derivadas por HKDF
 *   e circuit_id.
 */
"use strict";

const sodium             = require("libsodium-wrappers");
const { secureRandomBytes } = require("../crypto/rng.js");

/**
 * Aplica N camadas de criptografia (do último hop para o primeiro).
 * @param {Buffer}       payload
 * @param {Uint8Array[]} layerKeys — [hop1, hop2, ..., hopN]
 * @returns {{ encrypted: Buffer, nonces: Buffer[] }}
 */
async function onionEncrypt(payload, layerKeys) {
  await sodium.ready;
  let current  = payload;
  const nonces = [];
  for (let i = layerKeys.length - 1; i >= 0; i--) {
    const nonce = secureRandomBytes(sodium.crypto_secretbox_NONCEBYTES);
    current     = Buffer.from(sodium.crypto_secretbox_easy(current, nonce, layerKeys[i]));
    nonces.unshift(Buffer.from(nonce));
  }
  return { encrypted: current, nonces };
}

/**
 * Remove uma camada de criptografia (usado por cada relay individualmente).
 * @param {Buffer}     data
 * @param {Uint8Array} key
 * @param {Buffer}     nonce
 * @returns {Buffer}
 */
async function onionPeel(data, key, nonce) {
  await sodium.ready;
  const plain = sodium.crypto_secretbox_open_easy(data, nonce, key);
  if (!plain) throw new Error("[Onion] Falha ao remover camada: MAC inválido");
  return Buffer.from(plain);
}

module.exports = { onionEncrypt, onionPeel };
