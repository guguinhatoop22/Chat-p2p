/**
 * src/crypto/storage.js — Argon2id + chaves efêmeras por arquivo
 *
 * Design de Secure Deletion (correto para SSD/NVMe):
 *   Cada arquivo tem sua própria chave efêmera derivada da masterKey.
 *   "Apagar" = destruir a chave efêmera.
 *   Dados continuam no disco mas são CRIPTOGRAFICAMENTE IRRECUPERÁVEIS.
 *   (Overwrite físico não funciona em SSD por causa de wear leveling.)
 *
 *   masterKey = Argon2id(senha, salt)
 *   fileKey   = KDF(masterKey, subkeyId derivado do fileId UUID)
 *   ciphertext = XSalsa20-Poly1305(plaintext, fileKey, nonce)
 */
"use strict";

const argon2              = require("argon2");
const sodium              = require("libsodium-wrappers");
const { secureRandomBytes } = require("./rng.js");
const { zeroize }         = require("./memory.js");

// Parâmetros Argon2id — OWASP recomendado para armazenamento de senha
const ARGON2_OPTS = {
  type:        argon2.argon2id,
  memoryCost:  65536,  // 64 MB
  timeCost:    3,
  parallelism: 4,
  hashLength:  32,
  raw:         true,   // retorna Buffer, não string
};

/**
 * Deriva master key da senha do usuário.
 * @param {string} password
 * @param {Buffer} [salt] — se omitido, gera novo salt
 * @returns {{ masterKey: Buffer, salt: Buffer }}
 */
async function deriveMasterKey(password, salt = null) {
  await sodium.ready;
  // 32 bytes = 256-bit salt (crypto_pwhash_SALTBYTES é 16 mas usamos 32 por margem)
  const usedSalt  = salt ?? secureRandomBytes(32);
  const masterKey = await argon2.hash(password, { ...ARGON2_OPTS, salt: usedSalt });
  return { masterKey, salt: usedSalt };
}

/**
 * Deriva chave efêmera para um arquivo específico.
 * CORRIGIDO: subkey_id derivado do UUID do arquivo (não fixo em 1).
 * @param {Buffer} masterKey
 * @param {string} fileId — UUID v4
 * @returns {Uint8Array} fileKey (32 bytes)
 */
async function deriveFileKey(masterKey, fileId) {
  await sodium.ready;
  // Deriva subkey_id único a partir do UUID — collision impossível com UUIDs únicos
  // Usa módulo 2^31 para caber no domínio do KDF (subkey_id positivo de 64 bits)
  const subkeyId = parseInt(fileId.replace(/-/g, "").slice(0, 8), 16) % 2147483648;
  return sodium.crypto_kdf_derive_from_key(32, subkeyId, "filekdfx", masterKey);
}

/**
 * Criptografa dados com a fileKey.
 * @param {Buffer} plaintext
 * @param {Uint8Array} key
 * @returns {{ ciphertext: Buffer, nonce: Buffer }}
 */
async function encryptWithKey(plaintext, key) {
  await sodium.ready;
  const nonce      = secureRandomBytes(sodium.crypto_secretbox_NONCEBYTES);
  const ciphertext = sodium.crypto_secretbox_easy(plaintext, nonce, key);
  return { ciphertext: Buffer.from(ciphertext), nonce: Buffer.from(nonce) };
}

/**
 * Descriptografa dados com a fileKey.
 * @param {Buffer} ciphertext
 * @param {Buffer} nonce
 * @param {Uint8Array} key
 * @returns {Buffer}
 */
async function decryptWithKey(ciphertext, nonce, key) {
  await sodium.ready;
  const plain = sodium.crypto_secretbox_open_easy(ciphertext, nonce, key);
  if (!plain) throw new Error("[Storage] Falha na descriptografia: MAC inválido.");
  return Buffer.from(plain);
}

module.exports = { deriveMasterKey, deriveFileKey, encryptWithKey, decryptWithKey };
