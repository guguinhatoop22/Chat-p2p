"use strict";

/**
 * src/persistence/identity-store.js — Persistência de chaves de identidade
 *
 * As chaves X3DH são geradas uma vez e persistidas criptografadas em disco.
 * Sem isso, cada restart gera novas chaves → incompatível com peers anteriores.
 *
 * Proteção:
 *   - masterKey = Argon2id(deviceSecret, salt)
 *   - deviceSecret = 32 bytes aleatórios armazenados em ~/.p2p-secure/device.key
 *     (chmod 600 — protege contra acesso remoto não autorizado)
 *   - Identidade cifrada com XSalsa20-Poly1305 via storage.js
 *
 * Arquivo: ~/.p2p-secure/identity.enc
 *   { salt: hex, nonce: hex, fileId: string, ciphertext: hex }
 */

const fs   = require("node:fs");
const path = require("node:path");
const os   = require("node:os");
const { randomUUID }    = require("node:crypto");
const { secureRandomBytes } = require("../crypto/rng.js");
const { deriveMasterKey, deriveFileKey, encryptWithKey, decryptWithKey } = require("../crypto/storage.js");
const { zeroize } = require("../crypto/memory.js");

const DATA_DIR       = path.join(os.homedir(), ".p2p-secure");
const DEVICE_KEY_FILE = path.join(DATA_DIR, "device.key");
const IDENTITY_FILE  = path.join(DATA_DIR, "identity.enc");

// Garante que o diretório de dados existe com permissões restritas
if (!fs.existsSync(DATA_DIR)) fs.mkdirSync(DATA_DIR, { recursive: true, mode: 0o700 });

/**
 * Carrega ou gera o segredo do dispositivo (32 bytes).
 * Armazenado em DEVICE_KEY_FILE com modo 0o600.
 */
function _loadDeviceSecret() {
  if (fs.existsSync(DEVICE_KEY_FILE)) {
    const buf = fs.readFileSync(DEVICE_KEY_FILE);
    if (buf.length === 32) return buf;
  }
  // Primeiro boot — gerar segredo novo
  const secret = Buffer.from(secureRandomBytes(32));
  fs.writeFileSync(DEVICE_KEY_FILE, secret, { mode: 0o600 });
  console.log("[IdentityStore] Device secret gerado ✓");
  return secret;
}

/**
 * Carrega identidade salva em disco, ou null se não houver.
 * @returns {object|null} — { identityKey, signedPreKey, oneTimePreKeys, createdAt }
 */
async function loadIdentity() {
  if (!fs.existsSync(IDENTITY_FILE)) return null;

  try {
    const meta = JSON.parse(fs.readFileSync(IDENTITY_FILE, "utf8"));
    const deviceSecret = _loadDeviceSecret();

    const { masterKey, salt: _s } = await deriveMasterKey(
      deviceSecret.toString("hex"),
      Buffer.from(meta.salt, "hex"),
    );

    const fileKey = await deriveFileKey(masterKey, meta.fileId);
    zeroize(masterKey);

    const plain = await decryptWithKey(
      Buffer.from(meta.ciphertext, "hex"),
      Buffer.from(meta.nonce, "hex"),
      fileKey,
    );
    zeroize(fileKey);

    const identity = JSON.parse(plain.toString("utf8"));
    console.log("[IdentityStore] Identidade carregada do disco ✓");
    return identity;
  } catch (err) {
    console.error("[IdentityStore] Falha ao carregar identidade:", err.message);
    return null;
  }
}

/**
 * Salva identidade em disco criptografada.
 * @param {object} identity — { identityKey, signedPreKey, oneTimePreKeys, createdAt }
 */
async function saveIdentity(identity) {
  const deviceSecret = _loadDeviceSecret();
  const fileId = randomUUID();

  const { masterKey, salt } = await deriveMasterKey(deviceSecret.toString("hex"));
  const fileKey = await deriveFileKey(masterKey, fileId);
  zeroize(masterKey);

  // Exclui chaves privadas das OPKs do que é salvo em texto — guarda apenas IK e SPK
  // (simplificação Etapa 4: OPKs regeneradas de IK via KDF se necessário)
  const toSave = {
    identityKey:  identity.identityKey,
    signedPreKey: identity.signedPreKey,
    createdAt:    identity.createdAt,
  };

  const plain = Buffer.from(JSON.stringify(toSave), "utf8");
  const { ciphertext, nonce } = await encryptWithKey(plain, fileKey);
  zeroize(fileKey);

  const meta = {
    fileId,
    salt:       salt.toString("hex"),
    nonce:      nonce.toString("hex"),
    ciphertext: ciphertext.toString("hex"),
    version:    1,
  };

  fs.writeFileSync(IDENTITY_FILE, JSON.stringify(meta), { mode: 0o600 });
  console.log("[IdentityStore] Identidade salva em disco ✓");
}

module.exports = { loadIdentity, saveIdentity };
