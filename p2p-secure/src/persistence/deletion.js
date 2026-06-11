/**
 * src/persistence/deletion.js — Secure Deletion via destruição de chave
 *
 * SSD/NVMe não apaga dados fisicamente — overwrite físico NÃO funciona.
 * Solução correta:
 *   Cada mensagem é criptografada com sua própria chave efêmera.
 *   "Apagar" = destruir a chave efêmera.
 *   Os dados cifrados ficam no disco, mas são CRIPTOGRAFICAMENTE IRRECUPERÁVEIS.
 *
 * Fluxo:
 *   Salvar: gerar fileKey → cifrar → salvar ciphertext + registrar fileKey
 *   Apagar: zeroizar fileKey → deletar do keystore
 */
"use strict";

const { zeroize } = require("../crypto/memory.js");

const _keyStore = new Map(); // fileId → fileKey (Uint8Array)

/** Registra a fileKey de um arquivo no keystore. */
function registerFileKey(fileId, fileKey) {
  _keyStore.set(fileId, fileKey);
}

/** Recupera a fileKey de um arquivo. */
function getFileKey(fileId) {
  return _keyStore.get(fileId) ?? null;
}

/**
 * Apaga um arquivo destruindo sua chave efêmera.
 * @param {string} fileId
 * @returns {boolean} true se a chave existia e foi destruída
 */
function secureDelete(fileId) {
  const key = _keyStore.get(fileId);
  if (!key) { console.warn(`[Deletion] fileKey não encontrada: ${fileId}`); return false; }
  zeroize(key);
  _keyStore.delete(fileId);
  console.log(`[Deletion] Chave de ${fileId} destruída — dados irrecuperáveis ✓`);
  return true;
}

/** Zeroiza todas as chaves (usar no shutdown do daemon). */
function secureDeleteAll() {
  for (const [fileId, key] of _keyStore) { zeroize(key); _keyStore.delete(fileId); }
  console.log("[Deletion] Todas as chaves efêmeras destruídas ✓");
}

module.exports = { registerFileKey, getFileKey, secureDelete, secureDeleteAll };
