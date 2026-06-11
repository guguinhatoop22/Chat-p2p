"use strict";

/**
 * src/persistence/chat-store.js — Histórico de chat criptografado por peer
 *
 * Cada peer tem seu próprio arquivo de histórico:
 *   ~/.p2p-secure/chats/<peerIdHex8>.enc
 *
 * Formato em disco:
 *   { fileId, salt, nonce, ciphertext }  → JSON array de mensagens
 *
 * Proteção:
 *   - Mesmo esquema da identity-store: Argon2id(deviceSecret) → fileKey
 *   - Uma fileKey por arquivo de chat (por peer)
 *   - Deletar conversa = zeroizar fileKey → dados irrecuperáveis
 *
 * Limitação intencional: máximo de MAX_MESSAGES por peer em memória.
 * Mensagens mais antigas são truncadas (não paginação por ora).
 */

const fs   = require("node:fs");
const path = require("node:path");
const os   = require("node:os");
const { randomUUID }    = require("node:crypto");
const { secureRandomBytes } = require("../crypto/rng.js");
const { deriveMasterKey, deriveFileKey, encryptWithKey, decryptWithKey } = require("../crypto/storage.js");
const { registerFileKey, getFileKey, secureDelete } = require("./deletion.js");
const { zeroize } = require("../crypto/memory.js");

const DATA_DIR    = path.join(os.homedir(), ".p2p-secure");
const CHATS_DIR   = path.join(DATA_DIR, "chats");
const DEVICE_KEY_FILE = path.join(DATA_DIR, "device.key");
const MAX_MESSAGES = 500;

if (!fs.existsSync(CHATS_DIR)) fs.mkdirSync(CHATS_DIR, { recursive: true, mode: 0o700 });

// Cache em memória: Map<peerId string, Message[]>
const _cache   = new Map();
// Map de fileId por peer (para derivar fileKey)
const _fileMeta = new Map(); // peerId → { fileId, salt }

function _deviceSecret() {
  if (fs.existsSync(DEVICE_KEY_FILE)) {
    const buf = fs.readFileSync(DEVICE_KEY_FILE);
    if (buf.length === 32) return buf;
  }
  // Fallback: identity-store já criou, mas se não existir:
  const s = Buffer.from(secureRandomBytes(32));
  fs.writeFileSync(DEVICE_KEY_FILE, s, { mode: 0o600 });
  return s;
}

function _chatFile(peerId) {
  // Usa últimos 16 chars do peerId como nome de arquivo (não expõe PeerId completo)
  const safe = peerId.replace(/[^a-zA-Z0-9]/g, "").slice(-16);
  return path.join(CHATS_DIR, `${safe}.enc`);
}

function _metaFile(peerId) {
  const safe = peerId.replace(/[^a-zA-Z0-9]/g, "").slice(-16);
  return path.join(CHATS_DIR, `${safe}.meta`);
}

// ── Load ──────────────────────────────────────────────────────────────────

/**
 * Carrega histórico de chat de um peer do disco.
 * @param {string} peerId
 * @returns {object[]} array de mensagens (pode ser vazio)
 */
async function loadHistory(peerId) {
  if (_cache.has(peerId)) return _cache.get(peerId);

  const metaPath = _metaFile(peerId);
  const chatPath = _chatFile(peerId);

  if (!fs.existsSync(metaPath) || !fs.existsSync(chatPath)) {
    _cache.set(peerId, []);
    return [];
  }

  try {
    const meta   = JSON.parse(fs.readFileSync(metaPath, "utf8"));
    const secret = _deviceSecret();

    const { masterKey } = await deriveMasterKey(secret.toString("hex"), Buffer.from(meta.salt, "hex"));
    const fileKey = await deriveFileKey(masterKey, meta.fileId);
    zeroize(masterKey);

    // Registra no keystore (para deleção segura futura)
    registerFileKey(meta.fileId, fileKey);
    _fileMeta.set(peerId, meta);

    const enc   = JSON.parse(fs.readFileSync(chatPath, "utf8"));
    const plain = await decryptWithKey(
      Buffer.from(enc.ciphertext, "hex"),
      Buffer.from(enc.nonce, "hex"),
      fileKey,
      // NÃO zeroiza fileKey aqui — ainda precisamos dela para salvar
    );

    const messages = JSON.parse(plain.toString("utf8"));
    _cache.set(peerId, messages);
    console.log(`[ChatStore] ${messages.length} mensagens carregadas para ${peerId.slice(-8)}`);
    return messages;
  } catch (err) {
    console.error(`[ChatStore] Falha ao carregar histórico de ${peerId.slice(-8)}:`, err.message);
    _cache.set(peerId, []);
    return [];
  }
}

// ── Save ──────────────────────────────────────────────────────────────────

/**
 * Adiciona mensagem ao histórico e persiste em disco.
 * @param {string} peerId
 * @param {{ from: string, text: string, ts: number, encrypted: boolean }} msg
 */
async function appendMessage(peerId, msg) {
  if (!_cache.has(peerId)) _cache.set(peerId, []);
  const history = _cache.get(peerId);

  history.push(msg);
  // Truncar se exceder limite
  if (history.length > MAX_MESSAGES) history.splice(0, history.length - MAX_MESSAGES);

  await _persist(peerId, history);
}

async function _persist(peerId, messages) {
  try {
    const secret = _deviceSecret();
    let meta     = _fileMeta.get(peerId);
    let fileKey;

    if (!meta) {
      // Primeiro save para este peer — gerar fileId e salt
      const fileId = randomUUID();
      const { masterKey, salt } = await deriveMasterKey(secret.toString("hex"));
      fileKey = await deriveFileKey(masterKey, fileId);
      zeroize(masterKey);
      meta = { fileId, salt: salt.toString("hex") };
      _fileMeta.set(peerId, meta);
      registerFileKey(fileId, fileKey);
      fs.writeFileSync(_metaFile(peerId), JSON.stringify(meta), { mode: 0o600 });
    } else {
      fileKey = getFileKey(meta.fileId);
      if (!fileKey) {
        // fileKey foi perdida (ex: restart sem carregar) — recarregar
        const { masterKey } = await deriveMasterKey(secret.toString("hex"), Buffer.from(meta.salt, "hex"));
        fileKey = await deriveFileKey(masterKey, meta.fileId);
        zeroize(masterKey);
        registerFileKey(meta.fileId, fileKey);
      }
    }

    const plain = Buffer.from(JSON.stringify(messages), "utf8");
    const { ciphertext, nonce } = await encryptWithKey(plain, fileKey);
    // NÃO zeroiza fileKey — precisa dela para próxima escrita

    const enc = { nonce: nonce.toString("hex"), ciphertext: ciphertext.toString("hex") };
    fs.writeFileSync(_chatFile(peerId), JSON.stringify(enc), { mode: 0o600 });
  } catch (err) {
    console.error(`[ChatStore] Falha ao persistir histórico de ${peerId.slice(-8)}:`, err.message);
  }
}

// ── Delete ────────────────────────────────────────────────────────────────

/**
 * Apaga toda a conversa com um peer (destruição criptográfica + remoção de arquivo).
 * @param {string} peerId
 */
function deleteHistory(peerId) {
  const meta = _fileMeta.get(peerId);
  if (meta) secureDelete(meta.fileId);
  _fileMeta.delete(peerId);
  _cache.delete(peerId);
  try { fs.unlinkSync(_chatFile(peerId)); } catch { /* já não existe */ }
  try { fs.unlinkSync(_metaFile(peerId)); } catch { /* já não existe */ }
  console.log(`[ChatStore] Histórico de ${peerId.slice(-8)} apagado ✓`);
}

/**
 * Retorna IDs de peers que têm histórico salvo em disco.
 * (Baseado nos arquivos .meta existentes — não contém PeerId completo,
 *  apenas o sufixo, o que é intencional para privacidade.)
 */
function listStoredPeers() {
  try {
    return fs.readdirSync(CHATS_DIR)
      .filter(f => f.endsWith(".meta"))
      .map(f => f.replace(".meta", ""));
  } catch { return []; }
}

module.exports = { loadHistory, appendMessage, deleteHistory, listStoredPeers };
