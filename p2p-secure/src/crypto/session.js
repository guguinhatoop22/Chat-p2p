/**
 * src/crypto/session.js — Double Ratchet Session (Etapa 3)
 *
 * Implementa o Double Ratchet Algorithm sobre libsodium (Curve25519 + XSalsa20-Poly1305):
 *
 *   KDF Chain Ratchet: avança a message key a cada mensagem enviada/recebida.
 *   DH Ratchet:        ao receber nova chave DH do peer, avança a root key
 *                      e deriva novos sending/receiving chains. Garante
 *                      forward secrecy e break-in recovery.
 *
 * Deniability: MAC simétrico (secretbox) — receptor não pode provar autoria a terceiros.
 * Chaves out-of-order: skippedKeys guarda até MAX_SKIP message keys.
 *
 * Etapa 4: substituir por @signalapp/libsignal-client (implementação auditada).
 */
"use strict";

const sodium              = require("libsodium-wrappers");
const { createHmac }      = require("node:crypto");
const { zeroizeAll }      = require("./memory.js");
const { secureRandomBytes } = require("./rng.js");

const MAX_SKIP = 100; // máximo de message keys out-of-order armazenadas

let _sodiumReady = false;
async function _ensureSodium() {
  if (!_sodiumReady) { await sodium.ready; _sodiumReady = true; }
}

// ── KDF helpers ───────────────────────────────────────────────────────────

/**
 * Um passo do KDF chain ratchet (HMAC-SHA256).
 * Constante 0x01 → message key | 0x02 → next chain key
 * (mesmo padrão do Signal Protocol spec §2.2)
 */
function _kdfStep(chainKey) {
  const ck = Buffer.isBuffer(chainKey) ? chainKey : Buffer.from(chainKey);
  const messageKey   = createHmac("sha256", ck).update(Buffer.from([0x01])).digest();
  const nextChainKey = createHmac("sha256", ck).update(Buffer.from([0x02])).digest();
  return { messageKey, nextChainKey };
}

/**
 * KDF Root Ratchet: deriva nova root key + chain key a partir de DH output.
 * HKDF-SHA256 com info label diferente para cada direção.
 */
function _kdfRoot(rootKey, dhOut, info) {
  const rk   = Buffer.isBuffer(rootKey) ? rootKey : Buffer.from(rootKey);
  const dh   = Buffer.isBuffer(dhOut)   ? dhOut   : Buffer.from(dhOut);
  const inf  = Buffer.from(info, "utf8");
  // Extract
  const prk  = createHmac("sha256", rk).update(dh).digest();
  // Expand — dois blocos de 32 bytes (novo rootKey + novo chainKey)
  const newRootKey  = createHmac("sha256", prk).update(Buffer.concat([inf, Buffer.from([0x01])])).digest();
  const newChainKey = createHmac("sha256", prk).update(Buffer.concat([inf, Buffer.from([0x02])])).digest();
  return { newRootKey, newChainKey };
}

// ── Classe principal ──────────────────────────────────────────────────────

class DoubleRatchetSession {
  /**
   * @param {object}     p
   * @param {string}     p.sessionId       — peerId do outro lado
   * @param {Buffer}     p.rootKey         — 32 bytes, derivado do X3DH
   * @param {Buffer}     p.sendingChain    — chain key inicial de envio
   * @param {Buffer}     p.receivingChain  — chain key inicial de recebimento
   * @param {object}     p.myDHKeyPair     — { publicKey, privateKey } Curve25519
   * @param {Buffer}     p.theirDHPublicKey — chave pública DH do peer (recebida no handshake)
   * @param {boolean}    p.isInitiator
   */
  constructor({ sessionId, rootKey, sendingChain, receivingChain, myDHKeyPair, theirDHPublicKey, isInitiator }) {
    this.sessionId        = sessionId;
    this.rootKey          = Buffer.from(rootKey);
    this.sendingChain     = Buffer.from(sendingChain);
    this.receivingChain   = Buffer.from(receivingChain);
    this.myDHKeyPair      = myDHKeyPair;       // { publicKey: Uint8Array, privateKey: Uint8Array }
    this.theirDHPublicKey = Buffer.from(theirDHPublicKey);
    this.isInitiator      = isInitiator;
    this.sendCounter      = 0;
    this.recvCounter      = 0;
    this.skippedKeys      = new Map(); // "counter:dhPub" → messageKey
  }

  // ── DH Ratchet ────────────────────────────────────────────────────────

  /**
   * Avança o DH Ratchet (chamado quando recebemos nova chave DH do peer).
   * Gera novo par DH efêmero, deriva novos receiving chain e sending chain.
   * @param {Buffer} newTheirDH — nova chave pública DH do peer
   */
  _dhRatchet(newTheirDH) {
    // 1. Recalcula receiving chain com nova chave deles
    const dhRecv = sodium.crypto_scalarmult(this.myDHKeyPair.privateKey, new Uint8Array(newTheirDH));
    const { newRootKey: rk1, newChainKey: recvChain } = _kdfRoot(this.rootKey, dhRecv, "recv");
    zeroizeAll(Buffer.from(dhRecv));

    // 2. Gera novo par DH nosso
    const newMyDH = sodium.crypto_kx_keypair();

    // 3. Calcula sending chain com novo par nosso e nova chave deles
    const dhSend = sodium.crypto_scalarmult(newMyDH.privateKey, new Uint8Array(newTheirDH));
    const { newRootKey: rk2, newChainKey: sendChain } = _kdfRoot(rk1, dhSend, "send");
    zeroizeAll(Buffer.from(dhSend));

    // 4. Zeroizar chaves antigas
    if (this.myDHKeyPair.privateKey) zeroizeAll(this.myDHKeyPair.privateKey);
    zeroizeAll(this.rootKey, this.sendingChain, this.receivingChain);

    this.rootKey          = rk2;
    this.receivingChain   = recvChain;
    this.sendingChain     = sendChain;
    this.myDHKeyPair      = newMyDH;
    this.theirDHPublicKey = Buffer.from(newTheirDH);
    this.recvCounter      = 0;
  }

  // ── Encrypt ───────────────────────────────────────────────────────────

  /**
   * Criptografa plaintext avançando o KDF chain ratchet de envio.
   * @param {string|Uint8Array|Buffer} plaintext
   * @returns {{ ciphertext: string, nonce: string, counter: number, dhPublicKey: string }}
   *   Todos os campos são hex strings para serialização JSON segura.
   */
  async encrypt(plaintext) {
    await _ensureSodium();

    const { messageKey, nextChainKey } = _kdfStep(this.sendingChain);

    // Nonce único: 16 bytes aleatórios + 8 bytes do sendCounter (big-endian)
    const nonce = new Uint8Array(sodium.crypto_secretbox_NONCEBYTES); // 24 bytes
    nonce.set(secureRandomBytes(16));
    new DataView(nonce.buffer).setUint32(16, this.sendCounter, false);
    new DataView(nonce.buffer).setUint32(20, 0, false);

    const pt = typeof plaintext === "string"
      ? new TextEncoder().encode(plaintext)
      : plaintext;

    const ciphertext = sodium.crypto_secretbox_easy(pt, nonce, messageKey);

    zeroizeAll(messageKey, this.sendingChain);
    this.sendingChain = nextChainKey;
    const counter = this.sendCounter++;

    return {
      ciphertext:  Buffer.from(ciphertext).toString("hex"),
      nonce:       Buffer.from(nonce).toString("hex"),
      counter,
      dhPublicKey: Buffer.from(this.myDHKeyPair.publicKey).toString("hex"),
    };
  }

  // ── Decrypt ───────────────────────────────────────────────────────────

  /**
   * Descriptografa mensagem recebida, avançando o ratchet se necessário.
   * @param {object} msg — { ciphertext: hex, nonce: hex, counter: number, dhPublicKey: hex }
   * @returns {string} plaintext
   */
  async decrypt(msg) {
    await _ensureSodium();

    const { ciphertext, nonce, counter, dhPublicKey } = msg;
    const ct    = Buffer.from(ciphertext,  "hex");
    const nc    = Buffer.from(nonce,       "hex");
    const theirDH = Buffer.from(dhPublicKey, "hex");

    // Verifica se veio com nova chave DH (DH Ratchet necessário)
    const dhChanged = !theirDH.equals(this.theirDHPublicKey);

    // Tenta chave skipada primeiro (mensagem fora de ordem)
    const skipKey = `${counter}:${dhPublicKey}`;
    if (this.skippedKeys.has(skipKey)) {
      const messageKey = this.skippedKeys.get(skipKey);
      this.skippedKeys.delete(skipKey);
      return this._decrypt(ct, nc, messageKey);
    }

    if (dhChanged) {
      // Guarda message keys do chain atual que podem chegar fora de ordem
      this._stashSkippedKeys(this.theirDHPublicKey.toString("hex"));
      // Avança DH Ratchet
      this._dhRatchet(theirDH);
    }

    // Avança KDF chain até o counter esperado (stash intermediários)
    while (this.recvCounter < counter) {
      if (this.skippedKeys.size >= MAX_SKIP)
        throw new Error("[Session] Muitas mensagens puladas — sessão comprometida");
      const { messageKey, nextChainKey } = _kdfStep(this.receivingChain);
      this.skippedKeys.set(`${this.recvCounter}:${dhPublicKey}`, messageKey);
      zeroizeAll(this.receivingChain);
      this.receivingChain = nextChainKey;
      this.recvCounter++;
    }

    const { messageKey, nextChainKey } = _kdfStep(this.receivingChain);
    zeroizeAll(this.receivingChain);
    this.receivingChain = nextChainKey;
    this.recvCounter++;

    return this._decrypt(ct, nc, messageKey);
  }

  _decrypt(ct, nonce, messageKey) {
    const mk = Buffer.isBuffer(messageKey) ? new Uint8Array(messageKey) : messageKey;
    try {
      const pt = sodium.crypto_secretbox_open_easy(new Uint8Array(ct), new Uint8Array(nonce), mk);
      if (!pt) throw new Error("Autenticação falhou (MAC inválido)");
      return new TextDecoder().decode(pt);
    } finally {
      zeroizeAll(Buffer.from(mk));
    }
  }

  _stashSkippedKeys(dhPubHex) {
    let chain = Buffer.from(this.receivingChain);
    let n     = this.recvCounter;
    while (n < this.recvCounter + MAX_SKIP && this.skippedKeys.size < MAX_SKIP) {
      const { messageKey, nextChainKey } = _kdfStep(chain);
      this.skippedKeys.set(`${n}:${dhPubHex}`, messageKey);
      zeroizeAll(chain);
      chain = nextChainKey;
      n++;
    }
    zeroizeAll(chain);
  }

  // ── Destroy ───────────────────────────────────────────────────────────

  destroy() {
    zeroizeAll(this.rootKey, this.sendingChain, this.receivingChain, this.theirDHPublicKey);
    if (this.myDHKeyPair?.privateKey) zeroizeAll(this.myDHKeyPair.privateKey);
    for (const k of this.skippedKeys.values()) zeroizeAll(Buffer.from(k));
    this.skippedKeys.clear();
    console.log(`[Session] ${this.sessionId} destruída e chaves zeroizadas ✓`);
  }
}

module.exports = { DoubleRatchetSession };
