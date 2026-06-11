"use strict";

/**
 * src/crypto/session-manager.js — Gerencia sessões Double Ratchet por peer
 *
 * Uma sessão por peer (peerId string → DoubleRatchetSession).
 * Criação via X3DH após handshake bem-sucedido.
 * Destruição automática ao desconectar (forward secrecy).
 */

const sodium = require("libsodium-wrappers");
const { DoubleRatchetSession } = require("./session.js");
const { x3dhInitiator, x3dhResponder } = require("./x3dh.js");
const { zeroizeAll } = require("./memory.js");

class SessionManager {
  constructor() {
    // Map<peerId: string, DoubleRatchetSession>
    this._sessions = new Map();
  }

  /**
   * Cria sessão como INITIATOR (quem iniciou o handshake).
   *
   * Chama x3dhInitiator → deriva sharedSecret → cria Double Ratchet.
   * O sendingChain é derivado do sharedSecret (initiator envia primeiro).
   * O receivingChain é derivado com label diferente.
   *
   * @param {string} peerId
   * @param {object} myIdentityKey       — { publicKey: hex, privateKey: hex }
   * @param {object} mySignedPreKey      — { publicKey: hex, privateKey: hex }
   * @param {object} theirIdentityKey    — { publicKey: hex }
   * @param {object} theirSignedPreKey   — { publicKey: hex }
   * @returns {string} ephemeralPublicKey hex — deve ser enviado ao Responder
   */
  async createAsInitiator(peerId, myIdentityKey, mySignedPreKey, theirIdentityKey, theirSignedPreKey, ephemeralKeyPair = null) {
    await sodium.ready;

    const { sharedSecret, ephemeralPublicKey } = await x3dhInitiator(
      myIdentityKey, theirIdentityKey, theirSignedPreKey, ephemeralKeyPair,
    );

    const { sendingChain, receivingChain, rootKey, myDHKeyPair } =
      _deriveSessionKeys(sharedSecret, theirSignedPreKey.publicKey, true);

    zeroizeAll(sharedSecret);

    const session = new DoubleRatchetSession({
      sessionId:        peerId,
      rootKey,
      sendingChain,
      receivingChain,
      myDHKeyPair,
      theirDHPublicKey: Buffer.from(theirSignedPreKey.publicKey, "hex"),
      isInitiator:      true,
    });

    this._sessions.set(peerId, session);
    console.log(`[SessionMgr] Sessão criada (initiator) para ${peerId.slice(-8)}`);
    return ephemeralPublicKey;
  }

  /**
   * Cria sessão como RESPONDER (quem recebeu o handshake).
   *
   * @param {string} peerId
   * @param {object} myIdentityKey       — { publicKey: hex, privateKey: hex }
   * @param {object} mySignedPreKey      — { publicKey: hex, privateKey: hex }
   * @param {object} theirIdentityKey    — { publicKey: hex }
   * @param {string} ephemeralPublicKey  — hex recebido do Initiator
   */
  async createAsResponder(peerId, myIdentityKey, mySignedPreKey, theirIdentityKey, ephemeralPublicKey) {
    await sodium.ready;

    const sharedSecret = await x3dhResponder(
      myIdentityKey, mySignedPreKey, theirIdentityKey, ephemeralPublicKey,
    );

    const { sendingChain, receivingChain, rootKey, myDHKeyPair } =
      _deriveSessionKeys(sharedSecret, mySignedPreKey.publicKey, false);

    zeroizeAll(sharedSecret);

    const session = new DoubleRatchetSession({
      sessionId:        peerId,
      rootKey,
      sendingChain,
      receivingChain,
      myDHKeyPair,
      theirDHPublicKey: Buffer.from(ephemeralPublicKey, "hex"),
      isInitiator:      false,
    });

    this._sessions.set(peerId, session);
    console.log(`[SessionMgr] Sessão criada (responder) para ${peerId.slice(-8)}`);
  }

  /** Retorna sessão ativa para um peer, ou null. */
  get(peerId) {
    return this._sessions.get(peerId) ?? null;
  }

  has(peerId) {
    return this._sessions.has(peerId);
  }

  /**
   * Destrói sessão de um peer (zeroiza chaves).
   * Chamado ao desconectar — essencial para forward secrecy.
   */
  destroy(peerId) {
    const session = this._sessions.get(peerId);
    if (session) {
      session.destroy();
      this._sessions.delete(peerId);
    }
  }

  /** Destrói todas as sessões (shutdown). */
  destroyAll() {
    for (const [peerId] of this._sessions) this.destroy(peerId);
  }
}

// ── Helpers internos ──────────────────────────────────────────────────────

const { createHmac } = require("node:crypto");

/**
 * Deriva sendingChain, receivingChain, rootKey e novo par DH a partir do sharedSecret.
 * Initiator e Responder trocam sending/receiving para que se comuniquem corretamente.
 */
function _deriveSessionKeys(sharedSecret, dhPubHex, isInitiator) {
  const ss = Buffer.isBuffer(sharedSecret) ? sharedSecret : Buffer.from(sharedSecret);

  // Root key inicial = sharedSecret repassado por HKDF com label "root"
  const rootKey = createHmac("sha256", ss)
    .update(Buffer.from("P2PSecure-RootKey-v1"))
    .digest();

  // Duas chains simétricas — A→B e B→A
  const chainA = createHmac("sha256", ss)
    .update(Buffer.from("P2PSecure-ChainA-v1"))
    .digest();
  const chainB = createHmac("sha256", ss)
    .update(Buffer.from("P2PSecure-ChainB-v1"))
    .digest();

  // Initiator: sending=A, receiving=B | Responder: sending=B, receiving=A
  const sendingChain   = isInitiator ? chainA : chainB;
  const receivingChain = isInitiator ? chainB : chainA;

  // Par DH efêmero para o Double Ratchet (separado do X3DH)
  const myDHKeyPair = require("libsodium-wrappers").crypto_kx_keypair();

  return { rootKey, sendingChain, receivingChain, myDHKeyPair };
}

module.exports = { SessionManager };
