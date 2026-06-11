"use strict";

/**
 * src/network/peer-manager.js — Rastreia peers conectados
 *
 * Guarda referência ao objeto PeerId do libp2p (necessário para dialProtocol)
 * e ao timestamp de conexão.
 */

class PeerManager {
  constructor() {
    // Map<peerIdStr, { peerIdObj, connectedAt }>
    this._peers = new Map();
  }

  /**
   * Adiciona um peer. Retorna true se era novo, false se já existia.
   * @param {object} peerIdObj — PeerId object do libp2p
   * @returns {boolean}
   */
  add(peerIdObj) {
    const str = peerIdObj.toString();
    if (this._peers.has(str)) return false;
    this._peers.set(str, { peerIdObj, connectedAt: Date.now() });
    return true;
  }

  /**
   * Remove um peer pelo seu ID em string.
   * @param {string} peerIdStr
   * @returns {boolean}
   */
  remove(peerIdStr) {
    return this._peers.delete(peerIdStr);
  }

  has(peerIdStr) {
    return this._peers.has(peerIdStr);
  }

  /**
   * Retorna o objeto PeerId para uso em dialProtocol.
   * @param {string} peerIdStr
   * @returns {object|null}
   */
  getPeerIdObj(peerIdStr) {
    return this._peers.get(peerIdStr)?.peerIdObj ?? null;
  }

  /**
   * Lista todos os peers como objetos serializáveis.
   * @returns {Array<{ peerId: string, connectedAt: number }>}
   */
  list() {
    return Array.from(this._peers.entries()).map(([str, { connectedAt }]) => ({
      peerId: str,
      connectedAt,
    }));
  }

  get size() {
    return this._peers.size;
  }
}

module.exports = { PeerManager };
