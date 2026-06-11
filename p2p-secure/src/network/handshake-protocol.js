"use strict";

/**
 * src/network/handshake-protocol.js — Troca de chaves X3DH via libp2p
 *
 * Protocolo: /p2p-secure/handshake/1.0.0
 * Fluxo:
 *   Initiator abre stream → envia { identityKey, signedPreKey, ephemeralPublicKey }
 *   Responder recebe     → envia { identityKey, signedPreKey } de volta
 *   Ambos derivam sharedSecret e criam sessão Double Ratchet.
 *
 * Segurança:
 *   - Todas as chaves transmitidas são PUBLIC keys (nunca privadas)
 *   - Mensagem limitada a 4KB para evitar DoS
 *   - Timeout de 15s por handshake
 *   - peerId do libp2p serve como âncora de identidade (autenticado pelo Noise XX)
 */

const HANDSHAKE_PROTOCOL_ID = "/p2p-secure/handshake/1.0.0";
const MAX_MSG_BYTES         = 4096;
const HANDSHAKE_TIMEOUT_MS  = 15000;

/**
 * @param {object} opts
 * @param {function} opts.getMyKeys      — async () => { identityKey, signedPreKey }
 * @param {function} opts.onSessionReady — async (peerId, role) => void
 * @param {object}   opts.sessionManager — SessionManager instance
 */
function createHandshakeProtocol({ getMyKeys, onSessionReady, sessionManager }) {
  const enc = new TextEncoder();
  const dec = new TextDecoder();

  // ── Helpers de stream ──────────────────────────────────────────────────

  async function readOne(stream) {
    return new Promise((resolve, reject) => {
      const timer = setTimeout(() => reject(new Error("Handshake timeout")), HANDSHAKE_TIMEOUT_MS);
      (async () => {
        let buf = "";
        try {
          for await (const chunk of stream) {
            let bytes;
            if (chunk instanceof Uint8Array)              bytes = chunk;
            else if (chunk && typeof chunk.subarray === "function") bytes = chunk.subarray();
            else                                           bytes = new Uint8Array(chunk);
            buf += dec.decode(bytes, { stream: true });
            if (buf.includes("\n")) break;
          }
          clearTimeout(timer);
          const line = buf.split("\n")[0].trim();
          if (line.length > MAX_MSG_BYTES) return reject(new Error("Handshake message too large"));
          resolve(JSON.parse(line));
        } catch (e) { clearTimeout(timer); reject(e); }
      })();
    });
  }

  async function writeOne(stream, obj) {
    const payload = enc.encode(JSON.stringify(obj) + "\n");
    stream.send(payload);
  }

  // ── Validação de payload ───────────────────────────────────────────────

  function _validatePublicKeys(obj) {
    // Cada chave deve ser hex de exatamente 64 chars (32 bytes Curve25519)
    const HEX32 = /^[0-9a-f]{64}$/i;
    if (!HEX32.test(obj?.identityKey?.publicKey))   throw new Error("identityKey inválida");
    if (!HEX32.test(obj?.signedPreKey?.publicKey))  throw new Error("signedPreKey inválida");
    if (obj.ephemeralPublicKey && !HEX32.test(obj.ephemeralPublicKey))
      throw new Error("ephemeralPublicKey inválida");
  }

  // ── Handler (Responder) ────────────────────────────────────────────────

  function registerProtocol(node) {
    node.handle(HANDSHAKE_PROTOCOL_ID, async (stream, connection) => {
      const peerId = connection.remotePeer.toString();
      try {
        // 1. Receber oferta do Initiator
        const offer = await readOne(stream);
        _validatePublicKeys(offer);

        // 2. Buscar nossas chaves
        const myKeys = await getMyKeys();

        // 3. Criar sessão como Responder
        await sessionManager.createAsResponder(
          peerId,
          myKeys.identityKey,
          myKeys.signedPreKey,
          { publicKey: offer.identityKey.publicKey },
          offer.ephemeralPublicKey,
        );

        // 4. Enviar nossa chave pública de volta (sem privada, nunca)
        await writeOne(stream, {
          identityKey:  { publicKey: myKeys.identityKey.publicKey },
          signedPreKey: { publicKey: myKeys.signedPreKey.publicKey },
        });

        console.log(`[Handshake] Sessão estabelecida (responder) ↔ ${peerId.slice(-8)}`);
        onSessionReady(peerId, "responder", offer.identityKey.publicKey);
      } catch (err) {
        console.error("[Handshake] Erro (responder):", err.message);
      } finally {
        try { await stream.close(); } catch { /* best effort */ }
      }
    });
    console.log("[Handshake] Protocolo registrado:", HANDSHAKE_PROTOCOL_ID);
  }

  // ── Initiator ─────────────────────────────────────────────────────────

  /**
   * Inicia handshake com um peer após conexão.
   * @param {object} node       — libp2p node
   * @param {object} peerIdObj  — PeerId object
   * @param {string} theirPeerId — string
   */
  async function initiateHandshake(node, peerIdObj, theirPeerId) {
    let stream;
    try {
      // 1. Buscar nossas chaves
      const myKeys = await getMyKeys();

      // 2. Calcular X3DH como initiator — precisamos da chave pública deles
      //    Mas ainda não temos — pedimos via offer e usamos a resposta.
      //    Abordagem: enviamos nossa EK e IK na oferta.
      //    O Responder envia SPK de volta. Nós então completamos o X3DH localmente
      //    usando a SPK recebida.
      //    (Dois passes: offer → response → complete)

      // Passo 1: gerar EK efêmera para incluir na oferta
      const sodium = require("libsodium-wrappers");
      await sodium.ready;
      const ek = sodium.crypto_kx_keypair();
      const ephemeralPublicKey = Buffer.from(ek.publicKey).toString("hex");

      stream = await node.dialProtocol(peerIdObj, HANDSHAKE_PROTOCOL_ID);

      // 2. Enviar oferta com nossa IK pública + EK pública
      await writeOne(stream, {
        identityKey:         { publicKey: myKeys.identityKey.publicKey },
        signedPreKey:        { publicKey: myKeys.signedPreKey.publicKey },
        ephemeralPublicKey,
      });

      // 3. Receber resposta (SPK pública deles)
      const response = await readOne(stream);
      _validatePublicKeys(response);

      // 4. Criar sessão como Initiator (X3DH completo)
      // Passa a EK gerada acima — a mesma enviada na oferta ao Responder.
      await sessionManager.createAsInitiator(
        theirPeerId,
        myKeys.identityKey,
        myKeys.signedPreKey,
        { publicKey: response.identityKey.publicKey },
        { publicKey: response.signedPreKey.publicKey },
        ek,
      );

      console.log(`[Handshake] Sessão estabelecida (initiator) ↔ ${theirPeerId.slice(-8)}`);
      onSessionReady(theirPeerId, "initiator", response.identityKey.publicKey);
    } catch (err) {
      console.error("[Handshake] Erro (initiator):", err.message);
    } finally {
      if (stream) { try { await stream.close(); } catch { /* best effort */ } }
    }
  }

  return { registerProtocol, initiateHandshake };
}

module.exports = { createHandshakeProtocol, HANDSHAKE_PROTOCOL_ID };
