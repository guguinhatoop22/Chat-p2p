"use strict";

const { randomUUID } = require("node:crypto");

const CHAT_PROTOCOL_ID = "/p2p-secure/chat/1.0.0";
const ACK_TIMEOUT_MS = 5000;

function createChatProtocol({ onMessage, onStatus = null, sessionManager = null }) {
  const encoder = new TextEncoder();

  function decodeChunk(chunk) {
    if (chunk instanceof Uint8Array) return chunk;
    if (chunk && typeof chunk.subarray === "function") return chunk.subarray();
    return new Uint8Array(chunk);
  }

  function emitStatus(peerId, msgId, status) {
    if (typeof msgId === "string" && msgId) onStatus?.(peerId, msgId, status);
  }

  async function sendAck(stream, msgId) {
    if (typeof msgId !== "string" || msgId.length === 0) return;
    await stream.send(encoder.encode(JSON.stringify({ ack: true, msgId }) + "\n"));
  }

  async function waitForAck(stream, msgId) {
    const decoder = new TextDecoder();
    let buffer = "";

    for await (const chunk of stream) {
      buffer += decoder.decode(decodeChunk(chunk), { stream: true });

      const lines = buffer.split("\n");
      buffer = lines.pop() ?? "";

      for (const line of lines) {
        const trimmed = line.trim();
        if (!trimmed) continue;

        try {
          const msg = JSON.parse(trimmed);
          if (msg?.ack === true && msg.msgId === msgId) return true;
        } catch {
          // Ignora lixo ou payload inesperado.
        }
      }
    }

    return false;
  }

  async function readStream(stream, peerId) {
    const decoder = new TextDecoder();
    let buffer = "";

    try {
      for await (const chunk of stream) {
        buffer += decoder.decode(decodeChunk(chunk), { stream: true });

        const lines = buffer.split("\n");
        buffer = lines.pop() ?? "";

        for (const line of lines) {
          const trimmed = line.trim();
          if (!trimmed) continue;

          try {
            const msg = JSON.parse(trimmed);
            if (!msg || msg.ack === true) continue;

            let text;
            let encrypted = false;

            if (msg.encrypted && sessionManager?.has(peerId)) {
              const session = sessionManager.get(peerId);
              try {
                text = await session.decrypt(msg);
                encrypted = true;
              } catch (err) {
                console.error(`[Chat] Falha ao descriptografar mensagem de ${peerId.slice(-8)}:`, err.message);
                continue;
              }
            } else if (typeof msg.text === "string") {
              text = msg.text;
              encrypted = false;
              if (msg.encrypted) {
                console.warn("[Chat] Mensagem criptografada recebida sem sessao ativa - descartada");
                continue;
              }
            } else {
              continue;
            }

            if (typeof text !== "string" || text.length === 0 || text.length > 4096) continue;
            onMessage(peerId, text, typeof msg.ts === "number" ? msg.ts : Date.now(), encrypted, msg.id);
            await sendAck(stream, msg.id);
          } catch {
            // JSON malformado - ignorar.
          }
        }
      }
    } catch {
      // Stream fechado ou com erro - normal ao desconectar.
    }
  }

  function registerProtocol(node) {
    node.handle(CHAT_PROTOCOL_ID, async (stream, connection) => {
      const peerId = connection.remotePeer.toString();
      await readStream(stream, peerId);
    });
    console.log("[Chat] Protocolo registrado:", CHAT_PROTOCOL_ID);
  }

  async function sendChatMessage(node, peerIdObj, text, msgId = null) {
    const peerId = peerIdObj.toString();
    const session = sessionManager?.get(peerId) ?? null;
    const id = typeof msgId === "string" && msgId ? msgId : randomUUID();
    const ts = Date.now();

    let payload;
    if (session) {
      const encrypted = await session.encrypt(text);
      payload = encoder.encode(JSON.stringify({ ...encrypted, id, encrypted: true, ts }) + "\n");
    } else {
      console.warn(`[Chat] Enviando sem E2E para ${peerId.slice(-8)} (sem sessao DR)`);
      payload = encoder.encode(JSON.stringify({ id, text, ts, encrypted: false }) + "\n");
    }

    let stream;
    let sent = false;

    try {
      emitStatus(peerId, id, "sending");
      stream = await node.dialProtocol(peerIdObj, CHAT_PROTOCOL_ID);
      await stream.send(payload);
      sent = true;
      emitStatus(peerId, id, "sent");

      const acked = await Promise.race([
        waitForAck(stream, id).catch(() => false),
        new Promise((resolve) => setTimeout(() => resolve(false), ACK_TIMEOUT_MS)),
      ]);

      if (acked) emitStatus(peerId, id, "delivered");
      return { id, ts, encrypted: !!session, status: acked ? "delivered" : "sent" };
    } catch (err) {
      if (!sent) emitStatus(peerId, id, "failed");
      throw err;
    } finally {
      if (stream) {
        try { await stream.close(); } catch { /* best effort */ }
      }
    }
  }

  return { registerProtocol, sendChatMessage };
}

module.exports = { createChatProtocol, CHAT_PROTOCOL_ID };
