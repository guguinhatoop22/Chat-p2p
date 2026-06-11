/**
 * src/network/node.js — Core Daemon (processo Node.js separado do Electron)
 *
 * Este processo é o coração do app. Roda separado do renderer.
 * Comprometer a UI NÃO compromete este processo.
 *
 * Responsabilidades:
 *   - Health check do RNG (primeiro — bloqueia tudo se falhar)
 *   - Inicializar nó libp2p com protocolo de chat E2E
 *   - Gerenciar peers conectados (PeerManager)
 *   - Gerenciar sessões Double Ratchet (SessionManager)
 *   - Handshake X3DH automático ao conectar novo peer
 *   - IPC bidirecional com o processo Electron Main via process.send()
 *
 * Etapa atual (3): E2E encryption com X3DH + Double Ratchet.
 */
"use strict";

const { parentPort } = require("node:worker_threads");

// ── Health check do RNG — DEVE ser o primeiro código executado ────────────
const { healthCheck } = require("../crypto/rng.js");

console.log("[Daemon] Iniciando P2P Secure Chat Core Daemon...");
console.log("[Daemon] Plataforma:", process.platform, process.arch, "| Node:", process.version);

try {
  healthCheck();
} catch (err) {
  console.error("[Daemon] FALHA CRÍTICA NO RNG:", err.message);
  console.error("[Daemon] Encerrando — operação insegura impossível.");
  process.exit(1);
}

// ── Imports após validação do RNG ─────────────────────────────────────────
const { createLibp2pNode }        = require("./libp2p-factory.js");
const { createChatProtocol }      = require("./chat-protocol.js");
const { PeerManager }             = require("./peer-manager.js");
const { SessionManager }          = require("../crypto/session-manager.js");
const { generateIdentityKeys }    = require("../identity/keygen.js");
const { createHandshakeProtocol } = require("./handshake-protocol.js");
const { generateFingerprint } = require("../identity/fingerprint.js");
const { runRecovery }             = require("../persistence/recovery.js");
const { loadIdentity, saveIdentity } = require("../persistence/identity-store.js");
const { appendMessage, loadHistory } = require("../persistence/chat-store.js");
const { loadContacts, saveContact, removeContact } = require("../persistence/contact-store.js");
const { secureDeleteAll }         = require("../persistence/deletion.js");

let libp2pNode       = null;
let shuttingDown     = false;
let peerManager      = null;
let chatProtocol     = null;
let sessionMgr       = null;
let handshakeProt    = null;
let myKeys           = null; // { identityKey, signedPreKey } — carregadas ou geradas
// Map<peerId, identityPublicKey hex> — preenchido pelo handshake
const peerIdentityKeys = new Map();

// ── IPC com o processo Electron Main ─────────────────────────────────────
function sendToMain(msg) {
  if (parentPort) {
    try { parentPort.postMessage(msg); } catch { /* worker encerrado */ }
    return;
  }
  if (typeof process.send === "function") {
    try { process.send(msg); } catch { /* canal IPC fechado */ }
  }
}

// ── Comandos recebidos do Main Process ────────────────────────────────────
async function handleControlMessage(msg) {
  if (!msg || typeof msg.type !== "string") return;

  switch (msg.type) {
    // Dial de um peer por multiaddr
    case "peer:connect": {
      const { addr } = msg.data;
      const { reqId } = msg;
      try {
        const { multiaddr } = await import("@multiformats/multiaddr");
        const ma   = multiaddr(addr.trim());
        const conn = await libp2pNode.dial(ma);
        const peerId = conn.remotePeer.toString();
        sendToMain({ type: "peer:connect:response", reqId, data: { ok: true, peerId } });
      } catch (err) {
        console.error("[Daemon] Falha ao conectar:", err.message);
        sendToMain({ type: "peer:connect:response", reqId, data: { ok: false, error: err.message } });
      }
      break;
    }

    // Enviar mensagem de chat a um peer
    case "chat:send": {
      const { to, text, id } = msg.data;
      const peerIdObj = peerManager?.getPeerIdObj(to);
      if (!peerIdObj) {
        console.warn("[Daemon] chat:send — peer não encontrado:", to);
        if (typeof id === "string" && id) {
          sendToMain({ type: "chat:status", data: { peerId: to, id, status: "failed" } });
        }
        break;
      }
      try {
        const result = await chatProtocol.sendChatMessage(libp2pNode, peerIdObj, text, id);
        await appendMessage(to, {
          id: result.id,
          from: "me",
          text,
          ts: result.ts,
          encrypted: result.encrypted,
          status: result.status,
        });
      } catch (err) {
        console.error("[Daemon] Falha ao enviar mensagem:", err.message);
      }
      break;
    }

    // Listar peers conectados
    case "peers:get": {
      const { reqId } = msg;
      sendToMain({ type: "peers:list:response", reqId, data: peerManager?.list() ?? [] });
      break;
    }

    // Gerar fingerprint de segurança para um peer
    case "identity:fingerprint": {
      const { reqId, data: { peerId } } = msg;
      try {
        const myPub    = myKeys?.identityKey?.publicKey ?? "";
        const theirPub = peerIdentityKeys.get(peerId) ?? peerId;
        const fp       = generateFingerprint(myPub, theirPub, peerId);
        // Apenas o fingerprint é enviado de volta — o QR é gerado no Main Process
        sendToMain({ type: "identity:fingerprint:response", reqId, data: { fingerprint: fp } });
      } catch (err) {
        sendToMain({ type: "identity:fingerprint:response", reqId, data: { error: err.message } });
      }
      break;
    }

    // Carregar histórico de chat de um peer
    case "chat:history": {
      const { reqId, data: { peerId } } = msg;
      try {
        const history = await loadHistory(peerId);
        sendToMain({ type: "chat:history:response", reqId, data: history });
      } catch (err) {
        sendToMain({ type: "chat:history:response", reqId, data: [] });
      }
      break;
    }

    case "contacts:list": {
      const { reqId } = msg;
      try {
        const contacts = Array.from(loadContacts().entries()).map(([peerId, value]) => ({
          peerId,
          nick: value.nick,
        }));
        sendToMain({ type: "contacts:list:response", reqId, data: contacts });
      } catch {
        sendToMain({ type: "contacts:list:response", reqId, data: [] });
      }
      break;
    }

    case "contacts:save": {
      const { reqId, data } = msg;
      try {
        saveContact(data?.peerId, data?.nick);
        sendToMain({ type: "contacts:save:response", reqId, data: { ok: true } });
        sendToMain({ type: "contacts:updated", data: { peerId: data?.peerId } });
      } catch (err) {
        sendToMain({ type: "contacts:save:response", reqId, data: { ok: false, error: err.message } });
      }
      break;
    }

    case "contacts:remove": {
      const { reqId, data } = msg;
      try {
        removeContact(data?.peerId);
        sendToMain({ type: "contacts:remove:response", reqId, data: { ok: true } });
        sendToMain({ type: "contacts:updated", data: { peerId: data?.peerId } });
      } catch (err) {
        sendToMain({ type: "contacts:remove:response", reqId, data: { ok: false, error: err.message } });
      }
      break;
    }
  }
}

if (parentPort) {
  parentPort.on("message", (msg) => {
    handleControlMessage(msg).catch((err) => {
      console.error("[Daemon] Falha ao processar comando:", err);
    });
  });
} else {
  process.on("message", (msg) => {
    handleControlMessage(msg).catch((err) => {
      console.error("[Daemon] Falha ao processar comando:", err);
    });
  });
}

async function startDaemon() {
  // Verificar e recuperar arquivos de journal pendentes (DEVE ser primeiro)
  runRecovery();

  console.log("[Daemon] Inicializando nó libp2p...");

  // Carregar ou gerar chaves de identidade X3DH
  console.log("[Daemon] Carregando chaves de identidade...");
  myKeys = await loadIdentity();
  if (!myKeys) {
    myKeys = await generateIdentityKeys();
    await saveIdentity(myKeys);
    console.log("[Daemon] Novas chaves geradas e salvas ✓");
  } else {
    console.log("[Daemon] Chaves de identidade restauradas do disco ✓");
  }

  peerManager = new PeerManager();
  sessionMgr  = new SessionManager();

  chatProtocol = createChatProtocol({
    sessionManager: sessionMgr,
    onMessage(from, text, ts, encrypted, id) {
      console.log(`[Daemon] Mensagem de …${from.slice(-8)} [${encrypted ? "E2E✓" : "plaintext"}]: ${text.slice(0, 60)}`);
      sendToMain({ type: "peer:status", data: { peerId: from, status: "online" } });
      sendToMain({ type: "chat:receive", data: { from, text, ts, encrypted, id } });
      // Persistir mensagem recebida de forma assíncrona (nunca bloqueia)
      appendMessage(from, { id, from, text, ts, encrypted }).catch((err) => {
        console.error("[Daemon] Falha ao persistir mensagem:", err.message);
      });
    },
    onStatus(peerId, id, status) {
      sendToMain({ type: "chat:status", data: { peerId, id, status } });
    },
  });

  handshakeProt = createHandshakeProtocol({
    getMyKeys: async () => myKeys,
    sessionManager: sessionMgr,
    onSessionReady(peerId, role, theirIdentityKey) {
      console.log(`[Daemon] Sessão E2E pronta (${role}) ↔ ${peerId.slice(-8)}`);
      // Armazenar chave de identidade do peer para gerar fingerprint depois
      if (theirIdentityKey) peerIdentityKeys.set(peerId, theirIdentityKey);
      sendToMain({ type: "session:ready", data: { peerId, role } });
    },
  });

  libp2pNode = await createLibp2pNode();
  await libp2pNode.start();

  // Registrar protocolos
  chatProtocol.registerProtocol(libp2pNode);
  handshakeProt.registerProtocol(libp2pNode);

  const peerId = libp2pNode.peerId.toString();
  const addrs  = libp2pNode.getMultiaddrs().map(m => m.toString());

  console.log("[Daemon] libp2p OK ✓ | PeerID:", peerId);
  for (const addr of addrs) console.log("[Daemon] Ouvindo:", addr);

  // Eventos de peers — atualiza PeerManager e inicia handshake automaticamente
  libp2pNode.addEventListener("peer:connect", async (e) => {
    const peerIdObj = e.detail;
    if (peerManager.add(peerIdObj)) {
      const str = peerIdObj.toString();
      console.log("[Daemon] Peer conectado:", str);
      sendToMain({ type: "peer:connected", data: { peerId: str } });
      sendToMain({ type: "peer:status", data: { peerId: str, status: "online" } });

      // Inicia handshake X3DH automaticamente apenas do lado que tem PeerID menor.
      // Isso evita que ambos os lados tentem iniciar simultaneamente (race condition).
      // O lado com PeerID maior aguarda — seu lado responder já foi ativado.
      setTimeout(async () => {
        if (!sessionMgr.has(str)) {
          const myId = libp2pNode.peerId.toString();
          if (myId < str) {
            // Eu sou o iniciador (PeerID menor)
            await handshakeProt.initiateHandshake(libp2pNode, peerIdObj, str);
          }
          // Se myId > str: o peer remoto vai iniciar → meu lado responder já está registrado
        }
      }, 300);
    }
  });

  libp2pNode.addEventListener("peer:disconnect", (e) => {
    const str = e.detail.toString();
    peerManager.remove(str);
    // Destrói sessão DR — zeroiza chaves (forward secrecy)
    sessionMgr.destroy(str);
    // Preserva a chave de identidade do peer — necessária para fingerprint futuro
    console.log("[Daemon] Peer desconectado:", str);
    sendToMain({ type: "peer:disconnected", data: { peerId: str } });
    sendToMain({ type: "peer:status", data: { peerId: str, status: "offline" } });
  });

  // Notificar Main que o daemon está pronto (PeerID + endereços)
  sendToMain({ type: "daemon:ready", data: { peerId, addrs } });
  console.log("[Daemon] Pronto ✓");
}

async function shutdown(signal) {
  if (shuttingDown) return;
  shuttingDown = true;
  console.log(`\n[Daemon] ${signal} recebido — encerrando com segurança...`);
  sessionMgr?.destroyAll(); // zeroiza todas as chaves de sessão
  try { await secureDeleteAll(); } catch { /* best effort */ } // apaga chaves de arquivo do keystore
  if (libp2pNode) { try { await libp2pNode.stop(); } catch {} }
  console.log("[Daemon] Encerrado.");
  process.exit(0);
}

process.on("SIGTERM",            () => shutdown("SIGTERM"));
process.on("SIGINT",             () => shutdown("SIGINT"));
process.on("uncaughtException",  (e) => { console.error("[Daemon] Uncaught:", e);  shutdown("uncaughtException"); });
process.on("unhandledRejection", (r) => { console.error("[Daemon] Unhandled:", r); shutdown("unhandledRejection"); });

startDaemon().catch((e) => { console.error("[Daemon] Falha fatal:", e); process.exit(1); });
