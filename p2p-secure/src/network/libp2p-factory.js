/**
 * src/network/libp2p-factory.js — Factory do nó libp2p
 *
 * Transports:  TCP + WebSockets (WebRTC na Etapa 3)
 * Segurança:   Noise Protocol XX — autenticação mútua + forward secrecy
 * Mux:         mplex
 * Serviços:    identify, Kad-DHT
 *
 * Porta 0 = aleatória → evita fingerprinting por porta fixa.
 * Etapa 4: chave privada do PeerID persistida em ~/.p2p-secure/libp2p.key
 * Etapa 5 adiciona: relay, anti-Sybil, rendezvous rotativo.
 */
"use strict";

const fs   = require("node:fs");
const path = require("node:path");
const os   = require("node:os");

const DATA_DIR        = path.join(os.homedir(), ".p2p-secure");
const LIBP2P_KEY_FILE = path.join(DATA_DIR, "libp2p.key");
const LOCK_FILE       = path.join(DATA_DIR, "daemon.lock");

// Garante que o diretório de dados existe
if (!fs.existsSync(DATA_DIR)) fs.mkdirSync(DATA_DIR, { recursive: true, mode: 0o700 });

/**
 * Tenta adquirir o lock de instância única.
 * Retorna true se esta instância adquiriu o lock (é a primária).
 * Retorna false se outro processo já tem o lock (instância secundária).
 */
function _tryAcquireLock() {
  if (fs.existsSync(LOCK_FILE)) {
    try {
      const pid = parseInt(fs.readFileSync(LOCK_FILE, "utf8").trim(), 10);
      if (pid && pid !== process.pid && _isProcessAlive(pid)) {
        console.log(`[Factory] Outra inst\u00e2ncia ativa (PID ${pid}) \u2014 usando chave ef\u00eamera`);
        return false; // outra instância está rodando
      }
    } catch { /* lock corrompido — sobrescrever */ }
  }
  fs.writeFileSync(LOCK_FILE, String(process.pid), { mode: 0o600 });
  process.on("exit", () => { try { fs.unlinkSync(LOCK_FILE); } catch {} });
  return true;
}

function _isProcessAlive(pid) {
  try {
    process.kill(pid, 0);
    return true; // sem erro = processo existe
  } catch (e) {
    return e.code === "EPERM"; // EPERM = existe mas sem permissão; ESRCH = não existe
  }
}

/**
 * Carrega ou gera o keypair Ed25519 de identidade libp2p.
 * Instância primária: usa chave persistida em LIBP2P_KEY_FILE (PeerID estável).
 * Instância secundária (outro processo já tem o lock): chave efêmera (PeerID único).
 */
async function _loadOrCreateLibp2pKey() {
  const { generateKeyPair, privateKeyFromProtobuf, privateKeyToProtobuf } = await import("@libp2p/crypto/keys");

  const isPrimary = _tryAcquireLock();

  if (isPrimary && fs.existsSync(LIBP2P_KEY_FILE)) {
    try {
      const raw = fs.readFileSync(LIBP2P_KEY_FILE);
      const key = privateKeyFromProtobuf(raw);
      console.log("[Factory] Chave libp2p carregada do disco ✓");
      return key;
    } catch (err) {
      console.warn("[Factory] Falha ao carregar chave libp2p — gerando nova:", err.message);
    }
  }

  // Primeira execução, arquivo corrompido, ou instância secundária — gerar nova chave
  const key = await generateKeyPair("Ed25519");

  if (isPrimary) {
    const proto = privateKeyToProtobuf(key);
    fs.writeFileSync(LIBP2P_KEY_FILE, proto, { mode: 0o600 });
    console.log("[Factory] Nova chave libp2p gerada e salva ✓");
  } else {
    console.log("[Factory] Chave efêmera gerada (instância secundária) ✓");
  }

  return key;
}

// libp2p v3+ é ESM-only — usa dynamic import para compatibilidade com CJS
async function createLibp2pNode() {
  const privateKey = await _loadOrCreateLibp2pKey();

  const { createLibp2p } = await import("libp2p");
  const { tcp }          = await import("@libp2p/tcp");
  const { webSockets }   = await import("@libp2p/websockets");
  const { noise }        = await import("@libp2p/noise");
  const { mplex }        = await import("@libp2p/mplex");
  const { identify }     = await import("@libp2p/identify");
  const { kadDHT }       = await import("@libp2p/kad-dht");
  const { ping }         = await import("@libp2p/ping");

  return createLibp2p({
    privateKey,
    addresses: {
      listen: [
        "/ip4/0.0.0.0/tcp/0",
        "/ip4/0.0.0.0/tcp/0/ws",
      ],
    },
    transports:           [tcp(), webSockets()],
    connectionEncrypters: [noise()],   // Noise XX — autenticado + confidencial
    streamMuxers:         [mplex()],
    services: {
      identify: identify(),
      ping:     ping(),
      dht:      kadDHT({ clientMode: false }),
    },
    connectionManager: {
      maxConnections: 50,
      minConnections: 2,
    },
  });
}

module.exports = { createLibp2pNode };
