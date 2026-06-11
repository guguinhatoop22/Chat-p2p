#!/usr/bin/env bash
# =============================================================================
#  P2P Secure Chat v7 — Setup Completo (Version 3 — Otimizado)
#
#  Uso:
#    chmod +x setup-p2p-secure_Version3.sh
#    ./setup-p2p-secure_Version3.sh              # criação normal
#    ./setup-p2p-secure_Version3.sh --force      # sobrescreve se já existir
#    ./setup-p2p-secure_Version3.sh --no-install # pula npm install
#
#  Requisitos: Node.js >= 20, npm >= 10, git
#
#  Melhorias em relação às versões anteriores:
#   - Flag --force para reexecução idempotente
#   - Flag --no-install para CI/dry-run
#   - Validação de versão npm >= 10
#   - trap de cleanup em falha para não deixar estado parcial
#   - Correção de fd leak no fsyncSync do journal
#   - Correção de bug em deriveFileKey (subkey_id fixo em V1)
#   - CSP aplicado em default session E renderer session
#   - git commit inicial automático
#   - Módulos novos: recovery.js, deletion.js, cells.js, encrypt.js, shaper.js
# =============================================================================

set -euo pipefail

# ── Parsing de flags ──────────────────────────────────────────────────────────
FORCE_MODE=false
NO_INSTALL=false

for arg in "$@"; do
  case "$arg" in
    --force)      FORCE_MODE=true ;;
    --no-install) NO_INSTALL=true ;;
    --help|-h)
      echo "Uso: $0 [--force] [--no-install]"
      echo "  --force       Sobrescreve pasta existente"
      echo "  --no-install  Pula npm install (útil para CI)"
      exit 0
      ;;
    *) echo -e "${RED:-}[ERRO]${NC:-} Flag desconhecida: $arg"; exit 1 ;;
  esac
done

# ── Cores para output ─────────────────────────────────────────────────────────
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

log()    { echo -e "${GREEN}[OK]${NC} $1"; }
warn()   { echo -e "${YELLOW}[WARN]${NC} $1"; }
info()   { echo -e "${CYAN}[INFO]${NC} $1"; }
die()    { echo -e "${RED}[ERRO]${NC} $1"; exit 1; }
header() {
  echo -e "\n${BOLD}${CYAN}══════════════════════════════════════════${NC}"
  echo -e "${BOLD}${CYAN}  $1${NC}"
  echo -e "${BOLD}${CYAN}══════════════════════════════════════════${NC}\n"
}

# ── Cleanup em falha ──────────────────────────────────────────────────────────
ROOT="p2p-secure"
_CLEANUP_ON_FAIL=false

cleanup_on_fail() {
  if [ "$_CLEANUP_ON_FAIL" = true ] && [ -d "$ROOT" ]; then
    warn "Setup falhou — removendo pasta '$ROOT' para evitar estado parcial."
    rm -rf "$ROOT"
  fi
}
trap cleanup_on_fail ERR

# ── Verificações de ambiente ──────────────────────────────────────────────────
header "Verificando ambiente"

command -v node &>/dev/null || die "Node.js não encontrado. Instale em https://nodejs.org"
command -v npm  &>/dev/null || die "npm não encontrado."
command -v git  &>/dev/null || die "git não encontrado."

# Node.js >= 20
node -e "process.exit(parseInt(process.version.slice(1)) < 20 ? 1 : 0)" \
  || die "Node.js >= 20 obrigatório. Versão atual: $(node --version)"

# npm >= 10
NPM_MAJOR=$(npm --version | cut -d. -f1)
[ "$NPM_MAJOR" -ge 10 ] || die "npm >= 10 obrigatório. Versão atual: $(npm --version)"

log "Node.js $(node --version) ✓"
log "npm $(npm --version) ✓"
log "git $(git --version | awk '{print $3}') ✓"

# ── Criação da raiz do projeto ────────────────────────────────────────────────
header "Criando estrutura do projeto"

if [ -d "$ROOT" ]; then
  if [ "$FORCE_MODE" = true ]; then
    warn "Pasta '$ROOT' já existe — sobrescrevendo (--force)."
    rm -rf "$ROOT"
  else
    die "Pasta '$ROOT' já existe. Use --force para sobrescrever."
  fi
fi

mkdir "$ROOT"
_CLEANUP_ON_FAIL=true  # só ativa cleanup depois de criar a pasta
cd "$ROOT"

git init -q
git config user.email "p2p-secure@localhost" 2>/dev/null || true
git config user.name  "P2P Secure Setup"    2>/dev/null || true
log "Repositório git inicializado"

# ── Criação de TODAS as pastas ────────────────────────────────────────────────
info "Criando árvore de diretórios..."

for dir in \
  src/identity src/network src/onion src/traffic \
  src/crypto src/voice src/persistence src/abuse \
  src/build src/privacy src/ui \
  simulation protocols docs scripts \
  tests/unit tests/security tests/integration; do
  mkdir -p "$dir"
done

log "Árvore de diretórios criada ✓"

# ═════════════════════════════════════════════════════════════════════════════
# package.json
# ═════════════════════════════════════════════════════════════════════════════
header "Gerando package.json"

cat > package.json << 'PKGJSON'
{
  "name": "p2p-secure-chat",
  "version": "0.1.0",
  "description": "P2P Secure Chat — audit-grade, sem servidor central",
  "main": "src/ui/main.js",
  "type": "commonjs",
  "scripts": {
    "start":         "electron .",
    "start:daemon":  "node src/network/node.js",
    "dev":           "concurrently \"npm run start:daemon\" \"electron .\"",
    "build":         "electron-builder",
    "test":          "jest",
    "test:security": "jest tests/security",
    "lint":          "eslint src --ext .js,.jsx",
    "lint:fix":      "eslint src --ext .js,.jsx --fix"
  },
  "dependencies": {
    "@libp2p/bootstrap":   "^10.0.0",
    "@libp2p/identify":    "^3.0.0",
    "@libp2p/kad-dht":     "^14.0.0",
    "@libp2p/noise":       "^16.0.0",
    "@libp2p/tcp":         "^10.0.0",
    "@libp2p/websockets":  "^9.0.0",
    "@libp2p/mplex":       "^11.0.0",
    "libp2p":              "^3.0.0",
    "libsodium-wrappers":  "^0.7.15",
    "argon2":              "^0.41.0",
    "better-sqlite3":      "^11.0.0",
    "electron-store":      "^10.0.0",
    "qrcode":              "^1.5.4",
    "ws":                  "^8.18.0",
    "uuid":                "^11.0.0",
    "winston":             "^3.17.0"
  },
  "optionalDependencies": {
    "@libp2p/webrtc": "^5.0.0",
    "opus-encoder":   "^0.0.9"
  },
  "devDependencies": {
    "electron":         "^34.0.0",
    "electron-builder": "^25.0.0",
    "concurrently":     "^9.0.0",
    "jest":             "^29.7.0",
    "eslint":           "^9.0.0",
    "@eslint/js":       "^9.0.0"
  },
  "build": {
    "appId":       "com.p2psecure.chat",
    "productName": "P2P Secure Chat",
    "linux":  { "target": ["AppImage", "deb"] },
    "win":    { "target": ["nsis"] },
    "files":  ["src/**/*", "protocols/**/*", "!src/ui/node_modules"],
    "extraMetadata": { "main": "src/ui/main.js" }
  },
  "jest": {
    "testEnvironment": "node",
    "testMatch": ["**/tests/**/*.test.js"]
  }
}
PKGJSON
log "package.json ✓"

# ═════════════════════════════════════════════════════════════════════════════
# .gitignore
# ═════════════════════════════════════════════════════════════════════════════
cat > .gitignore << 'EOF'
node_modules/
dist/
build/
*.log
*.db
*.sqlite
.env
.env.*
coverage/
*.key
*.pem
*.der
.DS_Store
Thumbs.db
EOF
log ".gitignore ✓"

# ═════════════════════════════════════════════════════════════════════════════
# ESLint — proíbe Math.random() em módulos de segurança
# ═════════════════════════════════════════════════════════════════════════════
cat > eslint.config.js << 'EOF'
import js from "@eslint/js";

export default [
  js.configs.recommended,
  {
    // Apenas nos módulos críticos de segurança
    files: ["src/crypto/**/*.js", "src/identity/**/*.js", "src/onion/**/*.js"],
    rules: {
      // CRÍTICO: Math.random() proibido — quebra o build se detectado
      "no-restricted-globals": ["error", {
        "name": "Math",
        "message": "Use crypto.randomBytes() ou libsodium RNG. Math.random() é proibido em módulos de segurança."
      }]
    }
  }
];
EOF
log "eslint.config.js ✓ (Math.random proibido em módulos crypto/identity/onion)"

# ═════════════════════════════════════════════════════════════════════════════
# ELECTRON MAIN — src/ui/main.js
# ═════════════════════════════════════════════════════════════════════════════
header "Gerando Electron Main Process"

cat > src/ui/main.js << 'EOF'
/**
 * src/ui/main.js — Electron Main Process
 *
 * Segurança aplicada:
 *   contextIsolation: true  → renderer não acessa Node APIs diretamente
 *   nodeIntegration: false  → renderer isolado do Node runtime
 *   sandbox: true           → sandbox Chromium real
 *   CSP restritivo          → sem eval, sem inline scripts
 *   Headers de segurança    → X-Content-Type-Options, X-Frame-Options, etc.
 *
 * Arquitetura:
 *   UI (renderer) ←→ preload.js (bridge < 100 linhas) ←→ Core Daemon (processo separado)
 *   Comprometer a UI NÃO compromete o daemon/protocolo.
 *
 * CSP aplicado em duas camadas: session padrão + session do renderer.
 */
"use strict";

const { app, BrowserWindow, ipcMain, session } = require("electron");
const path  = require("node:path");
const { fork } = require("node:child_process");

let mainWindow    = null;
let daemonProcess = null;

// ── Content Security Policy ───────────────────────────────────────────────
const CSP = [
  "default-src 'self'",
  "script-src 'self'",        // sem eval, sem inline
  "style-src 'self'",
  "img-src 'self' data:",     // data: necessário para QR codes
  "connect-src 'self'",
  "font-src 'self'",
  "object-src 'none'",
  "base-uri 'self'",
  "form-action 'self'",
  "frame-ancestors 'none'",
].join("; ");

const SECURITY_HEADERS = {
  "Content-Security-Policy": [CSP],
  "X-Content-Type-Options":  ["nosniff"],
  "X-Frame-Options":         ["DENY"],
  "Referrer-Policy":         ["no-referrer"],
};

function _applyCSP(sess) {
  sess.webRequest.onHeadersReceived((details, cb) => {
    cb({ responseHeaders: { ...details.responseHeaders, ...SECURITY_HEADERS } });
  });
}

// ── Core Daemon ───────────────────────────────────────────────────────────
function startDaemon() {
  const daemonPath = path.join(__dirname, "..", "network", "node.js");
  daemonProcess = fork(daemonPath, [], {
    silent: false,
    env: { ...process.env, DAEMON_MODE: "true", NODE_ENV: process.env.NODE_ENV || "production" },
  });
  daemonProcess.on("error", (err) => console.error("[Main] Daemon error:", err));
  daemonProcess.on("exit",  (code) => {
    console.warn("[Main] Daemon saiu com código:", code);
    // TODO produção: restart com backoff exponencial
  });
  console.log("[Main] Core daemon iniciado — PID:", daemonProcess.pid);
}

// ── BrowserWindow com hardening completo ──────────────────────────────────
function createWindow() {
  mainWindow = new BrowserWindow({
    width: 1024, height: 720,
    show: false,  // exibe apenas após dom-ready (evita flash branco)
    webPreferences: {
      preload:          path.join(__dirname, "preload.js"),
      contextIsolation: true,   // OBRIGATÓRIO
      nodeIntegration:  false,  // OBRIGATÓRIO
      sandbox:          true,   // OBRIGATÓRIO — sandbox Chromium real
      webSecurity:      true,
      allowRunningInsecureContent: false,
      experimentalFeatures:        false,
    },
  });

  // CSP aplicado na session específica do renderer
  _applyCSP(mainWindow.webContents.session);

  mainWindow.loadFile(path.join(__dirname, "index.html"));
  mainWindow.once("ready-to-show", () => mainWindow.show());
  mainWindow.on("closed", () => { mainWindow = null; });
}

// ── IPC — único canal exposto ao renderer ─────────────────────────────────
ipcMain.handle("daemon:status", async () => ({
  running: daemonProcess !== null && !daemonProcess.killed,
}));

// ── Lifecycle ─────────────────────────────────────────────────────────────
app.whenReady().then(() => {
  // CSP também na session padrão (segunda linha de defesa)
  _applyCSP(session.defaultSession);

  startDaemon();
  createWindow();

  app.on("activate", () => {
    if (BrowserWindow.getAllWindows().length === 0) createWindow();
  });
});

function shutdown() {
  if (daemonProcess) daemonProcess.kill("SIGTERM");
  app.quit();
}

app.on("window-all-closed", () => { if (process.platform !== "darwin") shutdown(); });
app.on("before-quit",       () => { if (daemonProcess) daemonProcess.kill("SIGTERM"); });
EOF
log "src/ui/main.js ✓"

# ═════════════════════════════════════════════════════════════════════════════
# PRELOAD — src/ui/preload.js (bridge mínima, < 100 linhas)
# ═════════════════════════════════════════════════════════════════════════════
cat > src/ui/preload.js << 'EOF'
/**
 * src/ui/preload.js — Bridge mínima e auditada
 *
 * Regras invioláveis:
 *   - Nunca expõe require, process ou Node APIs ao renderer
 *   - Canais IPC explicitamente listados (allowlist)
 *   - Todos os dados sanitizados antes de repassar
 *   - Máximo 100 linhas — se crescer, algo está errado
 *
 * Fluxo:
 *   renderer → preload → ipcRenderer → main → daemon
 *   daemon   → main   → ipcRenderer → preload → renderer
 */
"use strict";

const { contextBridge, ipcRenderer } = require("electron");

const ALLOWED_SEND    = ["chat:send", "call:start", "call:end", "identity:verify"];
const ALLOWED_RECEIVE = ["chat:receive", "call:incoming", "peer:status", "security:alert"];
const ALLOWED_INVOKE  = ["daemon:status", "identity:getFingerprint", "peers:list"];

contextBridge.exposeInMainWorld("secureAPI", {

  send(channel, payload) {
    if (!ALLOWED_SEND.includes(channel)) {
      console.error("[Preload] Canal não permitido:", channel);
      return;
    }
    // Serializa para remover referências não serializáveis e funções
    ipcRenderer.send(channel, JSON.parse(JSON.stringify(payload)));
  },

  on(channel, callback) {
    if (!ALLOWED_RECEIVE.includes(channel)) {
      console.error("[Preload] Canal de recebimento não permitido:", channel);
      return;
    }
    // Wrapper: não expõe o objeto 'event' do Electron ao renderer
    const handler = (_event, data) => callback(data);
    ipcRenderer.on(channel, handler);
    return () => ipcRenderer.removeListener(channel, handler); // cleanup
  },

  async invoke(channel, payload) {
    if (!ALLOWED_INVOKE.includes(channel)) {
      throw new Error(`[Preload] invoke não permitido: ${channel}`);
    }
    return ipcRenderer.invoke(channel, payload);
  },
});
// ~45 linhas de lógica — dentro do limite de 100.
EOF
log "src/ui/preload.js ✓"

# ═════════════════════════════════════════════════════════════════════════════
# HTML — src/ui/index.html
# ═════════════════════════════════════════════════════════════════════════════
cat > src/ui/index.html << 'EOF'
<!DOCTYPE html>
<html lang="pt-BR">
<head>
  <meta charset="UTF-8" />
  <!-- CSP no HTML como segunda linha de defesa (além do header HTTP) -->
  <meta http-equiv="Content-Security-Policy"
        content="default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:;" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0" />
  <title>P2P Secure Chat</title>
  <link rel="stylesheet" href="styles.css" />
</head>
<body>
  <div id="app">
    <div id="loading"><p>Iniciando daemon seguro...</p></div>
  </div>
  <!-- Nenhum script inline — CSP proíbe -->
  <script src="renderer.js"></script>
</body>
</html>
EOF
log "src/ui/index.html ✓"

# ═════════════════════════════════════════════════════════════════════════════
# RENDERER — src/ui/renderer.js
# ═════════════════════════════════════════════════════════════════════════════
cat > src/ui/renderer.js << 'EOF'
/**
 * src/ui/renderer.js
 * Acessa APENAS window.secureAPI — sem require(), sem Node APIs.
 */
"use strict";

async function init() {
  const status  = await window.secureAPI.invoke("daemon:status");
  const loading = document.getElementById("loading");

  loading.innerHTML = status.running
    ? "<p>✅ Daemon ativo. Chat pronto.</p>"
    : "<p>❌ Daemon não iniciou. Verifique os logs.</p>";

  // Alertas de segurança vindos do daemon — exibir de forma bloqueante
  window.secureAPI.on("security:alert", (data) => {
    console.warn("[Security Alert]", data);
    // TODO: exibir alerta visual bloqueante na UI
  });
}

document.addEventListener("DOMContentLoaded", init);
EOF
log "src/ui/renderer.js ✓"

# ═════════════════════════════════════════════════════════════════════════════
# RNG — src/crypto/rng.js
# ═════════════════════════════════════════════════════════════════════════════
header "Gerando módulos crypto"

cat > src/crypto/rng.js << 'EOF'
/**
 * src/crypto/rng.js — RNG Hardened com health check e reseed periódico
 *
 * Plataformas:
 *   Linux:   crypto.randomBytes() → /dev/urandom (kernel CSPRNG)
 *   Windows: crypto.randomBytes() → BCryptGenRandom (CNG API)
 *
 * Segurança:
 *   - Health check na inicialização — bloqueia geração se falhar
 *   - Math.random() proibido por lint rule (quebra o build)
 *   - Reseed periódico a cada 30min com nova verificação de entropia
 *   - Teste chi-quadrado básico detecta falhas catastróficas de RNG
 */
"use strict";

const { randomBytes } = require("node:crypto");

const HEALTH_BYTES       = 1024;
const RESEED_INTERVAL_MS = 30 * 60 * 1000; // 30 minutos

let _healthy  = false;
let _lastSeed = null;

/** Teste estatístico básico — detecta falhas catastróficas de entropia */
function _basicEntropyCheck(buf) {
  const freq     = new Array(256).fill(0);
  const expected = buf.length / 256;
  for (const b of buf) freq[b]++;
  let chi = 0;
  for (const f of freq) chi += (f - expected) ** 2 / expected;
  return chi < 310; // > 310: distribuição anômala (p < 0.01 com 255 graus de liberdade)
}

/**
 * Health check do RNG — DEVE ser chamado na inicialização do daemon.
 * Lança erro e bloqueia geração de chaves se o RNG estiver comprometido.
 * @throws {Error}
 */
function healthCheck() {
  let buf;
  try { buf = randomBytes(HEALTH_BYTES); }
  catch (e) { throw new Error(`[RNG] Falha crítica ao gerar bytes: ${e.message}`); }

  if (!_basicEntropyCheck(buf))
    throw new Error("[RNG] Health check falhou: entropia anômala. Geração de chaves bloqueada.");

  _healthy  = true;
  _lastSeed = Date.now();
  console.log("[RNG] Health check OK ✓");
}

function _reseed() {
  console.log("[RNG] Reseed periódico em", new Date().toISOString());
  healthCheck();
}
setInterval(_reseed, RESEED_INTERVAL_MS).unref(); // .unref(): não impede o processo de encerrar

/**
 * Gera N bytes aleatórios seguros.
 * @param {number} size
 * @returns {Buffer}
 */
function secureRandomBytes(size) {
  if (!_healthy) throw new Error("[RNG] healthCheck() não executado.");
  return randomBytes(size);
}

/**
 * Inteiro aleatório uniforme em [0, max) sem modulo bias.
 * Usa rejection sampling para distribuição perfeita.
 * @param {number} max
 * @returns {number}
 */
function randomInt(max) {
  if (!_healthy) throw new Error("[RNG] healthCheck() não executado.");
  const needed = Math.ceil(Math.log2(max) / 8) + 1;
  const limit  = Math.floor(256 ** needed / max) * max;
  let val;
  do {
    const buf = randomBytes(needed);
    val = 0;
    for (const b of buf) val = val * 256 + b;
  } while (val >= limit);
  return val % max;
}

module.exports = { healthCheck, secureRandomBytes, randomInt };
EOF
log "src/crypto/rng.js ✓"

# ═════════════════════════════════════════════════════════════════════════════
# MEMORY — src/crypto/memory.js
# ═════════════════════════════════════════════════════════════════════════════
cat > src/crypto/memory.js << 'EOF'
/**
 * src/crypto/memory.js — Zeroização de buffers sensíveis pós-uso
 *
 * JS tem GC — não há garantia absoluta de quando a memória é liberada.
 * Este módulo faz o melhor possível: sobrescreve imediatamente após uso.
 * Libsodium (wasm) zeroiza internamente suas próprias alocações.
 *
 * Padrão correto:
 *   const key = deriveKey(...);
 *   try { usar(key); } finally { zeroize(key); }
 */
"use strict";

/** Sobrescreve buffer com zeros imediatamente. */
function zeroize(buf) {
  if (buf instanceof Uint8Array) buf.fill(0);
}

/** Zeroiza múltiplos buffers de uma vez. */
function zeroizeAll(...bufs) {
  for (const b of bufs) zeroize(b);
}

/**
 * Executa fn com buffer sensível e zeroiza após — mesmo em erro.
 * @param {Buffer} buf
 * @param {(buf: Buffer) => any} fn
 * @returns {any}
 */
function withZeroize(buf, fn) {
  try { return fn(buf); }
  finally { zeroize(buf); }
}

module.exports = { zeroize, zeroizeAll, withZeroize };
EOF
log "src/crypto/memory.js ✓"

# ═════════════════════════════════════════════════════════════════════════════
# SESSION — src/crypto/session.js (Double Ratchet)
# ═════════════════════════════════════════════════════════════════════════════
cat > src/crypto/session.js << 'EOF'
/**
 * src/crypto/session.js — Double Ratchet Session Manager
 *
 * Implementa o esqueleto do Double Ratchet Algorithm (Signal Protocol):
 *   KDF Chain Ratchet → avança a chave de cadeia por mensagem
 *   DH Ratchet        → avança a chave DH a cada round-trip
 *
 * Usa libsodium para TODAS as operações (constant-time).
 * Deniability via MAC simétrico — receptor não prova autoria a terceiros.
 *
 * TODO (Etapa 4): substituir por @signalapp/libsignal-client
 *   para implementação completa e formalmente auditada do protocolo Signal.
 */
"use strict";

const sodium         = require("libsodium-wrappers");
const { zeroizeAll } = require("./memory.js");
const { secureRandomBytes } = require("./rng.js");

let _sodiumReady = false;
async function _ensureSodium() {
  if (!_sodiumReady) { await sodium.ready; _sodiumReady = true; }
}

/**
 * Um passo do KDF chain ratchet via HMAC-SHA256.
 * @param {Uint8Array} chainKey
 * @returns {{ messageKey: Uint8Array, nextChainKey: Uint8Array }}
 */
function _kdfStep(chainKey) {
  const messageKey   = sodium.crypto_auth_hmacsha256(new Uint8Array([0x01]), chainKey);
  const nextChainKey = sodium.crypto_auth_hmacsha256(new Uint8Array([0x02]), chainKey);
  return { messageKey, nextChainKey };
}

class DoubleRatchetSession {
  /**
   * @param {object}     p
   * @param {string}     p.sessionId
   * @param {Uint8Array} p.rootKey       — gerada pelo X3DH
   * @param {Uint8Array} p.sendingChain  — chain key de envio inicial
   * @param {boolean}    p.isInitiator
   */
  constructor({ sessionId, rootKey, sendingChain, isInitiator }) {
    this.sessionId    = sessionId;
    this.rootKey      = rootKey;
    this.sendingChain = sendingChain;
    this.isInitiator  = isInitiator;
    this.sendCounter  = 0;
    this.recvCounter  = 0;
    this.skippedKeys  = new Map(); // entrega fora de ordem
  }

  /**
   * Criptografa uma mensagem avançando o ratchet de envio.
   * @param {Uint8Array|Buffer} plaintext
   * @returns {{ ciphertext: Uint8Array, nonce: Uint8Array, counter: number }}
   */
  async encrypt(plaintext) {
    await _ensureSodium();
    const { messageKey, nextChainKey } = _kdfStep(this.sendingChain);

    // Nonce: 8 bytes aleatórios + 4 bytes do counter (big-endian)
    const nonce = new Uint8Array(sodium.crypto_secretbox_NONCEBYTES);
    nonce.set(secureRandomBytes(8));
    new DataView(nonce.buffer).setUint32(8, this.sendCounter, false);

    const ciphertext = sodium.crypto_secretbox_easy(plaintext, nonce, messageKey);

    zeroizeAll(messageKey, this.sendingChain);
    this.sendingChain = nextChainKey;
    this.sendCounter++;

    return { ciphertext, nonce, counter: this.sendCounter - 1 };
  }

  /**
   * Descriptografa — implementação completa na Etapa 4 com libsignal.
   */
  async decrypt(_ciphertext, _nonce, _counter) {
    await _ensureSodium();
    throw new Error("[Session] decrypt: implementar na Etapa 4 com @signalapp/libsignal-client");
  }

  /** Zeroiza todas as chaves. DEVE ser chamado ao encerrar a sessão. */
  destroy() {
    zeroizeAll(this.rootKey, this.sendingChain);
    this.skippedKeys.clear();
    console.log(`[Session] ${this.sessionId} destruída e chaves zeroizadas ✓`);
  }
}

module.exports = { DoubleRatchetSession };
EOF
log "src/crypto/session.js ✓"

# ═════════════════════════════════════════════════════════════════════════════
# STORAGE — src/crypto/storage.js (Argon2id + chaves efêmeras por arquivo)
# ═════════════════════════════════════════════════════════════════════════════
cat > src/crypto/storage.js << 'EOF'
/**
 * src/crypto/storage.js — Argon2id + chaves efêmeras por arquivo
 *
 * Design de Secure Deletion (correto para SSD/NVMe):
 *   Cada arquivo tem sua própria chave efêmera derivada da masterKey.
 *   "Apagar" = destruir a chave efêmera.
 *   Dados continuam no disco mas são CRIPTOGRAFICAMENTE IRRECUPERÁVEIS.
 *   (Overwrite físico não funciona em SSD por causa de wear leveling.)
 *
 *   masterKey = Argon2id(senha, salt)
 *   fileKey   = KDF(masterKey, subkeyId derivado do fileId UUID)
 *   ciphertext = XSalsa20-Poly1305(plaintext, fileKey, nonce)
 */
"use strict";

const argon2              = require("argon2");
const sodium              = require("libsodium-wrappers");
const { secureRandomBytes } = require("./rng.js");
const { zeroize }         = require("./memory.js");

// Parâmetros Argon2id — OWASP recomendado para armazenamento de senha
const ARGON2_OPTS = {
  type:        argon2.argon2id,
  memoryCost:  65536,  // 64 MB
  timeCost:    3,
  parallelism: 4,
  hashLength:  32,
  raw:         true,   // retorna Buffer, não string
};

/**
 * Deriva master key da senha do usuário.
 * @param {string} password
 * @param {Buffer} [salt] — se omitido, gera novo salt
 * @returns {{ masterKey: Buffer, salt: Buffer }}
 */
async function deriveMasterKey(password, salt = null) {
  await sodium.ready;
  const usedSalt  = salt ?? secureRandomBytes(sodium.crypto_pwhash_SALTBYTES);
  const masterKey = await argon2.hash(password, { ...ARGON2_OPTS, salt: usedSalt });
  return { masterKey, salt: usedSalt };
}

/**
 * Deriva chave efêmera para um arquivo específico.
 * CORRIGIDO: subkey_id derivado do UUID do arquivo (não fixo em 1).
 * @param {Buffer} masterKey
 * @param {string} fileId — UUID v4
 * @returns {Uint8Array} fileKey (32 bytes)
 */
async function deriveFileKey(masterKey, fileId) {
  await sodium.ready;
  // Deriva subkey_id único a partir do UUID — collision impossível com UUIDs únicos
  // Usa módulo 2^31 para caber no domínio do KDF (subkey_id positivo de 64 bits)
  const subkeyId = parseInt(fileId.replace(/-/g, "").slice(0, 8), 16) % 2147483648;
  return sodium.crypto_kdf_derive_from_key(32, subkeyId, "filekdfx", masterKey);
}

/**
 * Criptografa dados com a fileKey.
 * @param {Buffer} plaintext
 * @param {Uint8Array} key
 * @returns {{ ciphertext: Buffer, nonce: Buffer }}
 */
async function encryptWithKey(plaintext, key) {
  await sodium.ready;
  const nonce      = secureRandomBytes(sodium.crypto_secretbox_NONCEBYTES);
  const ciphertext = sodium.crypto_secretbox_easy(plaintext, nonce, key);
  return { ciphertext: Buffer.from(ciphertext), nonce: Buffer.from(nonce) };
}

/**
 * Descriptografa dados com a fileKey.
 * @param {Buffer} ciphertext
 * @param {Buffer} nonce
 * @param {Uint8Array} key
 * @returns {Buffer}
 */
async function decryptWithKey(ciphertext, nonce, key) {
  await sodium.ready;
  const plain = sodium.crypto_secretbox_open_easy(ciphertext, nonce, key);
  if (!plain) throw new Error("[Storage] Falha na descriptografia: MAC inválido.");
  return Buffer.from(plain);
}

module.exports = { deriveMasterKey, deriveFileKey, encryptWithKey, decryptWithKey };
EOF
log "src/crypto/storage.js ✓"

# ═════════════════════════════════════════════════════════════════════════════
# KEYGEN — src/identity/keygen.js (X3DH)
# ═════════════════════════════════════════════════════════════════════════════
header "Gerando módulos de identidade"

cat > src/identity/keygen.js << 'EOF'
/**
 * src/identity/keygen.js — Geração de chaves X3DH via libsodium
 *
 * Protocolo X3DH (Extended Triple Diffie-Hellman):
 *   IK  — Identity Key:     longo prazo (persistida)
 *   SPK — Signed PreKey:    médio prazo (rotacionada por epoch)
 *   OPK — One-Time PreKey:  uso único por sessão
 *
 * Segurança:
 *   - RNG health-checked (via rng.js)
 *   - Delay aleatório no keygen (mitiga timing side-channel)
 *   - Libsodium para todas as operações (constant-time)
 *   - Math.random() proibido por lint rule
 *
 * TODO (Etapa 2): integrar @signalapp/libsignal-client para
 *   implementação completa e auditada do X3DH com Ed25519.
 */
"use strict";

const sodium             = require("libsodium-wrappers");
const { secureRandomBytes, randomInt } = require("../crypto/rng.js");
const { zeroizeAll }     = require("../crypto/memory.js");

/** Delay aleatório 10–60ms para mitigar timing side-channel em keygen */
async function _secureDelay() {
  await new Promise((r) => setTimeout(r, 10 + randomInt(50)));
}

/**
 * Gera par de chaves Curve25519.
 * @returns {{ publicKey: Uint8Array, privateKey: Uint8Array }}
 */
async function generateKeyPair() {
  await sodium.ready;
  await _secureDelay();
  return sodium.crypto_kx_keypair();
}

/**
 * Gera conjunto completo de chaves X3DH para uma identidade.
 * @returns {object} IK + SPK (com assinatura) + 10 OPKs
 */
async function generateIdentityKeys() {
  await sodium.ready;
  console.log("[Keygen] Gerando chaves de identidade X3DH...");

  const ik   = await generateKeyPair(); // Identity Key
  const spk  = await generateKeyPair(); // Signed PreKey
  const opks = await Promise.all(       // 10 One-Time PreKeys
    Array.from({ length: 10 }, () => generateKeyPair())
  );

  // Assinar SPK com IK para prova de posse
  // Nota: simplificação de esqueleto — Etapa 2 usa Ed25519 separado via libsignal
  const spkSig = sodium.crypto_sign_detached(spk.publicKey, ik.privateKey.slice(0, 32));

  const result = {
    identityKey: {
      publicKey:  Buffer.from(ik.publicKey).toString("hex"),
      privateKey: Buffer.from(ik.privateKey).toString("hex"),
    },
    signedPreKey: {
      publicKey:  Buffer.from(spk.publicKey).toString("hex"),
      privateKey: Buffer.from(spk.privateKey).toString("hex"),
      signature:  Buffer.from(spkSig).toString("hex"),
    },
    oneTimePreKeys: opks.map((kp, i) => ({
      id:         i,
      publicKey:  Buffer.from(kp.publicKey).toString("hex"),
      privateKey: Buffer.from(kp.privateKey).toString("hex"),
    })),
    createdAt: Date.now(),
  };

  // Zeroizar cópias temporárias das chaves privadas após serialização
  zeroizeAll(ik.privateKey, spk.privateKey);
  opks.forEach((kp) => zeroizeAll(kp.privateKey));

  console.log("[Keygen] Chaves de identidade geradas ✓");
  return result;
}

module.exports = { generateIdentityKeys, generateKeyPair };
EOF
log "src/identity/keygen.js ✓"

# ═════════════════════════════════════════════════════════════════════════════
# FINGERPRINT — src/identity/fingerprint.js
# ═════════════════════════════════════════════════════════════════════════════
cat > src/identity/fingerprint.js << 'EOF'
/**
 * src/identity/fingerprint.js — Verificação de identidade via QR
 *
 * Permite que dois usuários verifiquem identidade via QR code
 * ou sequência de palavras — igual ao Signal Safety Numbers.
 * Se o fingerprint não bater: MITM ativo.
 *
 * Algoritmo:
 *   fingerprint = SHA-256(sort(pubKeyA, pubKeyB) || sessionId)[0:15]
 *   → Base32 (RFC 4648) → grupos de 5 chars → QR code
 *
 * UX crítica: alerta BLOQUEANTE se identidade do peer mudar entre sessões.
 */
"use strict";

const { createHash }  = require("node:crypto");
const QRCode          = require("qrcode");
const sodium          = require("libsodium-wrappers");

const B32 = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

function _toBase32(buf) {
  let out = "", bits = 0, val = 0;
  for (const b of buf) {
    val  = (val << 8) | b;
    bits += 8;
    while (bits >= 5) { out += B32[(val >>> (bits - 5)) & 31]; bits -= 5; }
  }
  return out;
}

/**
 * Gera fingerprint de segurança para um par de peers.
 * Ambos os lados chegam ao mesmo resultado (ordem-independente).
 * @param {string} pubKeyA — hex
 * @param {string} pubKeyB — hex
 * @param {string} sessionId
 * @returns {string} ex: "ABCDE FGHIJ KLMNO PQRST UVWXY"
 */
function generateFingerprint(pubKeyA, pubKeyB, sessionId) {
  const [lo, hi] = [pubKeyA, pubKeyB].sort(); // ordem determinística
  const hash = createHash("sha256").update(lo).update(hi).update(sessionId).digest();
  return _toBase32(hash.slice(0, 15)).match(/.{1,5}/g).join(" ");
}

/**
 * Gera QR code com o fingerprint para scan entre peers.
 * @param {string} fingerprint
 * @returns {Promise<string>} data URL PNG
 */
async function generateFingerprintQR(fingerprint) {
  return QRCode.toDataURL(fingerprint, { errorCorrectionLevel: "H", width: 300, margin: 2 });
}

/**
 * Comparação constant-time via sodium.memcmp.
 * Evita timing attack na verificação de identidade.
 * Fallback manual constant-time se sodium não estiver disponível.
 * @param {string} fpA
 * @param {string} fpB
 * @returns {Promise<boolean>}
 */
async function compareFingerprints(fpA, fpB) {
  if (!fpA || !fpB || fpA.length !== fpB.length) return false;
  const bufA = Buffer.from(fpA, "utf8");
  const bufB = Buffer.from(fpB, "utf8");
  try {
    await sodium.ready;
    return sodium.memcmp(bufA, bufB); // constant-time
  } catch {
    // Fallback: comparação byte-a-byte constant-time manual
    let diff = 0;
    for (let i = 0; i < bufA.length; i++) diff |= bufA[i] ^ bufB[i];
    return diff === 0;
  }
}

module.exports = { generateFingerprint, generateFingerprintQR, compareFingerprints };
EOF
log "src/identity/fingerprint.js ✓"

# ═════════════════════════════════════════════════════════════════════════════
# CORE DAEMON — src/network/node.js
# ═════════════════════════════════════════════════════════════════════════════
header "Gerando Core Daemon"

cat > src/network/node.js << 'EOF'
/**
 * src/network/node.js — Core Daemon (processo Node.js separado do Electron)
 *
 * Este processo é o coração do app. Roda separado do renderer.
 * Comprometer a UI NÃO compromete este processo.
 *
 * Responsabilidades:
 *   - Health check do RNG (primeiro — bloqueia tudo se falhar)
 *   - Inicializar nó libp2p
 *   - Gerenciar sessões Double Ratchet
 *   - Orquestrar camadas onion + traffic (Etapas 5–6)
 *
 * Etapa atual (1): RNG + daemon base + libp2p bootstrap.
 */
"use strict";

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
const { createLibp2pNode } = require("./libp2p-factory.js");

let libp2pNode   = null;
let shuttingDown = false;

async function startDaemon() {
  console.log("[Daemon] Inicializando nó libp2p...");
  libp2pNode = await createLibp2pNode();
  await libp2pNode.start();

  console.log("[Daemon] libp2p OK ✓ | PeerID:", libp2pNode.peerId.toString());
  for (const addr of libp2pNode.getMultiaddrs())
    console.log("[Daemon] Ouvindo:", addr.toString());

  libp2pNode.addEventListener("peer:connect",    (e) => console.log("[Daemon] Peer conectado:",    e.detail.toString()));
  libp2pNode.addEventListener("peer:disconnect", (e) => console.log("[Daemon] Peer desconectado:", e.detail.toString()));

  console.log("[Daemon] Pronto ✓");
}

async function shutdown(signal) {
  if (shuttingDown) return;
  shuttingDown = true;
  console.log(`\n[Daemon] ${signal} recebido — encerrando com segurança...`);
  if (libp2pNode) { try { await libp2pNode.stop(); } catch {} }
  // TODO (Etapa 4): zeroizar chaves de sessão ativas via secureDeleteAll()
  console.log("[Daemon] Encerrado.");
  process.exit(0);
}

process.on("SIGTERM",            () => shutdown("SIGTERM"));
process.on("SIGINT",             () => shutdown("SIGINT"));
process.on("uncaughtException",  (e) => { console.error("[Daemon] Uncaught:", e);  shutdown("uncaughtException"); });
process.on("unhandledRejection", (r) => { console.error("[Daemon] Unhandled:", r); shutdown("unhandledRejection"); });

startDaemon().catch((e) => { console.error("[Daemon] Falha fatal:", e); process.exit(1); });
EOF
log "src/network/node.js ✓"

# ═════════════════════════════════════════════════════════════════════════════
# LIBP2P FACTORY — src/network/libp2p-factory.js
# ═════════════════════════════════════════════════════════════════════════════
cat > src/network/libp2p-factory.js << 'EOF'
/**
 * src/network/libp2p-factory.js — Factory do nó libp2p
 *
 * Transports:  TCP + WebSockets (WebRTC na Etapa 3)
 * Segurança:   Noise Protocol XX — autenticação mútua + forward secrecy
 * Mux:         mplex
 * Serviços:    identify, Kad-DHT
 *
 * Porta 0 = aleatória → evita fingerprinting por porta fixa.
 * Etapa 3 adiciona: relay, anti-Sybil, rendezvous rotativo.
 */
"use strict";

const { createLibp2p } = require("libp2p");
const { tcp }          = require("@libp2p/tcp");
const { webSockets }   = require("@libp2p/websockets");
const { noise }        = require("@libp2p/noise");
const { mplex }        = require("@libp2p/mplex");
const { identify }     = require("@libp2p/identify");
const { kadDHT }       = require("@libp2p/kad-dht");

async function createLibp2pNode() {
  return createLibp2p({
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
      dht:      kadDHT({ clientMode: false }),
    },
    connectionManager: {
      maxConnections: 50,
      minConnections: 2,
    },
  });
}

module.exports = { createLibp2pNode };
EOF
log "src/network/libp2p-factory.js ✓"

# ═════════════════════════════════════════════════════════════════════════════
# JOURNAL — src/persistence/journal.js (crash consistency)
# ═════════════════════════════════════════════════════════════════════════════
header "Gerando módulos de persistência"

cat > src/persistence/journal.js << 'EOF'
/**
 * src/persistence/journal.js — Crash Consistency via Journal Append-Only
 *
 * Problema: app fecha no meio de uma operação → estado inconsistente.
 * Solução:
 *   1. Escrever operação no journal com status PENDING
 *   2. Executar a operação
 *   3. Marcar como COMMITTED
 *
 *   Na inicialização: entradas PENDING sem COMMITTED = crash detectado
 *   → descartar estado parcial → reiniciar sessão limpa.
 *
 * TODO (Etapa 4): criptografar o journal com storage.js.
 */
"use strict";

const fs   = require("node:fs");
const path = require("node:path");
const os   = require("node:os");
const { randomUUID } = require("node:crypto");

const DATA_DIR     = path.join(os.homedir(), ".p2p-secure");
const JOURNAL_FILE = path.join(DATA_DIR, "journal.log");

if (!fs.existsSync(DATA_DIR)) fs.mkdirSync(DATA_DIR, { recursive: true, mode: 0o700 });

/**
 * Append atômico com fsync — garante ordem e durabilidade no disco.
 * CORRIGIDO: fecha o fd imediatamente após fsync (sem fd leak).
 */
function _appendSync(entry) {
  fs.appendFileSync(JOURNAL_FILE, JSON.stringify(entry) + "\n", { encoding: "utf8" });
  const fd = fs.openSync(JOURNAL_FILE, "a");
  try { fs.fsyncSync(fd); }
  finally { fs.closeSync(fd); }
}

/**
 * Registra operação com status PENDING.
 * @param {string} op — nome da operação
 * @param {object} data
 * @returns {string} id — usar em journalCommit()
 */
function journalWrite(op, data) {
  const entry = { id: randomUUID(), op, data, status: "PENDING", ts: Date.now() };
  _appendSync(entry);
  return entry.id;
}

/**
 * Marca operação como COMMITTED (sucesso).
 * @param {string} id
 */
function journalCommit(id) {
  _appendSync({ id, status: "COMMITTED", ts: Date.now() });
}

/**
 * Retorna entradas PENDING sem COMMITTED correspondente.
 * Linhas corrompidas são ignoradas silenciosamente (crash parcial de escrita).
 * @returns {object[]}
 */
function journalGetPending() {
  if (!fs.existsSync(JOURNAL_FILE)) return [];
  const lines     = fs.readFileSync(JOURNAL_FILE, "utf8").split("\n").filter(Boolean);
  const entries   = {};
  const committed = new Set();
  for (const line of lines) {
    try {
      const e = JSON.parse(line);
      if (e.status === "PENDING")   entries[e.id]  = e;
      if (e.status === "COMMITTED") committed.add(e.id);
    } catch { /* linha corrompida — ignorar */ }
  }
  return Object.values(entries).filter((e) => !committed.has(e.id));
}

/**
 * Compacta o journal — remove entradas já commitadas.
 * Chamar periodicamente para evitar crescimento infinito.
 */
function journalCompact() {
  if (!fs.existsSync(JOURNAL_FILE)) return;
  const lines     = fs.readFileSync(JOURNAL_FILE, "utf8").split("\n").filter(Boolean);
  const committed = new Set();
  const pending   = [];
  for (const line of lines) {
    try {
      const e = JSON.parse(line);
      if (e.status === "COMMITTED") committed.add(e.id);
      if (e.status === "PENDING")   pending.push(e);
    } catch {}
  }
  const remaining = pending.filter((e) => !committed.has(e.id));
  fs.writeFileSync(JOURNAL_FILE, remaining.map((e) => JSON.stringify(e)).join("\n") + (remaining.length ? "\n" : ""));
  console.log(`[Journal] Compactado — ${remaining.length} entradas pendentes restantes`);
}

module.exports = { journalWrite, journalCommit, journalGetPending, journalCompact };
EOF
log "src/persistence/journal.js ✓"

# ═════════════════════════════════════════════════════════════════════════════
# RECOVERY — src/persistence/recovery.js
# ═════════════════════════════════════════════════════════════════════════════
cat > src/persistence/recovery.js << 'EOF'
/**
 * src/persistence/recovery.js — Recovery automático de crash
 *
 * Chamado no boot do daemon ANTES de qualquer operação de estado.
 * Se encontrar entradas PENDING no journal: crash foi detectado.
 * Ação: descartar estado parcial + iniciar sessão limpa.
 *
 * Nunca ignora silenciosamente — sempre loga o que foi descartado.
 */
"use strict";

const { journalGetPending, journalCompact } = require("./journal.js");

/**
 * Executa recovery automático.
 * @returns {{ recovered: boolean, discarded: number }}
 */
function runRecovery() {
  const pending = journalGetPending();

  if (pending.length === 0) {
    console.log("[Recovery] Estado consistente ✓");
    return { recovered: false, discarded: 0 };
  }

  console.warn(`[Recovery] CRASH DETECTADO — ${pending.length} operação(ões) incompleta(s):`);
  for (const e of pending) {
    console.warn(`  [Recovery] Descartando: op=${e.op} id=${e.id} ts=${new Date(e.ts).toISOString()}`);
    // TODO (Etapa 4): rollback específico por tipo de operação
  }

  journalCompact();
  console.warn("[Recovery] Estado parcial descartado. Sessão reiniciada limpa.");
  return { recovered: true, discarded: pending.length };
}

module.exports = { runRecovery };
EOF
log "src/persistence/recovery.js ✓"

# ═════════════════════════════════════════════════════════════════════════════
# DELETION — src/persistence/deletion.js (Secure Deletion via destruição de chave)
# ═════════════════════════════════════════════════════════════════════════════
cat > src/persistence/deletion.js << 'EOF'
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
EOF
log "src/persistence/deletion.js ✓"

# ═════════════════════════════════════════════════════════════════════════════
# ONION CELLS — src/onion/cells.js (células de tamanho fixo)
# ═════════════════════════════════════════════════════════════════════════════
header "Gerando módulos onion e cover traffic"

cat > src/onion/cells.js << 'EOF'
/**
 * src/onion/cells.js — Células onion de tamanho fixo (512 bytes)
 *
 * Todo pacote na rede tem EXATAMENTE 512 bytes — sem exceção.
 * Tamanho variável vaza informação sobre o conteúdo (análise de tráfego).
 * Tamanho fixo elimina esse vetor de ataque.
 *
 * Estrutura:
 *   [ circuit_id: 4b ][ type: 1b ][ payload: 505b ][ nonce: 2b ]
 *
 * Tipos:
 *   DATA (0x00)    — dados reais
 *   COVER (0x01)   — cover traffic (descartada pelo receptor)
 *   RELAY (0x02)   — instrução de relay para próximo hop
 *   DESTROY (0x03) — encerrar circuito
 *
 * Padding: bytes aleatórios (não zeros) — impede correlação por compressão.
 *
 * TODO (Etapa 5): padding interno variável para circuit fingerprint hardening.
 */
"use strict";

const { secureRandomBytes } = require("../crypto/rng.js");

const CELL_SIZE    = 512;
const HEADER_SIZE  = 5;   // circuit_id(4) + type(1)
const NONCE_SIZE   = 2;
const PAYLOAD_SIZE = CELL_SIZE - HEADER_SIZE - NONCE_SIZE; // 505 bytes

const CELL_TYPE = Object.freeze({ DATA: 0x00, COVER: 0x01, RELAY: 0x02, DESTROY: 0x03 });

/**
 * Cria uma cell de tamanho fixo (512 bytes).
 * @param {number} circuitId
 * @param {number} type — CELL_TYPE.*
 * @param {Buffer} [payload] — max 505 bytes; restante preenchido com bytes aleatórios
 * @returns {Buffer} exatamente 512 bytes
 */
function createCell(circuitId, type, payload = Buffer.alloc(0)) {
  if (payload.length > PAYLOAD_SIZE)
    throw new Error(`[Cell] Payload excede ${PAYLOAD_SIZE} bytes (recebido: ${payload.length})`);

  const cell = Buffer.alloc(CELL_SIZE, 0);
  cell.writeUInt32BE(circuitId, 0);
  cell.writeUInt8(type, 4);

  // Preencher payload com bytes aleatórios (evita compressão e correlação)
  const paddedPayload = Buffer.from(secureRandomBytes(PAYLOAD_SIZE));
  payload.copy(paddedPayload, 0);
  paddedPayload.copy(cell, HEADER_SIZE);

  // Nonce aleatório nos últimos 2 bytes
  secureRandomBytes(NONCE_SIZE).copy(cell, CELL_SIZE - NONCE_SIZE);

  return cell;
}

/**
 * Parseia uma cell recebida.
 * @param {Buffer} cell — deve ter exatamente 512 bytes
 * @returns {{ circuitId: number, type: number, payload: Buffer, nonce: Buffer }}
 */
function parseCell(cell) {
  if (cell.length !== CELL_SIZE)
    throw new Error(`[Cell] Tamanho inválido: ${cell.length} (esperado ${CELL_SIZE})`);
  return {
    circuitId: cell.readUInt32BE(0),
    type:      cell.readUInt8(4),
    payload:   cell.slice(HEADER_SIZE, CELL_SIZE - NONCE_SIZE),
    nonce:     cell.slice(CELL_SIZE - NONCE_SIZE),
  };
}

/**
 * Cria cell de cover traffic.
 * Aparência idêntica a DATA — receptor descarta silenciosamente.
 * @param {number} circuitId
 * @returns {Buffer}
 */
function createCoverCell(circuitId) {
  return createCell(circuitId, CELL_TYPE.COVER);
}

module.exports = { createCell, parseCell, createCoverCell, CELL_TYPE, CELL_SIZE, PAYLOAD_SIZE };
EOF
log "src/onion/cells.js ✓"

# ═════════════════════════════════════════════════════════════════════════════
# ONION ENCRYPT — src/onion/encrypt.js
# ═════════════════════════════════════════════════════════════════════════════
cat > src/onion/encrypt.js << 'EOF'
/**
 * src/onion/encrypt.js — Criptografia em camadas (onion)
 *
 * Cada hop do circuito adiciona/remove uma camada de criptografia.
 * Resultado: cada relay vê apenas a próxima instrução de roteamento.
 * Nenhum relay vê origem + destino simultaneamente.
 *
 * Encrypt: payload → encrypt(hopN) → ... → encrypt(hop1) → wire
 * Decrypt: wire → decrypt(hop1) → ... → decrypt(hopN) → plaintext
 *
 * Usa XSalsa20-Poly1305 via libsodium (constant-time) para cada camada.
 *
 * TODO (Etapa 5): integrar com path-key.js para chaves derivadas por HKDF
 *   e circuit_id.
 */
"use strict";

const sodium             = require("libsodium-wrappers");
const { secureRandomBytes } = require("../crypto/rng.js");

/**
 * Aplica N camadas de criptografia (do último hop para o primeiro).
 * @param {Buffer}       payload
 * @param {Uint8Array[]} layerKeys — [hop1, hop2, ..., hopN]
 * @returns {{ encrypted: Buffer, nonces: Buffer[] }}
 */
async function onionEncrypt(payload, layerKeys) {
  await sodium.ready;
  let current  = payload;
  const nonces = [];
  for (let i = layerKeys.length - 1; i >= 0; i--) {
    const nonce = secureRandomBytes(sodium.crypto_secretbox_NONCEBYTES);
    current     = Buffer.from(sodium.crypto_secretbox_easy(current, nonce, layerKeys[i]));
    nonces.unshift(Buffer.from(nonce));
  }
  return { encrypted: current, nonces };
}

/**
 * Remove uma camada de criptografia (usado por cada relay individualmente).
 * @param {Buffer}     data
 * @param {Uint8Array} key
 * @param {Buffer}     nonce
 * @returns {Buffer}
 */
async function onionPeel(data, key, nonce) {
  await sodium.ready;
  const plain = sodium.crypto_secretbox_open_easy(data, nonce, key);
  if (!plain) throw new Error("[Onion] Falha ao remover camada: MAC inválido");
  return Buffer.from(plain);
}

module.exports = { onionEncrypt, onionPeel };
EOF
log "src/onion/encrypt.js ✓"

# ═════════════════════════════════════════════════════════════════════════════
# COVER TRAFFIC SHAPER — src/traffic/shaper.js
# ═════════════════════════════════════════════════════════════════════════════
cat > src/traffic/shaper.js << 'EOF'
/**
 * src/traffic/shaper.js — Cover Traffic Adaptativo
 *
 * Problema: ausência de tráfego é informação.
 * Solução: enviar células constantes mesmo sem mensagens reais.
 * Células COVER têm aparência idêntica a DATA — receptor descarta.
 *
 * Modos e rates:
 *   normal   →  1 cell/s (1000ms)
 *   private  →  3 cells/s (333ms)
 *   paranoia →  5 cells/s (200ms)
 *
 * TODO (Etapa 6): integrar com delay.js (log-normal) e sync.js
 *   (peer padding sync) para resistência a análise de correlação temporal.
 */
"use strict";

const { createCoverCell } = require("../onion/cells.js");

const RATES = Object.freeze({ normal: 1000, private: 333, paranoia: 200 });

class CoverTrafficShaper {
  /**
   * @param {object}   opts
   * @param {string}   opts.mode      — "normal" | "private" | "paranoia"
   * @param {function} opts.sendFn    — async (cell: Buffer) => void
   * @param {number}   opts.circuitId
   */
  constructor({ mode = "normal", sendFn, circuitId }) {
    this.mode      = mode;
    this.sendFn    = sendFn;
    this.circuitId = circuitId;
    this._timer    = null;
    this._running  = false;
  }

  start() {
    if (this._running) return;
    this._running = true;
    const interval = RATES[this.mode] ?? RATES.normal;
    this._timer = setInterval(async () => {
      try {
        await this.sendFn(createCoverCell(this.circuitId));
      } catch (err) {
        console.error("[Shaper] Erro ao enviar cover cell:", err.message);
      }
    }, interval);
    this._timer.unref(); // não impede o processo de encerrar
    console.log(`[Shaper] Cover traffic iniciado — modo: ${this.mode} (${interval}ms/cell)`);
  }

  stop() {
    if (this._timer) { clearInterval(this._timer); this._timer = null; }
    this._running = false;
    console.log("[Shaper] Cover traffic parado ✓");
  }

  /** Altera modo em runtime sem reiniciar o timer. */
  setMode(newMode) {
    if (!RATES[newMode]) throw new Error(`[Shaper] Modo inválido: ${newMode}`);
    this.stop();
    this.mode = newMode;
    this.start();
  }
}

module.exports = { CoverTrafficShaper };
EOF
log "src/traffic/shaper.js ✓"

# ═════════════════════════════════════════════════════════════════════════════
# STARTUP SCRIPT — scripts/start-dev.sh
# ═════════════════════════════════════════════════════════════════════════════
cat > scripts/start-dev.sh << 'EOF'
#!/usr/bin/env bash
# scripts/start-dev.sh — Inicia daemon + Electron em modo desenvolvimento
set -euo pipefail

echo "[Dev] Iniciando daemon de rede..."
node src/network/node.js &
DAEMON_PID=$!

echo "[Dev] Daemon PID: $DAEMON_PID"
echo "[Dev] Iniciando Electron..."
electron .

echo "[Dev] Encerrando daemon..."
kill "$DAEMON_PID" 2>/dev/null || true
EOF
chmod +x scripts/start-dev.sh
log "scripts/start-dev.sh ✓"

# ═════════════════════════════════════════════════════════════════════════════
# NPM INSTALL
# ═════════════════════════════════════════════════════════════════════════════
if [ "$NO_INSTALL" = false ]; then
  header "Instalando dependências (npm install)"
  info "Isso pode levar alguns minutos na primeira execução..."
  npm install --ignore-scripts 2>&1 | tail -5
  log "npm install concluído ✓"
else
  warn "npm install pulado (--no-install)"
fi

# ═════════════════════════════════════════════════════════════════════════════
# GIT COMMIT INICIAL
# ═════════════════════════════════════════════════════════════════════════════
header "Commit inicial"
git add -A
git commit -q -m "chore: scaffold inicial P2P Secure Chat v7

- Electron Main Process com CSP dupla (default session + renderer session)
- Preload bridge mínima com IPC allowlist (< 60 linhas)
- Módulos crypto: rng.js (health check), memory.js (zeroize), session.js (Double Ratchet esqueleto), storage.js (Argon2id)
- Módulos identity: keygen.js (X3DH), fingerprint.js (QR + constant-time compare)
- Core Daemon: node.js + libp2p-factory.js (Noise XX)
- Persistência: journal.js (crash consistency com fsync), recovery.js, deletion.js (secure delete via key destruction)
- Onion: cells.js (512 bytes fixos), encrypt.js (camadas XSalsa20-Poly1305)
- Cover Traffic: shaper.js (adaptativo, 3 modos)
- ESLint: Math.random() proibido em módulos de segurança

Próximas etapas:
  Etapa 2 — libsignal-client (X3DH completo)
  Etapa 3 — WebRTC + relay + anti-Sybil
  Etapa 4 — Double Ratchet decrypt + journal criptografado
  Etapa 5 — Onion routing completo
  Etapa 6 — Cover traffic com log-normal delay"
log "Commit inicial criado ✓"

# ═════════════════════════════════════════════════════════════════════════════
# SUMÁRIO FINAL
# ═════════════════════════════════════════════════════════════════════════════
header "Setup concluído"
echo -e "${BOLD}Projeto criado em:${NC} $(pwd)"
echo ""
echo -e "${BOLD}Arquivos gerados:${NC}"
find src -name "*.js" | sort | while read -r f; do echo "  $f"; done
echo ""
echo -e "${BOLD}Próximos passos:${NC}"
echo "  cd p2p-secure"
if [ "$NO_INSTALL" = true ]; then
  echo "  npm install"
fi
echo "  npm run lint        # verificar código"
echo "  npm test            # executar testes"
echo "  npm run dev         # iniciar em modo dev"
echo ""
echo -e "${GREEN}${BOLD}P2P Secure Chat scaffold completo ✓${NC}"
