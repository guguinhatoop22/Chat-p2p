/**
 * src/ui/main.js — Electron Main Process
 *
 * Segurança: contextIsolation + sandbox + CSP duplo (default session + renderer session).
 * IPC: relay bidirecional entre renderer ↔ daemon via processo filho (fork).
 */
"use strict";

const { app, BrowserWindow, ipcMain, session, Notification } = require("electron");
const path    = require("node:path");
const os      = require("node:os");
const { randomUUID } = require("node:crypto");
const { Worker } = require("node:worker_threads");
const QRCode   = require("qrcode");

// ── Suporte a múltiplas instâncias (teste local) ──────────────────────────
// Se outro processo Electron já está rodando com o mesmo userData,
// usa um diretório temporário único para esta instância secundária.
{
  const lockFile = require("node:path").join(os.homedir(), ".p2p-secure", "electron.lock");
  const fs = require("node:fs");
  let isSecondary = false;
  if (fs.existsSync(lockFile)) {
    try {
      const pid = parseInt(fs.readFileSync(lockFile, "utf8").trim(), 10);
      if (pid && pid !== process.pid) {
        try { process.kill(pid, 0); isSecondary = true; } catch (e) { if (e.code === "EPERM") isSecondary = true; }
      }
    } catch { /* lock corrompido */ }
  }
  if (isSecondary) {
    // Instância secundária: userData e cache em pasta temporária única
    const tmpDir = require("node:path").join(os.tmpdir(), "p2p-secure-" + process.pid);
    app.setPath("userData", tmpDir);
    app.setPath("temp", tmpDir);
    // Evita conflito de GPU shader cache entre instâncias
    app.commandLine.appendSwitch("disable-gpu-shader-disk-cache");
    console.log("[Main] Instância secundária — userData temporário:", tmpDir);
  } else {
    fs.mkdirSync(require("node:path").join(os.homedir(), ".p2p-secure"), { recursive: true, mode: 0o700 });
    fs.writeFileSync(lockFile, String(process.pid), { mode: 0o600 });
    process.on("exit", () => { try { fs.unlinkSync(lockFile); } catch {} });
  }
}

let mainWindow    = null;
let daemonProcess = null;
let daemonInfo    = null; // { peerId, addrs } — preenchido quando daemon envia 'daemon:ready'

function isDaemonRunning() {
  return daemonProcess !== null;
}

function resolveAssetPath(...segments) {
  return app.isPackaged
    ? path.join(process.resourcesPath, "app.asar", "assets", ...segments)
    : path.join(__dirname, "..", "..", "assets", ...segments);
}

function sendToDaemon(message) {
  if (!daemonProcess) return;
  daemonProcess.postMessage(message);
}

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
// Relay de mensagem do daemon para o renderer
function relayToRenderer(channel, data) {
  if (mainWindow && !mainWindow.isDestroyed()) {
    mainWindow.webContents.send(channel, data);
  }
}

function startDaemon() {
  const daemonPath = path.join(__dirname, "..", "network", "node.js");
  daemonProcess = new Worker(`require(${JSON.stringify(daemonPath)});`, { eval: true });
  daemonProcess.pid = daemonProcess.threadId;

  // Mensagens recebidas do processo daemon
  daemonProcess.on("message", (msg) => {
    if (!msg || typeof msg.type !== "string") return;
    switch (msg.type) {
      case "daemon:ready":
        daemonInfo = msg.data;
        console.log("[Main] Daemon pronto. PeerID:", daemonInfo?.peerId);
        break;
      case "chat:receive":
      case "chat:status":
      case "peer:connected":
      case "peer:disconnected":
      case "peer:status":
      case "security:alert":
      case "connect:error":
      case "session:ready":
      case "contacts:updated":
        relayToRenderer(msg.type, msg.data);
        break;
      // peer:connect:response e peers:list:response são tratados
      // pelos listeners one-time nos handlers ipcMain.handle abaixo
    }
  });

  daemonProcess.on("error", (err) => console.error("[Main] Daemon error:", err));
  daemonProcess.on("exit", (code) => {
    console.warn("[Main] Daemon worker saiu com codigo:", code);
    daemonProcess = null;
    daemonInfo = null;
  });
  daemonProcess.on("exit",  (code) => console.warn("[Main] Daemon saiu com código:", code));
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

// ── IPC Handlers ──────────────────────────────────────────────────────────

// daemon:status — processo daemon está vivo?
ipcMain.handle("daemon:status", async () => ({
  running: isDaemonRunning(),
}));

// daemon:info — PeerID e multiaddrs (aguarda até 5s o daemon ficar pronto)
ipcMain.handle("daemon:info", () => {
  if (daemonInfo) return daemonInfo;
  return new Promise((resolve) => {
    const timeout = setTimeout(() => resolve(null), 5000);
    const interval = setInterval(() => {
      if (daemonInfo) { clearInterval(interval); clearTimeout(timeout); resolve(daemonInfo); }
    }, 100);
  });
});

// peer:connect — dial por multiaddr; aguarda sucesso ou erro com reqId
ipcMain.handle("peer:connect", (_, addr) => {
  if (!isDaemonRunning())
    return { ok: false, error: "Daemon não está rodando" };
  return new Promise((resolve) => {
    const reqId = randomUUID();
    const timeout = setTimeout(() => {
      daemonProcess.removeListener("message", handler);
      resolve({ ok: false, error: "Timeout ao conectar (10s)" });
    }, 10000);
    function handler(msg) {
      if (msg?.type === "peer:connect:response" && msg.reqId === reqId) {
        clearTimeout(timeout);
        daemonProcess.removeListener("message", handler);
        resolve(msg.data);
      }
    }
    daemonProcess.on("message", handler);
    sendToDaemon({ type: "peer:connect", reqId, data: { addr } });
  });
});

// peers:list — lista peers conectados no daemon
ipcMain.handle("peers:list", () => {
  if (!isDaemonRunning()) return [];
  return new Promise((resolve) => {
    const reqId = randomUUID();
    const timeout = setTimeout(() => {
      daemonProcess.removeListener("message", handler);
      resolve([]);
    }, 3000);
    function handler(msg) {
      if (msg?.type === "peers:list:response" && msg.reqId === reqId) {
        clearTimeout(timeout);
        daemonProcess.removeListener("message", handler);
        resolve(msg.data ?? []);
      }
    }
    daemonProcess.on("message", handler);
    sendToDaemon({ type: "peers:get", reqId });
  });
});

// chat:send — fire-and-forget via ipcMain.on (não precisa de resposta)
ipcMain.on("chat:send", (_, payload) => {
  if (isDaemonRunning()) {
    sendToDaemon({ type: "chat:send", data: payload });
  }
});

ipcMain.on("notify:message", (_, payload) => {
  if (!mainWindow || mainWindow.isDestroyed()) return;
  if (mainWindow.isFocused()) return;
  if (!Notification.isSupported()) return;

  const title = typeof payload?.title === "string" && payload.title.trim()
    ? payload.title.trim()
    : "Nova mensagem";
  const body = typeof payload?.body === "string" ? payload.body : "";
  const peerId = typeof payload?.peerId === "string" ? payload.peerId : "";

  const notification = new Notification({ title, body });
  notification.on("click", () => {
    if (!mainWindow || mainWindow.isDestroyed()) return;
    if (mainWindow.isMinimized()) mainWindow.restore();
    mainWindow.show();
    mainWindow.focus();
    if (peerId) mainWindow.webContents.send("peer:focus", peerId);
  });
  notification.show();
});

// identity:getFingerprint — gera fingerprint de segurança para um peer
ipcMain.handle("identity:getFingerprint", async (_, payload) => {
  if (!isDaemonRunning()) return null;
  const { peerId } = payload ?? {};
  if (!peerId) return null;

  // 1. Pedir ao daemon que gere o fingerprint (tem acesso às chaves de identidade)
  const fingerprint = await new Promise((resolve) => {
    const reqId = randomUUID();
    const timeout = setTimeout(() => {
      daemonProcess.removeListener("message", handler);
      resolve(null);
    }, 8000);
    function handler(msg) {
      if (msg?.type === "identity:fingerprint:response" && msg.reqId === reqId) {
        clearTimeout(timeout);
        daemonProcess.removeListener("message", handler);
        resolve(msg.data?.fingerprint ?? null);
      }
    }
    daemonProcess.on("message", handler);
    sendToDaemon({ type: "identity:fingerprint", reqId, data: { peerId } });
  });

  if (!fingerprint) return { error: "Falha ao gerar fingerprint" };

  // 2. Gerar o QR code aqui no main process (evita problema de IPC com data URLs)
  try {
    const qr = await QRCode.toDataURL(fingerprint, {
      errorCorrectionLevel: "H",
      width: 256,
      margin: 2,
      color: { dark: "#000000", light: "#ffffff" },
    });
    return { fingerprint, qr };
  } catch (err) {
    console.error("[Main] Falha ao gerar QR:", err.message);
    return { fingerprint, qr: null };
  }
});

// chat:history — carrega histórico de mensagens de um peer do disco
ipcMain.handle("chat:history", (_, payload) => {
  if (!isDaemonRunning()) return [];
  const { peerId } = payload ?? {};
  if (!peerId) return [];
  return new Promise((resolve) => {
    const reqId = randomUUID();
    const timeout = setTimeout(() => {
      daemonProcess.removeListener("message", handler);
      resolve([]);
    }, 5000);
    function handler(msg) {
      if (msg?.type === "chat:history:response" && msg.reqId === reqId) {
        clearTimeout(timeout);
        daemonProcess.removeListener("message", handler);
        resolve(msg.data ?? []);
      }
    }
    daemonProcess.on("message", handler);
    sendToDaemon({ type: "chat:history", reqId, data: { peerId } });
  });
});

ipcMain.handle("contacts:list", () => {
  if (!isDaemonRunning()) return [];
  return new Promise((resolve) => {
    const reqId = randomUUID();
    const timeout = setTimeout(() => {
      daemonProcess.removeListener("message", handler);
      resolve([]);
    }, 5000);
    function handler(msg) {
      if (msg?.type === "contacts:list:response" && msg.reqId === reqId) {
        clearTimeout(timeout);
        daemonProcess.removeListener("message", handler);
        resolve(msg.data ?? []);
      }
    }
    daemonProcess.on("message", handler);
    sendToDaemon({ type: "contacts:list", reqId });
  });
});

ipcMain.handle("contacts:save", (_, payload) => {
  if (!isDaemonRunning()) {
    return { ok: false, error: "Daemon nao esta rodando" };
  }
  const { peerId, nick } = payload ?? {};
  return new Promise((resolve) => {
    const reqId = randomUUID();
    const timeout = setTimeout(() => {
      daemonProcess.removeListener("message", handler);
      resolve({ ok: false, error: "Timeout ao salvar contato" });
    }, 5000);
    function handler(msg) {
      if (msg?.type === "contacts:save:response" && msg.reqId === reqId) {
        clearTimeout(timeout);
        daemonProcess.removeListener("message", handler);
        resolve(msg.data ?? { ok: false, error: "Falha ao salvar contato" });
      }
    }
    daemonProcess.on("message", handler);
    sendToDaemon({ type: "contacts:save", reqId, data: { peerId, nick } });
  });
});

ipcMain.handle("contacts:remove", (_, peerId) => {
  if (!isDaemonRunning()) {
    return { ok: false, error: "Daemon nao esta rodando" };
  }
  return new Promise((resolve) => {
    const reqId = randomUUID();
    const timeout = setTimeout(() => {
      daemonProcess.removeListener("message", handler);
      resolve({ ok: false, error: "Timeout ao remover contato" });
    }, 5000);
    function handler(msg) {
      if (msg?.type === "contacts:remove:response" && msg.reqId === reqId) {
        clearTimeout(timeout);
        daemonProcess.removeListener("message", handler);
        resolve(msg.data ?? { ok: false, error: "Falha ao remover contato" });
      }
    }
    daemonProcess.on("message", handler);
    sendToDaemon({ type: "contacts:remove", reqId, data: { peerId } });
  });
});

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
  if (daemonProcess) daemonProcess.terminate();
  app.quit();
}

app.on("window-all-closed", () => { if (process.platform !== "darwin") shutdown(); });
app.on("before-quit",       () => { if (daemonProcess) daemonProcess.terminate(); });
