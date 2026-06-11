"use strict";

const { contextBridge, ipcRenderer } = require("electron");

const ALLOWED_SEND = ["chat:send", "call:start", "call:end", "identity:verify", "notify:message"];
const ALLOWED_RECEIVE = [
  "chat:receive",
  "chat:status",
  "call:incoming",
  "peer:status",
  "peer:focus",
  "security:alert",
  "peer:connected",
  "peer:disconnected",
  "connect:error",
  "session:ready",
  "contacts:updated",
];
const ALLOWED_INVOKE = [
  "daemon:status",
  "daemon:info",
  "identity:getFingerprint",
  "peers:list",
  "peer:connect",
  "chat:history",
  "contacts:list",
  "contacts:save",
  "contacts:remove",
];

contextBridge.exposeInMainWorld("secureAPI", {
  send(channel, payload) {
    if (!ALLOWED_SEND.includes(channel)) {
      console.error("[Preload] Canal nao permitido:", channel);
      return;
    }
    ipcRenderer.send(channel, JSON.parse(JSON.stringify(payload)));
  },

  on(channel, callback) {
    if (!ALLOWED_RECEIVE.includes(channel)) {
      console.error("[Preload] Canal de recebimento nao permitido:", channel);
      return;
    }
    const handler = (_event, data) => callback(data);
    ipcRenderer.on(channel, handler);
    return () => ipcRenderer.removeListener(channel, handler);
  },

  async invoke(channel, payload) {
    if (!ALLOWED_INVOKE.includes(channel)) {
      throw new Error(`[Preload] invoke nao permitido: ${channel}`);
    }
    return ipcRenderer.invoke(channel, payload);
  },
});
