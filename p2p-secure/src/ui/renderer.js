"use strict";

const state = {
  myPeerId: null,
  activePeer: null,
  peers: new Map(),
  contacts: new Map(),
  peerStatus: new Map(),
  e2eSessions: new Set(),
  chatHistory: new Map(),
  historyLoaded: new Set(),
  editingNick: false,
};

let elPeerIdDisplay;
let elMyAddrs;
let elPeerAddr;
let elBtnConnect;
let elPeersList;
let elMessages;
let elMessageInput;
let elBtnSend;
let elStatusText;
let elPeerCount;
let elChatHeaderLabel;
let elActivePeerDisplay;
let elActivePeerId;
let elPeerNickEdit;
let elBtnEditNick;
let elBtnNickSave;
let elBtnNickCancel;
let elBtnVerify;
let elToast;
let elFpModal;
let elFpModalPeer;
let elFpQr;
let elFpText;
let elFpClose;

let toastTimer = null;

function showToast(msg, ms = 3500) {
  elToast.textContent = msg;
  elToast.classList.remove("hidden");
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => {
    elToast.classList.add("hidden");
  }, ms);
}

function fallbackPeerName(peerId) {
  return peerId ? peerId.slice(-8) : "?";
}

function displayName(peerId) {
  if (!peerId) return "";
  return state.contacts.get(peerId)?.nick ?? fallbackPeerName(peerId);
}

function peerPresence(peerId) {
  return state.peerStatus.get(peerId) ?? "offline";
}

function fmt(ts) {
  return new Date(ts).toLocaleTimeString("pt-BR", {
    hour: "2-digit",
    minute: "2-digit",
  });
}

function addToHistory(peerId, msg) {
  if (!state.chatHistory.has(peerId)) state.chatHistory.set(peerId, []);
  state.chatHistory.get(peerId).push(msg);
}

function scrollToBottom() {
  elMessages.scrollTop = elMessages.scrollHeight;
}

function statusIcon(status) {
  switch (status) {
    case "sending": return "\u23F3";
    case "sent": return "\u2713";
    case "delivered": return "\u2713\u2713";
    case "failed": return "\u2717";
    default: return "\u23F3";
  }
}

function applyStatusToElement(elStatus, status) {
  if (!elStatus) return;
  elStatus.className = "msg-status " + status;
  elStatus.textContent = statusIcon(status);
  elStatus.title = status;
}

function updateMsgStatus(id, status) {
  if (typeof id !== "string" || !id) return;

  for (const history of state.chatHistory.values()) {
    const msg = history.find((item) => item?.id === id);
    if (msg) msg.status = status;
  }

  const elMsg = elMessages?.querySelector(`[data-msg-id="${id}"]`);
  if (!elMsg) return;
  applyStatusToElement(elMsg.querySelector(".msg-status"), status);
}

async function loadContacts() {
  try {
    const list = await window.secureAPI.invoke("contacts:list");
    const contacts = new Map();

    for (const item of Array.isArray(list) ? list : []) {
      const peerId = typeof item?.peerId === "string" ? item.peerId : "";
      const nick = typeof item?.nick === "string" ? item.nick.trim() : "";
      if (peerId && nick) contacts.set(peerId, { nick });
    }

    state.contacts = contacts;
  } catch (err) {
    console.error("[Renderer] Falha ao carregar contatos:", err.message);
    state.contacts = new Map();
  }
}

async function loadConnectedPeers() {
  try {
    const peers = await window.secureAPI.invoke("peers:list");
    state.peers = new Map();
    state.peerStatus = new Map();

    for (const peer of Array.isArray(peers) ? peers : []) {
      if (typeof peer?.peerId !== "string") continue;
      state.peers.set(peer.peerId, { peerId: peer.peerId, connectedAt: peer.connectedAt ?? Date.now() });
      state.peerStatus.set(peer.peerId, "online");
    }
  } catch (err) {
    console.error("[Renderer] Falha ao carregar peers:", err.message);
    state.peers = new Map();
    state.peerStatus = new Map();
  }
}

function ensurePeer(peerId, connectedAt = Date.now()) {
  if (!peerId) return;
  if (!state.peers.has(peerId)) {
    state.peers.set(peerId, { peerId, connectedAt });
  }
}

function setPeerPresence(peerId, status, connectedAt = Date.now()) {
  if (!peerId) return;
  ensurePeer(peerId, connectedAt);
  state.peerStatus.set(peerId, status === "online" ? "online" : "offline");
}

function renderPeersList() {
  elPeersList.innerHTML = "";

  if (state.peers.size === 0) {
    const empty = document.createElement("div");
    empty.className = "empty-peers";
    empty.textContent = "Nenhum peer conectado";
    elPeersList.appendChild(empty);
    elPeerCount.textContent = "0 peers";
    return;
  }

  elPeerCount.textContent = state.peers.size + " peer(s)";

  for (const [peerId] of state.peers) {
    const item = document.createElement("div");
    item.className = "peer-item" + (peerId === state.activePeer ? " active" : "");
    item.dataset.peerId = peerId;

    const titleRow = document.createElement("div");
    titleRow.className = "peer-title-row";

    const dot = document.createElement("span");
    dot.className = "presence-dot " + peerPresence(peerId);
    dot.title = peerPresence(peerId) === "online" ? "Online" : "Offline";

    const idLine = document.createElement("div");
    idLine.className = "peer-id";
    idLine.textContent = displayName(peerId);
    idLine.title = peerId;

    titleRow.appendChild(dot);
    titleRow.appendChild(idLine);

    const statusLine = document.createElement("div");
    statusLine.className = "peer-status";
    const isE2E = state.e2eSessions.has(peerId);
    const online = peerPresence(peerId) === "online";
    statusLine.textContent = (online ? "online" : "offline") + (isE2E ? " | E2E ativa" : "");

    const history = state.chatHistory.get(peerId);
    if (history && history.length > 0 && peerId !== state.activePeer) {
      statusLine.textContent += " | mensagem";
    }

    item.appendChild(titleRow);
    item.appendChild(statusLine);
    item.addEventListener("click", () => { selectPeer(peerId); });
    elPeersList.appendChild(item);
  }
}

function renderActivePeerHeader() {
  const peerId = state.activePeer;
  const hasActivePeer = Boolean(peerId);

  elBtnVerify.classList.toggle("hidden", !hasActivePeer || !state.e2eSessions.has(peerId));
  elBtnEditNick.classList.toggle("hidden", !hasActivePeer || state.editingNick);
  elBtnNickSave.classList.toggle("hidden", !hasActivePeer || !state.editingNick);
  elBtnNickCancel.classList.toggle("hidden", !hasActivePeer || !state.editingNick);
  elPeerNickEdit.classList.toggle("hidden", !hasActivePeer || !state.editingNick);
  elActivePeerDisplay.classList.toggle("hidden", !hasActivePeer || state.editingNick);
  elActivePeerId.classList.toggle("hidden", !hasActivePeer);

  if (!hasActivePeer) {
    elChatHeaderLabel.textContent = "Selecione um peer para conversar";
    elActivePeerDisplay.textContent = "";
    elActivePeerDisplay.title = "";
    elActivePeerId.textContent = "";
    elPeerNickEdit.value = "";
    return;
  }

  elChatHeaderLabel.textContent = "Conversa com:";
  elActivePeerDisplay.textContent = displayName(peerId);
  elActivePeerDisplay.title = peerId;
  elActivePeerId.textContent = peerId;

  if (state.editingNick) {
    elPeerNickEdit.value = state.contacts.get(peerId)?.nick ?? "";
    elPeerNickEdit.placeholder = "Apelido para " + fallbackPeerName(peerId);
  }
}

async function refreshContacts() {
  await loadContacts();
  renderPeersList();
  renderActivePeerHeader();
  if (state.activePeer) renderMessages();

  if (!elFpModal.classList.contains("hidden") && state.activePeer) {
    elFpModalPeer.textContent = "Peer: " + displayName(state.activePeer) + " (" + state.activePeer + ")";
  }
}

function setNickEditing(enabled) {
  if (!state.activePeer) return;
  state.editingNick = enabled;
  renderActivePeerHeader();

  if (enabled) {
    queueMicrotask(() => {
      elPeerNickEdit.focus();
      elPeerNickEdit.select();
    });
  }
}

async function selectPeer(peerId) {
  ensurePeer(peerId);
  state.activePeer = peerId;
  state.editingNick = false;
  elMessageInput.disabled = false;
  elBtnSend.disabled = false;
  renderActivePeerHeader();

  if (!state.historyLoaded.has(peerId)) {
    state.historyLoaded.add(peerId);
    try {
      const disk = await window.secureAPI.invoke("chat:history", { peerId });
      if (Array.isArray(disk) && disk.length > 0) {
        const existing = state.chatHistory.get(peerId) ?? [];
        const merged = [...disk];
        const seen = new Set(disk.map((msg) => (msg.id ? "id:" + msg.id : "ts:" + msg.ts + "|" + msg.from)));

        for (const msg of existing) {
          const key = msg.id ? "id:" + msg.id : "ts:" + msg.ts + "|" + msg.from;
          if (!seen.has(key)) merged.push(msg);
        }

        merged.sort((a, b) => a.ts - b.ts);
        state.chatHistory.set(peerId, merged);
      }
    } catch {
      // Best effort only.
    }
  }

  renderMessages();
  renderPeersList();
  elMessageInput.focus();
}

function renderMessages() {
  elMessages.innerHTML = "";

  if (!state.activePeer) {
    const empty = document.createElement("div");
    empty.id = "empty-state";
    const p = document.createElement("p");
    p.textContent = "Nenhuma conversa selecionada";
    const s = document.createElement("small");
    s.textContent = "Conecte a um peer usando o painel esquerdo";
    empty.appendChild(p);
    empty.appendChild(s);
    elMessages.appendChild(empty);
    return;
  }

  const history = state.chatHistory.get(state.activePeer) ?? [];
  if (history.length === 0) {
    const empty = document.createElement("div");
    empty.id = "empty-state";
    const p = document.createElement("p");
    p.textContent = "Nenhuma mensagem ainda";
    const s = document.createElement("small");
    s.textContent = "Diga ola!";
    empty.appendChild(p);
    empty.appendChild(s);
    elMessages.appendChild(empty);
    return;
  }

  for (const msg of history) appendMsg(msg);
  scrollToBottom();
}

function appendMsg(msg) {
  if (!msg || (msg.from !== "me" && msg.peerId !== state.activePeer)) return;

  const wrap = document.createElement("div");
  wrap.className = "message " + (msg.from === "me" ? "outgoing" : "incoming");
  if (typeof msg.id === "string" && msg.id) wrap.dataset.msgId = msg.id;

  const text = document.createElement("div");
  text.className = "msg-text";
  text.textContent = msg.text;
  wrap.appendChild(text);

  const meta = document.createElement("div");
  meta.className = "meta";

  const metaText = document.createElement("span");
  metaText.className = "msg-meta-text";
  const peerLabel = msg.from === "me" ? "Eu" : displayName(msg.from);
  const e2eTag = msg.encrypted ? " [E2E]" : " [PLAIN]";
  metaText.textContent = fmt(msg.ts) + " \u00B7 " + peerLabel + e2eTag;
  meta.appendChild(metaText);

  if (msg.from === "me") {
    const elStatus = document.createElement("span");
    applyStatusToElement(elStatus, msg.status ?? "sending");
    meta.appendChild(elStatus);
  }

  wrap.appendChild(meta);
  elMessages.appendChild(wrap);
}

function appendSystemMsg(text) {
  const line = document.createElement("div");
  line.className = "system-msg";
  line.textContent = text;
  elMessages.appendChild(line);
  scrollToBottom();
}

async function handleVerify() {
  const peerId = state.activePeer;
  if (!peerId) return;

  elBtnVerify.disabled = true;
  elBtnVerify.textContent = "Gerando...";

  try {
    const result = await window.secureAPI.invoke("identity:getFingerprint", { peerId });
    if (!result || result.error) {
      showToast("Erro ao gerar fingerprint: " + (result?.error ?? "sessao nao iniciada"));
      return;
    }

    elFpModalPeer.textContent = "Peer: " + displayName(peerId) + " (" + peerId + ")";
    elFpText.textContent = result.fingerprint;
    if (result.qr) {
      elFpQr.src = result.qr;
      elFpQr.classList.remove("hidden");
    } else {
      elFpQr.classList.add("hidden");
    }

    elFpModal.classList.remove("hidden");
    elFpClose.focus();
  } catch (err) {
    showToast("Erro: " + err.message);
  } finally {
    elBtnVerify.disabled = false;
    elBtnVerify.textContent = "Verificar";
  }
}

async function handleConnect() {
  const addr = elPeerAddr.value
    .split(/[\s\n]+/)
    .map((line) => line.trim())
    .find((line) => line.startsWith("/")) ?? "";

  if (!addr) {
    showToast("Cole o multiaddr do peer (deve comecar com /)");
    return;
  }

  elBtnConnect.disabled = true;
  elBtnConnect.textContent = "Conectando...";
  try {
    const result = await window.secureAPI.invoke("peer:connect", addr);
    if (result && result.ok) {
      elPeerAddr.value = "";
      showToast("Conexao iniciada!", 2000);
    } else {
      showToast("Erro: " + (result?.error ?? "falha desconhecida"));
    }
  } catch (err) {
    showToast("Erro: " + (err.message ?? "falha"));
  } finally {
    elBtnConnect.disabled = false;
    elBtnConnect.textContent = "Conectar";
  }
}

function handleSend() {
  const text = elMessageInput.value.trim();
  if (!text || !state.activePeer) return;

  const id = globalThis.crypto?.randomUUID?.() ?? ("msg-" + Date.now() + "-" + Math.random().toString(16).slice(2));
  const msg = {
    id,
    peerId: state.activePeer,
    from: "me",
    text,
    ts: Date.now(),
    encrypted: state.e2eSessions.has(state.activePeer),
    status: "sending",
  };

  addToHistory(state.activePeer, msg);

  const empty = document.getElementById("empty-state");
  if (empty) empty.remove();

  appendMsg(msg);
  scrollToBottom();

  window.secureAPI.send("chat:send", { to: state.activePeer, text, id });
  elMessageInput.value = "";
}

async function handleSaveNick() {
  const peerId = state.activePeer;
  if (!peerId) return;

  const nick = elPeerNickEdit.value.replace(/\s+/g, " ").trim();
  elBtnNickSave.disabled = true;

  try {
    const result = nick
      ? await window.secureAPI.invoke("contacts:save", { peerId, nick })
      : await window.secureAPI.invoke("contacts:remove", peerId);

    if (!result?.ok) {
      showToast("Erro ao salvar contato: " + (result?.error ?? "falha"));
      return;
    }

    state.editingNick = false;
    await refreshContacts();
    showToast(nick ? "Apelido salvo para " + displayName(peerId) : "Apelido removido");
  } catch (err) {
    showToast("Erro ao salvar contato: " + err.message);
  } finally {
    elBtnNickSave.disabled = false;
    renderActivePeerHeader();
  }
}

function handleCancelNickEdit() {
  state.editingNick = false;
  renderActivePeerHeader();
}

async function init() {
  elPeerIdDisplay = document.getElementById("peer-id-display");
  elMyAddrs = document.getElementById("my-addrs");
  elPeerAddr = document.getElementById("peer-addr");
  elBtnConnect = document.getElementById("btn-connect");
  elPeersList = document.getElementById("peers-list");
  elMessages = document.getElementById("messages");
  elMessageInput = document.getElementById("message-input");
  elBtnSend = document.getElementById("btn-send");
  elStatusText = document.getElementById("status-text");
  elPeerCount = document.getElementById("peer-count");
  elChatHeaderLabel = document.getElementById("chat-header-label");
  elActivePeerDisplay = document.getElementById("active-peer-display");
  elActivePeerId = document.getElementById("active-peer-id");
  elPeerNickEdit = document.getElementById("peer-nick-edit");
  elBtnEditNick = document.getElementById("btn-edit-nick");
  elBtnNickSave = document.getElementById("btn-save-nick");
  elBtnNickCancel = document.getElementById("btn-cancel-nick");
  elBtnVerify = document.getElementById("btn-verify");
  elToast = document.getElementById("toast");
  elFpModal = document.getElementById("fp-modal");
  elFpModalPeer = document.getElementById("fp-modal-peer");
  elFpQr = document.getElementById("fp-qr");
  elFpText = document.getElementById("fp-text");
  elFpClose = document.getElementById("fp-close");

  elBtnConnect.addEventListener("click", handleConnect);
  elBtnSend.addEventListener("click", handleSend);
  elBtnVerify.addEventListener("click", handleVerify);
  elBtnEditNick.addEventListener("click", () => { setNickEditing(true); });
  elBtnNickSave.addEventListener("click", handleSaveNick);
  elBtnNickCancel.addEventListener("click", handleCancelNickEdit);
  elActivePeerDisplay.addEventListener("dblclick", () => {
    if (state.activePeer) setNickEditing(true);
  });
  elFpClose.addEventListener("click", () => { elFpModal.classList.add("hidden"); });
  elFpModal.addEventListener("click", (event) => {
    if (event.target === elFpModal) elFpModal.classList.add("hidden");
  });

  document.addEventListener("keydown", (event) => {
    if (event.key === "Escape" && !elFpModal.classList.contains("hidden")) {
      elFpModal.classList.add("hidden");
      return;
    }
    if (event.key === "Escape" && state.editingNick) handleCancelNickEdit();
  });

  elMessageInput.addEventListener("keydown", (event) => {
    if (event.key === "Enter" && !event.shiftKey) {
      event.preventDefault();
      handleSend();
    }
  });

  elPeerAddr.addEventListener("keydown", (event) => {
    if (event.key === "Enter" && (event.ctrlKey || event.metaKey)) {
      event.preventDefault();
      handleConnect();
    }
  });

  elPeerNickEdit.addEventListener("keydown", (event) => {
    if (event.key === "Enter") {
      event.preventDefault();
      handleSaveNick();
    }
  });

  const status = await window.secureAPI.invoke("daemon:status");
  if (!status?.running) {
    elStatusText.textContent = "Daemon nao iniciou";
    elStatusText.className = "status-err";
    return;
  }

  const info = await window.secureAPI.invoke("daemon:info");
  if (info?.peerId) {
    state.myPeerId = info.peerId;
    elPeerIdDisplay.textContent = info.peerId;
    elPeerIdDisplay.title = info.peerId;
    if (info.addrs?.length) {
      elMyAddrs.textContent = info.addrs
        .filter((addr) => !addr.includes("127.0.0.1"))
        .slice(0, 2)
        .join("\n") || info.addrs[0];
    }
  } else {
    elPeerIdDisplay.textContent = "N/D";
  }

  await loadContacts();
  await loadConnectedPeers();

  elStatusText.textContent = "Daemon ativo";
  elStatusText.className = "status-ok";
  renderActivePeerHeader();
  renderPeersList();
  renderMessages();

  window.secureAPI.on("session:ready", ({ peerId }) => {
    state.e2eSessions.add(peerId);
    renderPeersList();
    renderActivePeerHeader();
    showToast("Canal E2E estabelecido com " + displayName(peerId), 3000);
    if (state.activePeer === peerId) appendSystemMsg("Criptografia E2E ativa");
  });

  window.secureAPI.on("peer:connected", ({ peerId }) => {
    setPeerPresence(peerId, "online");
    renderPeersList();
    if (state.activePeer && state.activePeer !== peerId) {
      appendSystemMsg("Peer conectado: " + displayName(peerId));
    }
    showToast("Peer conectado: " + displayName(peerId), 2500);
  });

  window.secureAPI.on("peer:disconnected", ({ peerId }) => {
    setPeerPresence(peerId, "offline");
    state.e2eSessions.delete(peerId);
    if (state.activePeer === peerId) {
      appendSystemMsg("Peer ficou offline");
    }
    renderPeersList();
    showToast("Peer desconectado: " + displayName(peerId), 2500);
  });

  window.secureAPI.on("peer:status", ({ peerId, status }) => {
    setPeerPresence(peerId, status);
    renderPeersList();
  });

  window.secureAPI.on("chat:receive", ({ from, text, ts, encrypted, id }) => {
    setPeerPresence(from, "online", ts);
    renderPeersList();

    const msg = { id, peerId: from, from, text, ts, encrypted: !!encrypted };
    addToHistory(from, msg);
    window.secureAPI.send("notify:message", {
      title: displayName(from),
      body: encrypted ? "Nova mensagem encriptada" : String(text ?? "").slice(0, 80),
      peerId: from,
    });

    if (state.activePeer === from) {
      const empty = document.getElementById("empty-state");
      if (empty) empty.remove();
      appendMsg(msg);
      scrollToBottom();
    } else {
      renderPeersList();
      showToast("Nova mensagem de " + displayName(from));
    }
  });

  window.secureAPI.on("chat:status", ({ id, status }) => {
    updateMsgStatus(id, status);
  });

  window.secureAPI.on("peer:focus", (peerId) => {
    if (!peerId) return;
    ensurePeer(peerId);
    void selectPeer(peerId);
  });

  window.secureAPI.on("contacts:updated", async () => {
    await refreshContacts();
  });

  window.secureAPI.on("connect:error", ({ error }) => {
    showToast("Erro de conexao: " + error, 5000);
  });

  window.secureAPI.on("security:alert", (data) => {
    console.warn("[Security Alert]", data);
    showToast("Alerta de seguranca!", 6000);
  });
}

document.addEventListener("DOMContentLoaded", init);
