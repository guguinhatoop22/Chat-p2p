"use strict";

const fs = require("node:fs");
const path = require("node:path");
const os = require("node:os");

const DATA_DIR = path.join(os.homedir(), ".p2p-secure");
const CONTACTS_FILE = path.join(DATA_DIR, "contacts.json");
const MAX_NICK_LENGTH = 40;

let cache = null;

function ensureDataDir() {
  if (!fs.existsSync(DATA_DIR)) {
    fs.mkdirSync(DATA_DIR, { recursive: true, mode: 0o700 });
  }
}

function cloneContactsMap(source) {
  return new Map(Array.from(source.entries(), ([peerId, value]) => [
    peerId,
    { nick: value.nick },
  ]));
}

function normalizePeerId(peerId) {
  return typeof peerId === "string" ? peerId.trim() : "";
}

function normalizeNick(nick) {
  if (typeof nick !== "string") return "";
  return nick.replace(/\s+/g, " ").trim().slice(0, MAX_NICK_LENGTH);
}

function persistContacts(contacts) {
  ensureDataDir();
  const data = {};
  for (const [peerId, value] of Array.from(contacts.entries()).sort(([a], [b]) => a.localeCompare(b))) {
    data[peerId] = { nick: value.nick };
  }
  fs.writeFileSync(CONTACTS_FILE, JSON.stringify(data, null, 2), { mode: 0o600 });
  cache = cloneContactsMap(contacts);
}

function loadContacts() {
  ensureDataDir();

  if (cache) return cloneContactsMap(cache);
  if (!fs.existsSync(CONTACTS_FILE)) {
    cache = new Map();
    return new Map();
  }

  try {
    const parsed = JSON.parse(fs.readFileSync(CONTACTS_FILE, "utf8"));
    const contacts = new Map();

    if (parsed && typeof parsed === "object" && !Array.isArray(parsed)) {
      for (const [peerId, value] of Object.entries(parsed)) {
        const safePeerId = normalizePeerId(peerId);
        const safeNick = normalizeNick(value?.nick);
        if (safePeerId && safeNick) contacts.set(safePeerId, { nick: safeNick });
      }
    }

    cache = contacts;
    return cloneContactsMap(cache);
  } catch (err) {
    console.error("[ContactStore] Falha ao carregar contatos:", err.message);
    cache = new Map();
    return new Map();
  }
}

function saveContact(peerId, nick) {
  const safePeerId = normalizePeerId(peerId);
  const safeNick = normalizeNick(nick);
  if (!safePeerId) throw new Error("peerId invalido");
  if (!safeNick) {
    removeContact(safePeerId);
    return;
  }

  const contacts = loadContacts();
  contacts.set(safePeerId, { nick: safeNick });
  persistContacts(contacts);
}

function removeContact(peerId) {
  const safePeerId = normalizePeerId(peerId);
  if (!safePeerId) throw new Error("peerId invalido");

  const contacts = loadContacts();
  if (!contacts.delete(safePeerId)) return;
  persistContacts(contacts);
}

module.exports = { loadContacts, saveContact, removeContact };
