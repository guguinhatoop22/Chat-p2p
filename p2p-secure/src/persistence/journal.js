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
