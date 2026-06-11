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
