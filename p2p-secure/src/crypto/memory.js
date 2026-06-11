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
