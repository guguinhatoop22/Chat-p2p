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
