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
