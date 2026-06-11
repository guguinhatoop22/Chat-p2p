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
