# P2P Secure Chat

Chat peer-to-peer com criptografia ponta a ponta (E2E), sem servidor central. Construído com Electron, libp2p e protocolos inspirados no Signal (X3DH + Double Ratchet).

**Repositório:** [github.com/guguinhatoop22/Chat-p2p](https://github.com/guguinhatoop22/Chat-p2p)

---

## Visão geral

O P2P Secure Chat conecta usuários diretamente entre si — não há servidor de mensagens no meio. Cada instalação roda um **daemon de rede** isolado do processo gráfico (Electron), de modo que comprometer a interface não expõe automaticamente as chaves criptográficas.

```
┌─────────────────┐     IPC      ┌──────────────────┐     libp2p     ┌─────────────┐
│  Electron UI    │ ◄──────────► │  Node Daemon     │ ◄────────────► │  Outro peer │
│  (renderer)     │              │  (node.js)       │                │             │
└─────────────────┘              └──────────────────┘                └─────────────┘
                                         │
                                         ├── X3DH + Double Ratchet (E2E)
                                         ├── SQLite (histórico, contatos)
                                         └── ~/.p2p-secure/ (chaves cifradas)
```

---

## Funcionalidades

| Recurso | Status |
|---------|--------|
| Mensagens E2E criptografadas (X3DH + Double Ratchet) | ✅ Etapa 3 |
| Rede P2P via libp2p (TCP, WebSockets, DHT, Noise) | ✅ |
| Handshake automático ao conectar peers | ✅ |
| Identidade persistente com chaves cifradas (Argon2id) | ✅ |
| QR Code para compartilhar PeerID / multiaddr | ✅ |
| Histórico de chat local (SQLite) | ✅ |
| Múltiplas instâncias para teste local | ✅ |
| Roteamento onion (cells, encrypt) | 🔧 Em desenvolvimento |
| WebRTC / relay / anti-Sybil | 📋 Planejado (Etapas 4–5) |

---

## Requisitos

- **Node.js** ≥ 20
- **npm** ≥ 10
- **Git**
- Windows, Linux ou macOS

Ferramentas nativas necessárias para compilar dependências (`argon2`, `better-sqlite3`):

| SO | Pacotes |
|----|---------|
| Windows | [Visual Studio Build Tools](https://visualstudio.microsoft.com/visual-cpp-build-tools/) com workload "Desktop development with C++" |
| Linux (Debian/Ubuntu) | `build-essential python3` |
| macOS | Xcode Command Line Tools (`xcode-select --install`) |

---

## Instalação

### Opção 1 — Manual (recomendado)

```bash
git clone https://github.com/guguinhatoop22/Chat-p2p.git
cd Chat-p2p/p2p-secure
npm install
```

### Opção 2 — Script de setup (Linux/macOS)

```bash
chmod +x setup-p2p-secure_Version3.sh
./setup-p2p-secure_Version3.sh
```

Flags disponíveis:

| Flag | Descrição |
|------|-----------|
| `--force` | Sobrescreve pasta existente |
| `--no-install` | Pula `npm install` (útil para CI) |

---

## Uso

### Iniciar o aplicativo

```bash
cd p2p-secure
npm start
```

### Apenas o daemon de rede

```bash
npm run start:daemon
```

### Desenvolvimento (Linux/macOS)

```bash
./scripts/start-dev.sh
```

### Conectar dois peers

1. Abra o app em **duas máquinas** (ou duas instâncias na mesma rede local).
2. Copie o **multiaddr** exibido na barra lateral (ex.: `/ip4/192.168.1.10/tcp/41234/p2p/12D3KooW...`).
3. Cole no campo "Conectar a peer" da outra instância e clique **Conectar**.
4. O handshake X3DH ocorre automaticamente; as mensagens passam a ser E2E.

> **Dica:** peers na mesma LAN geralmente se conectam por IP local. Para redes diferentes, será necessário relay ou port forwarding (planejado nas próximas etapas).

---

## Build

```bash
# Instalador Windows (.exe NSIS)
npm run build:win

# AppImage / .deb (Linux)
npm run build

# Pasta descompactada (sem instalador)
npm run build:dir
```

O artefato gerado fica em `p2p-secure/dist/`.

---

## Scripts disponíveis

| Comando | Descrição |
|---------|-----------|
| `npm start` | Abre o app Electron |
| `npm run start:daemon` | Inicia só o daemon P2P |
| `npm run build:win` | Gera instalador Windows |
| `npm test` | Executa testes Jest |
| `npm run test:security` | Testes de segurança |
| `npm run lint` | ESLint nos módulos `src/` |
| `npm run lint:fix` | Corrige problemas de lint automaticamente |

---

## Arquitetura do código

```
p2p-secure/
├── src/
│   ├── ui/              # Electron (main, renderer, preload)
│   ├── network/         # Daemon libp2p, handshake, chat protocol
│   ├── crypto/          # RNG, X3DH, Double Ratchet, storage
│   ├── identity/        # Geração de chaves e fingerprint
│   ├── persistence/     # SQLite, journal, recovery, secure delete
│   ├── onion/           # Roteamento onion (em desenvolvimento)
│   └── traffic/         # Traffic shaping
├── assets/              # Ícones do app
├── scripts/             # Scripts de desenvolvimento
└── tests/               # Testes Jest (a adicionar)
```

### Módulos de segurança

- **`rng.js`** — RNG com health check (chi-quadrado) e reseed a cada 30 min; bloqueia geração de chaves se falhar.
- **`x3dh.js`** — Extended Triple Diffie-Hellman sobre Curve25519 (libsodium).
- **`session.js`** — Double Ratchet com forward secrecy e break-in recovery.
- **`storage.js`** — Cifragem de arquivos com Argon2id + XSalsa20-Poly1305.
- **`memory.js`** — Zeroização de buffers sensíveis após uso.

### Dados locais

Todos os dados sensíveis ficam em `~/.p2p-secure/` (ou `%USERPROFILE%\.p2p-secure\` no Windows):

| Arquivo | Conteúdo |
|---------|----------|
| `device.key` | Segredo do dispositivo (32 bytes, chmod 600) |
| `identity.enc` | Chaves X3DH cifradas |
| `libp2p.key` | Chave Ed25519 do PeerID libp2p |
| `chat.db` | Histórico de mensagens (SQLite) |

> **Nunca** commite arquivos de `~/.p2p-secure/` — eles estão no `.gitignore`.

---

## Segurança

- **Isolamento de processos:** daemon separado do renderer Electron.
- **CSP rígido:** sem `eval`, sem scripts inline.
- **`contextIsolation` + `sandbox`** no Electron.
- **Noise Protocol XX** no transporte libp2p.
- **Math.random() proibido** em módulos críticos (regra ESLint que quebra o build).
- **Deniability:** MAC simétrico — receptor não pode provar autoria a terceiros.

### Roadmap de segurança

| Etapa | Objetivo |
|-------|----------|
| 3 (atual) | X3DH + Double Ratchet sobre libsodium |
| 4 | Migrar para `@signalapp/libsignal-client` (auditado) + One-Time Pre-Keys |
| 5 | Relay, anti-Sybil, rendezvous rotativo |

---

## Contribuindo

1. Faça um fork do repositório.
2. Crie uma branch: `git checkout -b feature/minha-feature`
3. Commit: `git commit -m "feat: descrição da mudança"`
4. Push: `git push origin feature/minha-feature`
5. Abra um Pull Request.

Antes de submeter, execute:

```bash
npm run lint
npm test
```

---

## Licença

Projeto em desenvolvimento ativo. Licença a definir.

---

## Autor

[guguinhatoop22](https://github.com/guguinhatoop22)
