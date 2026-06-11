import js from "@eslint/js";

export default [
  js.configs.recommended,
  {
    // Apenas nos módulos críticos de segurança
    files: ["src/crypto/**/*.js", "src/identity/**/*.js", "src/onion/**/*.js"],
    rules: {
      // CRÍTICO: Math.random() proibido — quebra o build se detectado
      "no-restricted-globals": ["error", {
        "name": "Math",
        "message": "Use crypto.randomBytes() ou libsodium RNG. Math.random() é proibido em módulos de segurança."
      }]
    }
  }
];
