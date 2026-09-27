import js from "@eslint/js";
import ts from "typescript-eslint";
import globals from "globals";
export default ts.config(
  js.configs.recommended,
  ...ts.configs.recommended,
  {
    files: ["**/*.{ts,tsx}"],
    languageOptions: { globals: { ...globals.browser, ...globals.node } },
  },
  {
    files: ["**/*.cjs"],
    languageOptions: { globals: globals.node },
    rules: { "@typescript-eslint/no-require-imports": "off" },
  },
  {
    files: ["tests/fixture-preload.cjs"],
    languageOptions: { globals: globals.browser },
  },
  {
    ignores: [
      "node_modules/**",
      "dist/**",
      "release/**",
      "backend/**",
      "artifacts/**",
    ],
  },
);
