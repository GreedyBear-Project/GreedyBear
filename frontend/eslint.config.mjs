// Canonical config lives in .github/configurations/node_linters/eslint/
// This file is a thin re-export so that IDEs and direct ESLint invocations from
// the frontend/ directory still work.
//
// Run `npm run lint-config-install` first to ensure shared config dependencies are installed.
export { default } from "../.github/configurations/node_linters/eslint/eslint.config.mjs";