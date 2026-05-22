import { defineConfig } from "eslint/config";
import globals from "globals";
import js from "@eslint/js";
import react from "eslint-plugin-react";
import reactHooks from "eslint-plugin-react-hooks";
import importPlugin from "eslint-plugin-import";
import jsxA11y from "eslint-plugin-jsx-a11y";

export default defineConfig([
    js.configs.recommended,
    {
        languageOptions: {
            globals: {
                ...globals.browser,
                ...globals.node,
                process: "readonly",
                global: "readonly",
            },

            ecmaVersion: "latest",
            sourceType: "module",

            parserOptions: {
                ecmaFeatures: {
                    jsx: true,
                },
            },
        },

        plugins: {
            react,
            "react-hooks": reactHooks,
            import: importPlugin,
            "jsx-a11y": jsxA11y,
        },

        rules: {
            // --- Logic / quality rules (from certego configs) ---
            "prefer-destructuring": ["error", { object: true, array: false }],
            "guard-for-in": "off",
            "no-plusplus": "off",
            "no-param-reassign": "off",
            "no-console": "off",
            "no-unused-vars": "off",
            "no-underscore-dangle": ["error", { allowAfterThis: true }],
            "no-bitwise": "off",
            "no-nested-ternary": "off",
            "no-restricted-syntax": ["error", "WithStatement"],
            "no-multiple-empty-lines": ["error", { max: 2, maxBOF: 0, maxEOF: 0 }],
            "max-len": ["error", {
                code: 160,
                ignoreStrings: true,
                ignoreUrls: true,
                ignoreTemplateLiterals: true,
                ignoreRegExpLiterals: true,
                ignoreComments: true,
            }],

            // --- React rules ---
            "react/jsx-props-no-spreading": "off",
            "react/jsx-key": "error",
            "react/forbid-prop-types": "off",
            "react/react-in-jsx-scope": "off",
            "react/prop-types": "off",
            "react/display-name": "off",

            // --- React hooks ---
            "react-hooks/rules-of-hooks": "error",
            "react-hooks/exhaustive-deps": "warn",

            // --- Import rules ---
            "import/prefer-default-export": "off",

            // --- jsx-a11y rules (certego overrides) ---
            "jsx-a11y/control-has-associated-label": "off",
            "jsx-a11y/alt-text": "off",
            "jsx-a11y/click-events-have-key-events": "off",
            "jsx-a11y/no-static-element-interactions": "off",
            "jsx-a11y/interactive-supports-focus": "off",
            "jsx-a11y/anchor-has-content": "off",
            "jsx-a11y/no-noninteractive-element-interactions": "off",
        },
    },

    // Test file globals
    {
        files: ["tests/**/*.{js,jsx}"],

        languageOptions: {
            globals: {
                describe: "readonly",
                it: "readonly",
                expect: "readonly",
                beforeEach: "readonly",
                afterEach: "readonly",
                test: "readonly",
                afterAll: "readonly",
                beforeAll: "readonly",
                vi: "readonly",
            },
        },
    },
    {
        ignores: ["node_modules/**", "dist/**", "build/**", ".snapshots/**", "**/*.min.js"],
    },
]);