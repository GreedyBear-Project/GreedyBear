import { defineConfig } from 'vite';
import { configDefaults } from 'vitest/config';
import react from '@vitejs/plugin-react';
import { fileURLToPath } from 'url';
import path from 'path';

const __dirname = path.dirname(fileURLToPath(import.meta.url));

export default defineConfig({
    plugins: [react()],
    test: {
        globals: true,
        environment: 'jsdom',
        setupFiles: './vitest.setup.js',
        css: true,
        exclude: [...configDefaults.exclude, 'tests/visual/**'],
    },
    base: process.env.VITE_BASE_URL || '/',

    resolve: {
        alias: {
            '~bootstrap': path.resolve(__dirname, 'node_modules/bootstrap'),
            '~': path.resolve(__dirname, 'node_modules'),
        }
    },

    server: {
        port: 3001,
        proxy: {
            '/api': {
                target: 'http://localhost:80',
                changeOrigin: true,
                secure: false
            }
        }
    },

    build: {
        outDir: 'build',
        sourcemap: false,
        chunkSizeWarningLimit: 1024,
        rollupOptions: {
            output: {
                // Split large dependencies into separate chunks for better caching and smaller initial load
                codeSplitting: {
                    groups: [
                        { name: 'recharts', test: /\/recharts/ },
                        { name: 'vendor', test: /\/react(-dom|-router-dom)?\// },
                        { name: 'certego', test: /\/@certego\/certego-ui/ },
                        { name: 'reactstrap', test: /\/reactstrap/ },
                    ],
                },
            },
        },
    }
});
