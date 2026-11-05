import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';
import { viteSingleFile } from 'vite-plugin-singlefile';
import { fileURLToPath } from 'node:url';

// One self-contained HTML file: no CDN, no separate assets, opens offline and
// ships inside the zero-dependency package as reports/dashboard.html.
export default defineConfig({
  plugins: [react(), viteSingleFile({ removeViteModuleLoader: true })],
  build: {
    outDir: fileURLToPath(new URL('../reports', import.meta.url)),
    emptyOutDir: false,
    target: 'es2022',
    cssCodeSplit: false,
    assetsInlineLimit: 100000000,
    rollupOptions: { input: fileURLToPath(new URL('./dashboard.html', import.meta.url)) },
  },
});
