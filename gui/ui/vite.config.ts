import {readFileSync} from 'node:fs';

import {defineConfig, type Plugin} from 'vite';
import react from '@vitejs/plugin-react';

// The app's version, read from the crate that is the app. Two places
// claiming a version is one place too many, and the sidebar's footer has to
// agree with the tray's last line.
const version = /^version = "([^"]+)"/m.exec(readFileSync('../Cargo.toml', 'utf8'))?.[1];
if (!version) {
  throw new Error('no version in ../Cargo.toml');
}

// The webview loads this build off the bundle, so every path in it has to
// be relative: there is no server root to be absolute against.
//
// Nothing is fetched at runtime. The theme is a CSS file built ahead of
// time by `npm run theme`, the fonts are the system's, and the only images
// are two inline SVG paths — so the whole window is one JS file, one CSS
// file and an index.html, and the CSP in tauri.conf.json stays at 'self'.
export default defineConfig({
  base: './',
  define: {__VERSION__: JSON.stringify(version)},
  plugins: [react(), noCrossOrigin()],
  build: {
    target: 'safari16',
    assetsDir: 'assets',
    sourcemap: false,
    // The polyfill exists to `fetch()` modulepreload links on browsers that
    // do not honour them. There is one chunk and no preload links, so it
    // would never run — and leaving the only `fetch` in the bundle unused
    // is worse than not shipping it.
    modulePreload: {polyfill: false},
    // One chunk. A window this small gains nothing from code splitting and
    // loses the guarantee that what shipped is what you can read.
    rollupOptions: {output: {inlineDynamicImports: true}},
  },
});

/**
 * Strip `crossorigin` from the emitted script and stylesheet tags.
 *
 * Vite writes it for a CDN-hosted build. This build is loaded off a custom
 * protocol by a webview, where the attribute only buys a CORS check on
 * assets that came out of the same bundle as the page.
 */
function noCrossOrigin(): Plugin {
  return {
    name: 'asterism-no-crossorigin',
    enforce: 'post',
    transformIndexHtml: html => html.replace(/\s+crossorigin(?==|\s|>)/g, ''),
  };
}
