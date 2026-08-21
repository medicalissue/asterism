import {defineTheme} from '@astryxdesign/core/theme';

/**
 * Asterism's application theme lives with the application. Nothing in this
 * file is shared with, generated from, or resolved through a private repo.
 */
export const asterismTheme = defineTheme({
  name: 'asterism',
  tokens: {
    '--color-accent': ['#5e5ce6', '#8b89ff'],
    '--color-on-accent': ['#ffffff', '#11111a'],
    '--color-background-body': ['#f7f7f8', '#0f1013'],
    '--color-background-surface': ['#ffffff', '#15161a'],
    '--color-background-card': ['#ffffff', '#191a1f'],
    '--color-background-popover': ['#ffffff', '#202126'],
    '--color-background-muted': ['#f0f0f2', '#1d1e23'],
    '--color-text-primary': ['#17171a', '#f4f4f5'],
    '--color-text-secondary': ['#68686f', '#9d9da6'],
    '--color-text-disabled': ['#a6a6ac', '#62626a'],
    '--color-border': ['rgba(23, 23, 26, 0.10)', 'rgba(244, 244, 245, 0.10)'],
    '--color-border-emphasized': ['rgba(23, 23, 26, 0.20)', 'rgba(244, 244, 245, 0.20)'],
    '--radius-inner': '5px',
    '--radius-element': '7px',
    '--radius-container': '10px',
    '--font-family-body': '-apple-system, BlinkMacSystemFont, "SF Pro Text", "Segoe UI", sans-serif',
    '--font-family-heading': '-apple-system, BlinkMacSystemFont, "SF Pro Display", "Segoe UI", sans-serif',
    '--font-family-code': 'ui-monospace, Menlo, Consolas, monospace',
    '--font-size-sm': '0.8125rem',
    '--font-size-base': '0.875rem',
  },
  components: {
    button: {
      base: {fontWeight: '520', letterSpacing: '-0.005em'},
    },
  },
});
