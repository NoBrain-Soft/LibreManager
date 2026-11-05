import type { ILinkHandler, ITerminalOptions, ITheme } from '@xterm/xterm';
import { cssVar, type ResolvedTheme } from '@/app/theme';

const LIGHT_ANSI: Partial<ITheme> = {
  black: '#1d1d1b',
  red: '#b02626',
  green: '#1d7a1d',
  yellow: '#8a5a00',
  blue: '#1c5cab',
  magenta: '#9b3a7a',
  cyan: '#0f7a73',
  white: '#6b6a65',
  brightBlack: '#52514e',
  brightRed: '#d03b3b',
  brightGreen: '#008300',
  brightYellow: '#a86d00',
  brightBlue: '#2a78d6',
  brightMagenta: '#c2508f',
  brightCyan: '#138f87',
  brightWhite: '#3a3a37',
};

const DARK_ANSI: Partial<ITheme> = {
  black: '#2c2c2a',
  red: '#e66767',
  green: '#3fbf5f',
  yellow: '#e5b03a',
  blue: '#5a9cec',
  magenta: '#d57fb3',
  cyan: '#3cc4b8',
  white: '#d8d7d2',
  brightBlack: '#6b6a65',
  brightRed: '#f08a8a',
  brightGreen: '#6fd98a',
  brightYellow: '#f2cc6b',
  brightBlue: '#86b6ef',
  brightMagenta: '#e8a3cd',
  brightCyan: '#73dcd2',
  brightWhite: '#f6f5f2',
};

export function xtermTheme(mode: ResolvedTheme): ITheme {
  const bg = cssVar('--term-bg', mode === 'dark' ? '#121211' : '#fbfbfa');
  const fg = cssVar('--term-fg', mode === 'dark' ? '#e8e7e3' : '#1d1d1b');
  return {
    background: bg,
    foreground: fg,
    cursor: fg,
    cursorAccent: bg,
    selectionBackground: mode === 'dark' ? 'rgba(57,135,229,0.40)' : 'rgba(42,120,214,0.25)',
    ...(mode === 'dark' ? DARK_ANSI : LIGHT_ANSI),
  };
}

/** Links (OSC 8 / URLs) only open http(s) after confirmation, without opener. */
export const safeLinkHandler: ILinkHandler = {
  allowNonHttpProtocols: false,
  activate(_event, text) {
    let url: URL;
    try {
      url = new URL(text);
    } catch {
      return;
    }
    if (url.protocol !== 'http:' && url.protocol !== 'https:') return;
    if (window.confirm(`Open this link from the terminal?\n\n${url.href}`)) {
      window.open(url.href, '_blank', 'noopener,noreferrer');
    }
  },
};

export const XTERM_FONT = "ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, 'Liberation Mono', 'DejaVu Sans Mono', monospace";

export function baseTerminalOptions(mode: ResolvedTheme): ITerminalOptions {
  return {
    fontFamily: XTERM_FONT,
    fontSize: 13,
    lineHeight: 1.15,
    scrollback: 5000,
    theme: xtermTheme(mode),
    linkHandler: safeLinkHandler,
    allowProposedApi: false,
    macOptionIsMeta: true,
  };
}
