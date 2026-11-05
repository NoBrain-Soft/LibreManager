import { describe, expect, it } from 'vitest';
import { sanitizeOutput } from './text';

describe('sanitizeOutput', () => {
  it('strips ANSI color and cursor sequences', () => {
    expect(sanitizeOutput('\x1b[1;31mE:\x1b[0m failed\x1b[2K')).toBe('E: failed');
  });

  it('strips OSC sequences (titles, hyperlinks)', () => {
    expect(sanitizeOutput('\x1b]0;title\x07ok \x1b]8;;https://x\x1b\\link\x1b]8;;\x1b\\')).toBe('ok link');
  });

  it('normalizes carriage returns and keeps tabs/newlines', () => {
    expect(sanitizeOutput('a\r\nb\rc\td\n')).toBe('a\nb\nc\td\n');
  });

  it('removes other control characters but keeps unicode and HTML-like text as-is', () => {
    expect(sanitizeOutput('x\x00\x07y <script>alert(1)</script> ü')).toBe('xy <script>alert(1)</script> ü');
  });
});
