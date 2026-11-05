// Job output is untrusted text from managed hosts. It is rendered as React
// text (never HTML); this only strips terminal control sequences so apt/dnf
// progress output stays readable in a <pre>.

/* eslint-disable no-control-regex -- matching control characters is the point */
const OSC = /\x1b\][^\x07\x1b]*(?:\x07|\x1b\\)/g;
const CSI = /\x1b\[[0-?]*[ -/]*[@-~]/g;
const ESC_OTHER = /\x1b[@-Z\\-_]/g;
const CONTROL = /[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]/g;
/* eslint-enable no-control-regex */

export function sanitizeOutput(text: string): string {
  return text
    .replace(OSC, '')
    .replace(CSI, '')
    .replace(ESC_OTHER, '')
    .replace(/\r\n/g, '\n')
    .replace(/\r/g, '\n')
    .replace(CONTROL, '');
}
