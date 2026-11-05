import js from '@eslint/js';
import { defineConfig, globalIgnores } from 'eslint/config';
import reactHooks from 'eslint-plugin-react-hooks';
import reactRefresh from 'eslint-plugin-react-refresh';
import globals from 'globals';
import tseslint from 'typescript-eslint';

// Security-relevant restrictions (CLAUDE.md rule 8, strict CSP):
// - never render server strings as HTML
// - no eval-like constructs
// - no tokens in Web Storage (the only allowed use is the theme preference,
//   which carries an explicit eslint-disable with justification)
const securityRules = {
  'no-eval': 'error',
  'no-new-func': 'error',
  'no-script-url': 'error',
  'no-restricted-syntax': [
    'error',
    {
      selector: "JSXAttribute[name.name='dangerouslySetInnerHTML']",
      message: 'Never render server-provided strings as HTML.',
    },
    {
      selector: "MemberExpression[property.name=/^(innerHTML|outerHTML)$/]",
      message: 'Never assign HTML strings; build DOM nodes or use React.',
    },
    {
      selector: "CallExpression[callee.property.name='insertAdjacentHTML']",
      message: 'Never insert HTML strings.',
    },
  ],
  'no-restricted-globals': [
    'error',
    { name: 'localStorage', message: 'No tokens/secrets in Web Storage (CLAUDE.md rule 8).' },
    { name: 'sessionStorage', message: 'No tokens/secrets in Web Storage (CLAUDE.md rule 8).' },
  ],
  'no-restricted-properties': [
    'error',
    { object: 'window', property: 'localStorage', message: 'No tokens/secrets in Web Storage.' },
    { object: 'window', property: 'sessionStorage', message: 'No tokens/secrets in Web Storage.' },
    { object: 'document', property: 'write', message: 'Not allowed.' },
  ],
};

export default defineConfig([
  globalIgnores(['dist', 'node_modules', 'coverage', 'src/api/schema.d.ts']),
  {
    files: ['**/*.{ts,tsx}'],
    extends: [
      js.configs.recommended,
      tseslint.configs.recommendedTypeChecked,
      reactHooks.configs.flat.recommended,
      reactRefresh.configs.vite,
    ],
    languageOptions: {
      ecmaVersion: 2022,
      globals: globals.browser,
      parserOptions: {
        projectService: true,
        tsconfigRootDir: import.meta.dirname,
      },
    },
    rules: {
      ...securityRules,
      '@typescript-eslint/no-implied-eval': 'error',
      '@typescript-eslint/no-unused-vars': [
        'error',
        { argsIgnorePattern: '^_', varsIgnorePattern: '^_', caughtErrors: 'none' },
      ],
      '@typescript-eslint/no-misused-promises': ['error', { checksVoidReturn: { attributes: false } }],
      '@typescript-eslint/consistent-type-imports': ['error', { fixStyle: 'inline-type-imports' }],
      'react-refresh/only-export-components': ['warn', { allowConstantExport: true }],
    },
  },
  {
    files: ['src/**/*.test.{ts,tsx}'],
    rules: {
      '@typescript-eslint/no-non-null-assertion': 'off',
      '@typescript-eslint/unbound-method': 'off',
    },
  },
  {
    files: ['**/*.js'],
    extends: [js.configs.recommended],
    languageOptions: { ecmaVersion: 2022, sourceType: 'module', globals: globals.node },
  },
]);
