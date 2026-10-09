import { defineConfig, mergeConfig } from 'vitest/config';

export default defineConfig({
  test: {
    projects: [
      {
        name: 'unit',
        test: {
          include: ['src/**/*.test.ts'],
          environment: 'node',
          coverage: {
            provider: 'v8',
            reporter: ['text', 'json', 'html', 'lcov'],
            thresholds: {
              lines: 80,
              functions: 80,
              branches: 80,
              statements: 80,
            },
          },
        },
      },
      {
        name: 'security',
        test: {
          include: ['src/__tests__/security/**/*.test.ts'],
          environment: 'node',
          testTimeout: 30000,
        },
      },
      {
        name: 'certs',
        test: {
          include: ['src/__tests__/certs/**/*.test.ts'],
          environment: 'node',
        },
      },
    ],
    globals: true,
  },
});