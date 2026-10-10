import { defineConfig } from 'vitest/config';

export default defineConfig({
  test: {
    globals: true,
    environment: 'node',
    coverage: {
      provider: 'v8',
      include: ['src/lib/**/*.ts'],
      exclude: ['src/**/*.test.ts'],
      reporter: ['text', 'lcov'],
    },
    projects: [
      {
        extends: true,
        test: {
          name: 'unit',
          include: ['src/**/*.test.ts'],
          exclude: ['src/__tests__/**'],
        },
      },
      {
        extends: true,
        test: {
          name: 'security',
          include: ['src/__tests__/security/**/*.test.ts'],
          testTimeout: 30000,
        },
      },
      {
        extends: true,
        test: {
          name: 'certs',
          include: ['src/__tests__/certs/**/*.test.ts'],
        },
      },
    ],
  },
});
