const config = {
  preset: 'ts-jest',
  testEnvironment: 'node',
  // atch both regular tests and integration tests
  testMatch: [
    '<rootDir>/test/**/*.(test|integration.test).(ts|tsx|js)',
    '<rootDir>/**/*.(test|integration.test).(ts|tsx|js)',
  ],
  collectCoverage: true,
  collectCoverageFrom: [
    'src/**/*.{ts,tsx}',
    '!src/**/*.d.ts',
    '!src/**/types.ts',
    '!src/**/errors.ts',
  ],
  coverageReporters: ['text', 'lcov'],
  coveragePathIgnorePatterns: ['/node_modules/', '/dist/'],
  testPathIgnorePatterns: ['/node_modules/', '/dist/'],
  verbose: true,
  errorOnDeprecated: true,
};

export default config;
