module.exports = {
  root: true,
  env: {
    node: true,
    es2022: true
  },
  extends: [
    'standard'
  ],
  parserOptions: {
    ecmaVersion: 'latest',
    sourceType: 'module'
  },
  rules: {
    'no-console': 'off'
  }
};
