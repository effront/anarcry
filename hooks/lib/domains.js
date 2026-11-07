const VALID_DOMAINS = [
  'web-scanner',
  'crypto-scanner',
  'exploit',
  'auth',
  'model',
  'report',
  'tui',
  'gui',
  'assistant',
  'infra',
  'testing',
  'general',
];

function isValid(domain) {
  return VALID_DOMAINS.includes(String(domain || '').toLowerCase());
}

module.exports = { VALID_DOMAINS, isValid };
