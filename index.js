// ============================================
// DEPRECATED: Use server.js instead
// ============================================
// This file is kept for compatibility.
// All functionality has been moved to server.js
// which is now the primary entry point.
//
// The package.json has been updated to run:
//   npm start → node server.js
//   npm run dev → nodemon server.js
// ============================================

console.warn('⚠️  WARNING: index.js is deprecated. Use server.js instead.');
console.warn('Redirecting to server.js...\n');

require('./server.js');

