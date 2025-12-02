// reset-db.js  — run manually only with: node reset-db.js
const fs = require('fs');
const path = require('path');
const dbFile = path.join(__dirname, 'users.db');

if (fs.existsSync(dbFile)) {
  fs.unlinkSync(dbFile);
  console.log('✅ users.db deleted. Restart server to recreate the DB.');
} else {
  console.log('ℹ️ users.db not found (already clean). Start server to create DB.');
}
