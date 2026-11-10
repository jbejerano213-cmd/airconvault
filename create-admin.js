const bcrypt = require('bcryptjs');
const db = require('./db');

const [, , name, email, password] = process.argv;

if (!name || !email || !password) {
  console.log('Usage: node create-admin.js "Full Name" email@example.com "password"');
  process.exit(1);
}
if (password.length < 8) {
  console.log('Password must be at least 8 characters.');
  process.exit(1);
}

try {
  db.prepare(
    `INSERT INTO users (name,email,password_hash,role,can_upload,can_download,can_delete)
     VALUES (?,?,?,'admin',1,1,1)`
  ).run(name, email.toLowerCase(), bcrypt.hashSync(password, 12));
  console.log('Administrator created.');
} catch (e) {
  console.log(e.code === 'SQLITE_CONSTRAINT_UNIQUE' ? 'That email already exists.' : e.message);
}