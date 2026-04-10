#!/usr/bin/env node
import fs from 'fs';
import path from 'path';
import crypto from 'crypto';
import Database from 'better-sqlite3';

const DB_PATH = path.join(process.cwd(), 'store/2fa.db');
fs.mkdirSync(path.dirname(DB_PATH), { recursive: true });

let db;
try {
  db = new Database(DB_PATH);
  db.exec(`
    CREATE TABLE IF NOT EXISTS secrets (
      name TEXT PRIMARY KEY,
      secret TEXT UNIQUE NOT NULL
    )
  `);
} catch (err) {
  console.error('DB error:', err.message);
  process.exit(1);
}

const BASE32_CHARS = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
function base32ToBytes(base32) {
  let bits = 0;
  let value = 0;
  const bytes = [];
  base32 = base32.replace(/=+$/, '').toUpperCase();
  for (let i = 0; i < base32.length; i++) {
    const idx = BASE32_CHARS.indexOf(base32[i]);
    if (idx === -1) throw new Error('Invalid base32');
    value = (value << 5) | idx;
    bits += 5;
    if (bits >= 8) {
      bytes.push((value >>> (bits - 8)) & 255);
      bits -= 8;
    }
  }
  return Buffer.from(bytes);
}

function totp(secretBase32, epoch = Date.now(), timeStep = 30, digits = 6) {
  const secret = base32ToBytes(secretBase32);
  const time = Math.floor(epoch / 1000 / timeStep);
  const timeBuffer = Buffer.alloc(8);
  timeBuffer.writeBigUInt64BE(BigInt(time), 0);
  const hmac = crypto.createHmac('sha1', secret).update(timeBuffer).digest();
  const offset = hmac[hmac.length - 1] & 0xf;
  const code = (hmac[offset] & 0x7f) << 24 |
               (hmac[offset + 1] & 0xff) << 16 |
               (hmac[offset + 2] & 0xff) << 8 |
               (hmac[offset + 3] & 0xff);
  return (code % Math.pow(10, digits)).toString().padStart(digits, '0');
}

const cmd = process.argv[2];

if (cmd === 'list') {
  const rows = db.prepare('SELECT name FROM secrets ORDER BY name').all();
  for (const row of rows) {
    console.log(row.name);
  }
} else if (cmd === 'add' && process.argv[3] && process.argv[4]) {
  const name = process.argv[3];
  const secret = process.argv[4];
  try {
    base32ToBytes(secret); // Validate
    db.prepare('INSERT OR REPLACE INTO secrets (name, secret) VALUES (?, ?)').run(name, secret);
    console.log('Added/updated secret for', name);
  } catch (err) {
    console.error('Invalid secret:', err.message);
    process.exit(1);
  }
} else if (cmd === 'get' && process.argv[3]) {
  const name = process.argv[3];
  const row = db.prepare('SELECT secret FROM secrets WHERE name = ?').get(name);
  if (!row) {
    console.error('No secret found for', name);
    process.exit(1);
  }
  const code = totp(row.secret);
  console.log(code);
} else {
  console.error('Usage: node scripts/totp.js [add|get|list] <name> [secret]');
  process.exit(1);
}

db.close();
