// src/utils/crypto.js
const argon2 = require('argon2');
const crypto = require('crypto');
const { PEPPER } = require('../config/env');

async function hashPassword(password, saltBuffer) {
  const peppered = Buffer.concat([Buffer.from(password, 'utf8'), Buffer.from(PEPPER, 'utf8')]);
  const opts = {
    type: argon2.argon2id,
    salt: saltBuffer,
    memoryCost: 65536,
    timeCost: 3,
    parallelism: 2
  };
  const hash = await argon2.hash(peppered, opts);
  return hash;
}

async function verifyPassword(password, saltBuffer, storedHash) {
  const peppered = Buffer.concat([Buffer.from(password, 'utf8'), Buffer.from(PEPPER, 'utf8')]);
  return await argon2.verify(storedHash, peppered);
}

function generateRandomToken(len = 48) {
  return crypto.randomBytes(len).toString('base64url');
}

function sha256Hex(input) {
  if (Buffer.isBuffer(input)) {
    return crypto.createHash('sha256').update(input).digest('hex');
  }
  return crypto.createHash('sha256').update(String(input)).digest('hex');
}

async function encryptSecret(secretBuffer) {
  const key = crypto.createHash('sha256').update(Buffer.from(PEPPER, 'utf8')).digest();
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
  const enc = Buffer.concat([cipher.update(secretBuffer), cipher.final()]);
  const tag = cipher.getAuthTag();
  return Buffer.concat([iv, tag, enc]); // iv (12) | tag (16) | ciphertext
}

async function decryptSecret(blob) {
  const key = crypto.createHash('sha256').update(Buffer.from(PEPPER, 'utf8')).digest();
  const iv = blob.slice(0, 12);
  const tag = blob.slice(12, 28);
  const enc = blob.slice(28);
  const decipher = crypto.createDecipheriv('aes-256-gcm', key, iv);
  decipher.setAuthTag(tag);
  const out = Buffer.concat([decipher.update(enc), decipher.final()]);
  return out;
}

module.exports = { hashPassword, verifyPassword, generateRandomToken, sha256Hex, encryptSecret, decryptSecret };
