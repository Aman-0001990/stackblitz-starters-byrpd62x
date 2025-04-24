const jwt = require('jsonwebtoken');
const crypto = require('crypto');

const SECRET_KEY = 'my_super_secret_key'; // for JWT signing
const ENCRYPTION_KEY = crypto.randomBytes(32); // 256-bit key
const IV = crypto.randomBytes(16); // Initialization Vector

// Encrypt the payload -> sign with JWT -> encrypt the token
const encrypt = (payload) => {
  const token = jwt.sign(payload, SECRET_KEY, { expiresIn: '1h' });
  const cipher = crypto.createCipheriv('aes-256-cbc', ENCRYPTION_KEY, IV);
  let encrypted = cipher.update(token, 'utf8', 'hex');
  encrypted += cipher.final('hex');
  const encryptedData = IV.toString('hex') + ':' + encrypted;
  return encryptedData;
};

// Decrypt the token -> verify JWT -> get payload
const decrypt = (token) => {
  const parts = token.split(':');
  const iv = Buffer.from(parts[0], 'hex');
  const encryptedText = parts[1];
  const decipher = crypto.createDecipheriv('aes-256-cbc', ENCRYPTION_KEY, iv);
  let decrypted = decipher.update(encryptedText, 'hex', 'utf8');
  decrypted += decipher.final('utf8');
  const payload = jwt.verify(decrypted, SECRET_KEY);
  return payload;
};

module.exports = {
  encrypt,
  decrypt
};