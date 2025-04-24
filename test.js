const { encrypt, decrypt } = require('./script');

const samplePayload = { userId: 123, role: 'admin' };

const encrypted = encrypt(samplePayload);
const decrypted = decrypt(encrypted);

// Compare payloads
if (
  decrypted.userId === samplePayload.userId &&
  decrypted.role === samplePayload.role
) {
  console.log('Success');
} else {
  console.log('Failed');
}