const crypto = require('crypto');
const fs = require('fs');

const privateKeyBuffer = fs.readFileSync('./private.pem');

const AES_ALGORITHM = 'aes-256-ctr';
const AES_KEY_NAME = './aes-key';
const FILE_TO_DECRYPT = './file.txt';

/**
* Function decrypts encrypted buffer using given key.
* Returns decrypted message buffer.
*
* @param {Buffer} message
* @param {Buffer} key
*/
function aesDecrypt (message, key) {
    const iv = Buffer.alloc(16, 0);
    const aes = crypto.createDecipheriv(AES_ALGORITHM, key,iv);
  const decryptedBuffer = aes.update(message);
  aes.final()

  return { message: decryptedBuffer }
}

/**
* Function decrypts message with given private key.
*
* @param {Buffer} privateKey
* @param {Buffer} message
*/
function rsaDecrypt(privateKey, message) {
  return crypto.privateDecrypt(privateKey, message);
}

// Load encrypted file and encrypted key
const encryptedFile = fs.readFileSync(FILE_TO_DECRYPT);
const encryptedKey = fs.readFileSync(AES_KEY_NAME);

// Decrypt key first (this will happen on the attackers side)
const decryptedKey = rsaDecrypt(privateKeyBuffer, encryptedKey);

// Using decrypted key decrypt file
const { message: decryptedMessage } = aesDecrypt(encryptedFile, decryptedKey);

// Save decrypted file
fs.writeFileSync(FILE_TO_DECRYPT, decryptedMessage);