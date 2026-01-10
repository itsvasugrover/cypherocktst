const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

// Generate client keys
const clientKeyPair = crypto.generateKeyPairSync('ec', {
    namedCurve: 'secp256k1',
    publicKeyEncoding: { type: 'spki', format: 'pem' },
    privateKeyEncoding: { type: 'sec1', format: 'pem' }
});

// Generate server keys
const serverKeyPair = crypto.generateKeyPairSync('ec', {
    namedCurve: 'secp256k1',
    publicKeyEncoding: { type: 'spki', format: 'pem' },
    privateKeyEncoding: { type: 'sec1', format: 'pem' }
});

// Generate serial ID (32 hex characters)
const serialId = crypto.randomBytes(16).toString('hex');

// Ensure keys directory exists in server and client directory respectively
if (!fs.existsSync(path.join(__dirname, 'server', 'keys'))) {
    fs.mkdirSync(path.join(__dirname, 'server', 'keys'), { recursive: true });
}

if (!fs.existsSync(path.join(__dirname, 'client', 'keys'))) {
    fs.mkdirSync(path.join(__dirname, 'client', 'keys'), { recursive: true });
}

// Write to server keys directory
const serverKeysDir = path.join(__dirname, 'server', 'keys');

fs.writeFileSync(path.join(serverKeysDir, 'client_public_key.pem'), clientKeyPair.publicKey);
fs.writeFileSync(path.join(serverKeysDir, 'server_private_key.pem'), serverKeyPair.privateKey);

// Write to client keys directory
const clientKeysDir = path.join(__dirname, 'client', 'keys');

fs.writeFileSync(path.join(clientKeysDir, 'client_private_key.pem'), clientKeyPair.privateKey);
fs.writeFileSync(path.join(clientKeysDir, 'server_public_key.pem'), serverKeyPair.publicKey);
fs.writeFileSync(path.join(clientKeysDir, 'client_serial_id.txt'), serialId);

console.log('Keys generated successfully.');
console.log(`Client Serial ID: ${serialId}`);
console.log('Files created in client/keys and server/keys directories:');
console.log('- server/keys/client_public_key.pem');
console.log('- server/keys/server_private_key.pem');
console.log('- client/keys/client_serial_id.txt');
console.log('- client/keys/client_private_key.pem');
console.log('- client/keys/server_public_key.pem');