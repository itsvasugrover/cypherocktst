import { Buffer } from "node:buffer";

import { Client } from "./client.ts";
import env from "./env.ts";
import * as comms from "./proto/comms.ts";
import { Crypto } from "./utils/crypto.ts";
import { logger } from "./utils/logger.ts";

const MIN_VAL = env.MIN_VAL;
const MAX_VAL = env.MAX_VAL;
const SECRET = env.SECRET;
let responseCount = 0;
const TOTAL_ATTEMPTS = env.TOTAL_ATTEMPTS;

async function main() {
  logger.info("--- Client Starting ---");
  logger.info(`[Config] Range: [${MIN_VAL}, ${MAX_VAL}], Secret: ${SECRET}`);

  if (SECRET < MIN_VAL || SECRET > MAX_VAL) {
    logger.error("Secret is out of range! Proof will fail logically, but we proceed to test protocol.");
  }

  // Load keys from PEM files defined in env
  const cryptoLoader = new Crypto();
  const privKey = cryptoLoader.loadPrivateKeyFromPem(env.CLIENT_PRIVATE_KEY);
  if (privKey.length === 0) {
    logger.error("Failed to load Client Private Key");
    process.exit(1);
  }

  const serverPub = cryptoLoader.loadPublicKeyFromPem(env.SERVER_PUBLIC_KEY);
  if (serverPub.length === 0) {
    logger.error("Failed to load Server Public Key");
    process.exit(1);
  }

  // Initialize Signer with loaded key
  const signer = new Crypto(Buffer.from(privKey).toString("hex"));
  const serverPubKeyBuf = Buffer.from(serverPub);

  const client = new Client(env.SERVER_HOST, env.SERVER_PORT);

  let receivedBuffer = Buffer.alloc(0);

  (client as any).handleIncomingData = async (chunk: Buffer) => {
    receivedBuffer = Buffer.concat([receivedBuffer, chunk]);

    while (receivedBuffer.length >= 4) {
      const len = receivedBuffer.readUInt32LE(0);
      if (receivedBuffer.length < 4 + len) {
        break;
      }
      const body = receivedBuffer.subarray(4, 4 + len);
      receivedBuffer = receivedBuffer.subarray(4 + len);
      try {
        const msg = comms.GenericMessage.decode(body);

        if (msg.authChallenge) {
          logger.info("[Auth] Received Challenge from Server");
          const nonce = Buffer.from(msg.authChallenge.randomNumber);
          const serverSig = Buffer.from(msg.authChallenge.serverSignature);
          const nonceHash = signer.hash(nonce);

          if (!signer.verify(serverPubKeyBuf, nonceHash, serverSig)) {
            logger.error("[Auth] Server Signature Verification FAILED!");
            client.close();
            return;
          }
          logger.info("[Auth] Server Signature Verified.");

          const mySig = signer.sign(nonceHash);
          const resp = comms.GenericMessage.create({ authResponse: { signature: mySig } });
          client.sendMessage(resp);
        }
        else if (msg.authStatus) {
          if (msg.authStatus.authenticated) {
            logger.info("[Auth] Authentication Successful.");
            // Send requests
            for (let i = 0; i < TOTAL_ATTEMPTS; i++) {
              logger.info(`[Client] Sending Proof Attempt #${i + 1}...`);
              try {
                const proof = signer.generateRangeProof(SECRET, MIN_VAL, MAX_VAL);
                const rangeMsg = comms.GenericMessage.create({
                  rangeProofRequest: {
                    minValue: MIN_VAL,
                    maxValue: MAX_VAL,
                    bitLength: 32,
                    c1: proof.c1,
                    c2: proof.c2,
                    sq0: proof.squares[0],
                    sq1: proof.squares[1],
                    sq2: proof.squares[2],
                    sq3: proof.squares[3],
                  },
                });
                logger.info("[Client] Sending Range Proof...");
                client.sendMessage(rangeMsg);
              }
              catch (e) {
                logger.error(e as any, "Proof Gen Error");
              }
            }
          }
          else {
            logger.error("[Client] Authentication Denied.");
            client.close();
          }
        }
        else if (msg.rangeProofResponse) {
          if (msg.rangeProofResponse.success) {
            logger.info(`[${responseCount + 1}/${TOTAL_ATTEMPTS}] >>> RANGE PROOF VERIFIED SUCCESSFULLY <<<`);
          }
          else {
            logger.error(`[${responseCount + 1}/${TOTAL_ATTEMPTS}] >>> RANGE PROOF FAILED <<<`);
          }

          responseCount++;
          if (responseCount >= TOTAL_ATTEMPTS) {
            logger.info("All proofs processed. Closing connection.");
            await new Promise(resolve => setTimeout(resolve, 500));
            client.close();
          }
        }
      }
      catch (e) {
        logger.error(e as any, "Decode Error");
      }
    }
  };

  try {
    await client.connect();

    // Strict Compliance: Hash Serial ID
    const serialHash = signer.hash(env.CLIENT_SERIAL_ID!);
    const signature = signer.sign(serialHash);

    const message = comms.GenericMessage.create({
      authInit: {
        serialId: env.CLIENT_SERIAL_ID,
        signature,
      },
    });

    logger.info("[Client] Sending AuthInit...");
    logger.info(`[Client] Serial ID: ${env.CLIENT_SERIAL_ID}`);
    client.sendMessage(message);
  }
  catch (error) {
    logger.error(error as any, "Main Error");
  }
}

main();
