import { Buffer } from "node:buffer";

import { Client } from "./client.ts";
import env from "./env.ts";
import * as comms from "./proto/comms.ts";
import { Crypto } from "./utils/crypto.ts";
import { logger } from "./utils/logger.ts";

const args = process.argv.slice(2);
function getConfig(key: string, def: number) {
  const idx = args.indexOf(key);
  if (idx !== -1 && idx + 1 < args.length) {
    return Number.parseInt(args[idx + 1]!);
  }
  return def;
}

const MIN_VAL = getConfig("--min", 0);
const MAX_VAL = getConfig("--max", 100);
const SECRET = getConfig("--secret", 42);

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

  (client as any).handleIncomingData = (data: Buffer) => {
    if (data.length < 4)
      return;
    const len = data.readUInt32LE(0);
    const body = data.subarray(4, 4 + len);

    try {
      const msg = comms.GenericMessage.decode(body);

      if (msg.authChallenge) {
        logger.info("[Auth] Received Challenge from Server");

        const nonce = Buffer.from(msg.authChallenge.randomNumber);
        const serverSig = Buffer.from(msg.authChallenge.serverSignature);

        // Strict Compliance: Hash the Nonce before verify
        const nonceHash = signer.hash(nonce);

        if (!signer.verify(serverPubKeyBuf, nonceHash, serverSig)) {
          logger.error("[Auth] Server Signature Verification FAILED!");
          client.close();
          return;
        }
        logger.info("[Auth] Server Signature Verified.");

        // Sign the Nonce (Hash first)
        const mySig = signer.sign(nonceHash);

        const resp = comms.GenericMessage.create({
          authResponse: { signature: mySig },
        });
        client.sendMessage(resp);
      }
      else if (msg.authStatus) {
        if (msg.authStatus.authenticated) {
          logger.info("[Auth] Authentication Successful.");
          logger.info("Generating Range Proof...");
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
            logger.info("Sending Range Proof...");
            client.sendMessage(rangeMsg);
          }
          catch (e) {
            // Cast 'e' to any or Error to satisfy Logger signature
            logger.error(e as any, "Proof Generation Failed");
          }
        }
        else {
          logger.error("[Auth] Authentication Denied by Server.");
          client.close();
        }
      }
      else if (msg.rangeProofResponse) {
        if (msg.rangeProofResponse.success) {
          logger.info(">>> RANGE PROOF VERIFIED SUCCESSFULLY <<<");
        }
        else {
          logger.error(">>> RANGE PROOF FAILED <<<");
        }
        client.close();
      }
    }
    catch (e) {
      logger.error(e as any, "Decode Error");
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

    logger.info("Sending AuthInit...");
    logger.info(`Serial ID: ${env.CLIENT_SERIAL_ID}`);
    logger.info(`Signature: ${signature.toString('hex')}`);
    client.sendMessage(message);
  }
  catch (error) {
    logger.error(error as any, "Main Error");
  }
}

main();
