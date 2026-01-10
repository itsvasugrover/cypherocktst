import { Buffer } from "node:buffer";

import { Client } from "./client.ts";
import * as comms from "./proto/comms.ts";

async function main() {
  const client = new Client('127.0.0.1', 8080);

  try {
    await client.connect();

    const authPayload = comms.AuthInit.create({
      serialId: "DEVICE-X-12345",
      signature: Buffer.from("dummy-signature-bytes")
    });

    const message = comms.GenericMessage.create({
      authInit: authPayload
    });

    console.log("Sending AuthInit...");
    client.sendMessage(message);

    setTimeout(() => {
      console.log("Test finished, closing.");
      client.close();
    }, 2000);

  } catch (error) {
    console.error("Main Error:", error);
  }
}

main();
