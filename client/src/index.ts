import { Buffer } from "node:buffer";

import { GenericMessage } from "./proto/comms.ts";

console.warn("Cypherock Client Starting...");

// Test creating a message to see if Proto works
const msg = GenericMessage.create({
  authInit: {
    serialId: "TEST-SERIAL",
    signature: Buffer.from("test-sig"),
  },
});

const encoded = GenericMessage.encode(msg).finish();
console.warn(`ProtoBuf Encoded size: ${encoded.length} bytes`);
