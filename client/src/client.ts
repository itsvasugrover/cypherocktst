import { Buffer } from "node:buffer";
import * as net from "node:net";

import * as comms from "./proto/comms.ts";
import { logger } from "./utils/logger.ts";

export class Client {
  private socket: net.Socket;
  private host: string;
  private port: number;

  constructor(host: string, port: number) {
    this.host = host;
    this.port = port;
    this.socket = new net.Socket();
  }

  public connect(): Promise<void> {
    return new Promise((resolve, reject) => {
      this.socket.connect(this.port, this.host, () => {
        logger.info(`[Client] Connected to ${this.host}:${this.port}`);
        resolve();
      });

      this.socket.on("error", (err) => {
        logger.error(`[Client] Connection Error: ${err.message}`);
        reject(err);
      });

      this.socket.on("close", () => {
        logger.info("[Client] Connection closed");
      });

      this.socket.on("data", (data) => {
        this.handleIncomingData(data as Buffer);
      });
    });
  }

  public sendMessage(payload: comms.GenericMessage): void {
    // logger.info(`[Client] Sending Message to Server: ${JSON.stringify(payload)}`);
    const buffer = comms.GenericMessage.encode(payload).finish();

    const head = Buffer.alloc(4);
    // logger.info(`[Client] Preparing to send ${buffer.length} bytes`);
    head.writeUInt32LE(buffer.length, 0);

    const packet = Buffer.concat([head, buffer]);
    // logger.info(`[Client] Sending ${packet.length} bytes`);
    this.socket.write(packet);
    const messageType = Object.keys(payload).find(key => (payload as any)[key] !== undefined) || "unknown";
    logger.info(`[Client] Sent ${buffer.length} bytes (Type: ${messageType})`);
  }

  private handleIncomingData(data: Buffer) {
    if (data.length < 4)
      return;

    const len = data.readUInt32LE(0);
    const body = data.subarray(4, 4 + len);

    try {
      const msg = comms.GenericMessage.decode(body);
      logger.info(`[Client] Received Message from Server: ${JSON.stringify(msg)}`);
    }
    catch (e) {
      logger.error("[Client] Failed to decode response:", e);
    }
  }

  public close() {
    this.socket.end();
  }
}
