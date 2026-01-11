import type { ZodError } from "zod";

import { config } from "dotenv";
import { expand } from "dotenv-expand";
import { readFileSync } from "node:fs";
import z from "zod";

expand(config());

const ENV_SCHEMA = z.object({
  NODE_ENV: z.enum(["development", "test", "production"]).default("development"),
  LOG_LEVEL: z.enum(["trace", "debug", "info", "warn", "error", "fatal"]).default("info"),
  SERVER_HOST: z.string().default("127.0.0.1"),
  SERVER_PORT: z.coerce.number().default(8080),
  MIN_VAL: z.coerce.number().default(0),
  MAX_VAL: z.coerce.number().default(100),
  SECRET: z.coerce.number().default(42),
  TOTAL_ATTEMPTS: z.coerce.number().default(3),
  CLIENT_SERIAL_ID: z.string().optional().default(readFileSync("./keys/client_serial_id.txt", "utf-8").trim()),
  CLIENT_PRIVATE_KEY: z.string().optional().default(readFileSync("./keys/client_private_key.pem", "utf-8").trim()),
  SERVER_PUBLIC_KEY: z.string().optional().default(readFileSync("./keys/server_public_key.pem", "utf-8").trim()),
});

export type Env = z.infer<typeof ENV_SCHEMA>;

// eslint-disable-next-line import/no-mutable-exports
let env: Env;

try {
  // eslint-disable-next-line node/no-process-env
  env = ENV_SCHEMA.parse(process.env);
}
catch (error) {
  const envError = error as ZodError;
  console.error("Invalid environment variables: ");
  console.error(envError.flatten().fieldErrors);
  process.exit(1);
}

export default env;
