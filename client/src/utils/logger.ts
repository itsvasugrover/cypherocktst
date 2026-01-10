import pino from "pino";

import env from "./../env.ts";

// Create a pretty logger instance
const logger = pino({
  transport: env.NODE_ENV === "production"
    ? {
        targets: [
          {
            target: "pino/file",
            options: {
              destination: "./logs/client.log",
              mkdir: true,
              append: true,
              level: env.LOG_LEVEL,
              sync: true,
            },
          },
          {
            target: "pino/file",
            options: {
              destination: 1,
              level: env.LOG_LEVEL,
            },
          },
        ],
      }
    : {
        targets: [
          {
            target: "pino/file",
            options: {
              destination: "./logs/client.log",
              mkdir: true,
              append: false,
              level: env.LOG_LEVEL,
              sync: true,
            },
          },
          {
            target: "pino-pretty",
            options: {
              colorize: true,
              translateTime: "SYS:standard",
              ignore: "pid,hostname",
              level: env.LOG_LEVEL,
            },
          },
        ],
      },
});

// Export the logger for direct use
export { logger };
