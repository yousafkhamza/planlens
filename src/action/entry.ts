import { runAction } from "./main.js";

runAction({ env: process.env, log: (s) => process.stdout.write(s.endsWith("\n") ? s : `${s}\n`) }).then(
  (code) => {
    process.exitCode = code;
  },
  (e: unknown) => {
    process.stdout.write(`::error::planlens crashed: ${String((e as Error)?.stack ?? e).replace(/\n/g, "%0A")}\n`);
    process.exitCode = 2;
  },
);
