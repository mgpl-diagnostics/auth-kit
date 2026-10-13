import { defineConfig } from "tsup";

export default defineConfig({
  entry: { index: "src/index.ts", redis: "src/redis.ts" },
  format: ["esm"],
  dts: true,
  target: "node20",
  platform: "node",
  clean: true,
  external: [/^node:/, "ioredis"],
});
