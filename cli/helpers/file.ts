import { readFileSync, writeFileSync } from "fs";
import { join } from "path";

export function readJson<T>(relativePath: string): T {
  return JSON.parse(
    readFileSync(join(__dirname, "../", relativePath), "utf-8"),
  ) as T;
}

export function writeJson(relativePath: string, data: unknown): void {
  writeFileSync(
    join(__dirname, "../", relativePath),
    JSON.stringify(data, null, 2),
    "utf-8",
  );
}
