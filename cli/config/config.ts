import dotenv from "dotenv";
import path from "path";
import { requireEnv } from "../flows/common";
dotenv.config({ path: path.join(__dirname, "../.env") });

export const DEPLOYER_PRIVATE_KEY = ensureHexPrefix(
  requireEnv("DEPLOYER_PRIVATE_KEY")
);
export const SIGNER_ONE_ADDRESS = ensureHexPrefix(
  requireEnv("SIGNER_ONE_ADDRESS")
); // hardware wallet hence private key is not needed
export const SIGNER_TWO_PRIVATE_KEY = ensureHexPrefix(
  requireEnv("SIGNER_TWO_PRIVATE_KEY")
);
export const PERMISSION_ADDRESS = ensureHexPrefix(
  requireEnv("PERMISSION_ADDRESS")
);

function ensureHexPrefix(key: string): string {
  if (!key) return key;
  return key.startsWith("0x") ? key : `0x${key}`;
}
