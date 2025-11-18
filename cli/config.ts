import dotenv from "dotenv";
import path from "path";

dotenv.config({ path: path.join(__dirname, ".env") });

const DEPLOYER_PRIVATE_KEY_RAW = process.env.DEPLOYER_PRIVATE_KEY || "";
const SIGNER_ONE_PRIVATE_KEY_RAW = process.env.SIGNER_ONE_PRIVATE_KEY || ""; // this will get the permissions to execute or interact with the htlc's
const SIGNER_TWO_PRIVATE_KEY_RAW = process.env.SIGNER_TWO_PRIVATE_KEY || "";
const SIGNER_THREE_PRIVATE_KEY_RAW = process.env.SIGNER_THREE_PRIVATE_KEY || "";

export const DEPLOYER_PRIVATE_KEY = ensureHexPrefix(DEPLOYER_PRIVATE_KEY_RAW);
export const SIGNER_ONE_PRIVATE_KEY = ensureHexPrefix(
  SIGNER_ONE_PRIVATE_KEY_RAW
);
export const SIGNER_TWO_PRIVATE_KEY = ensureHexPrefix(
  SIGNER_TWO_PRIVATE_KEY_RAW
);
export const SIGNER_THREE_PRIVATE_KEY = ensureHexPrefix(
  SIGNER_THREE_PRIVATE_KEY_RAW
);

// Validate that all private keys are set
if (
  !DEPLOYER_PRIVATE_KEY ||
  !SIGNER_ONE_PRIVATE_KEY ||
  !SIGNER_TWO_PRIVATE_KEY ||
  !SIGNER_THREE_PRIVATE_KEY
) {
  throw new Error(
    "Missing required private keys. Please set all private keys in config.ts or as environment variables."
  );
}

function ensureHexPrefix(key: string): string {
  if (!key) return key;
  return key.startsWith("0x") ? key : `0x${key}`;
}
