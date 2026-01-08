import dotenv from "dotenv";
import path from "path";

dotenv.config({ path: path.join(__dirname, ".env") });

// For deployment - only need deployer private key and signer addresses
const DEPLOYER_PRIVATE_KEY_RAW = process.env.DEPLOYER_PRIVATE_KEY || "";
const SIGNER_ONE_ADDRESS_RAW = process.env.SIGNER_ONE_ADDRESS || "";
const SIGNER_TWO_ADDRESS_RAW = process.env.SIGNER_TWO_ADDRESS || "";
const SIGNER_THREE_ADDRESS_RAW = process.env.SIGNER_THREE_ADDRESS || "";

// For execution - need signer private keys for signing multisig transactions
const SIGNER_ONE_PRIVATE_KEY_RAW = process.env.SIGNER_ONE_PRIVATE_KEY || "";
const SIGNER_TWO_PRIVATE_KEY_RAW = process.env.SIGNER_TWO_PRIVATE_KEY || "";
const SIGNER_THREE_PRIVATE_KEY_RAW = process.env.SIGNER_THREE_PRIVATE_KEY || "";
const PERMISSION_ADDRESS_RAW = process.env.PERMISSION_ADDRESS || "";

export const DEPLOYER_PRIVATE_KEY = ensureHexPrefix(DEPLOYER_PRIVATE_KEY_RAW);
export const SIGNER_ONE_ADDRESS = ensureHexPrefix(SIGNER_ONE_ADDRESS_RAW);
export const SIGNER_TWO_ADDRESS = ensureHexPrefix(SIGNER_TWO_ADDRESS_RAW);
export const SIGNER_THREE_ADDRESS = ensureHexPrefix(SIGNER_THREE_ADDRESS_RAW);

export const SIGNER_ONE_PRIVATE_KEY = ensureHexPrefix(
  SIGNER_ONE_PRIVATE_KEY_RAW
);
export const SIGNER_TWO_PRIVATE_KEY = ensureHexPrefix(
  SIGNER_TWO_PRIVATE_KEY_RAW
);
export const SIGNER_THREE_PRIVATE_KEY = ensureHexPrefix(
  SIGNER_THREE_PRIVATE_KEY_RAW
);
export const PERMISSION_ADDRESS = ensureHexPrefix(PERMISSION_ADDRESS_RAW);

// deploy.ts only needs: DEPLOYER_PRIVATE_KEY + signer addresses or it works with the env for the execute.ts as well
// execute.ts needs: all private keys + PERMISSION_ADDRESS

function ensureHexPrefix(key: string): string {
  if (!key) return key;
  return key.startsWith("0x") ? key : `0x${key}`;
}
