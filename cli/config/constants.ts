import { join } from "path";

export const DEPLOY_SCRIPT_PATH = join(
  __dirname,
  "../../script/main/DeployContracts.s.sol:DeployContracts",
);

export const SCRIPT_PATHS = {
  approve: join(__dirname, "../../script/main/ApproveHTLCToken.s.sol"),
  authorize: join(__dirname, "../../script/main/AuthorizeExecutor.s.sol"),
  permissions: join(__dirname, "../../script/main/GrantHTLCPermissions.s.sol"),
  initiate: join(__dirname, "../../script/main/InitiateHTLC.s.sol"),
};

export const DIGEST_PATTERNS = {
  approval: /Digest:\s+(0x[a-fA-F0-9]{64})/i,
  authorization: /AuthDigest:\s+(0x[a-fA-F0-9]{64})/i,
  permissions: /PermDigest:\s+(0x[a-fA-F0-9]{64})/i,
};
