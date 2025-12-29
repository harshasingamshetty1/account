import { join } from "path";

export const SCRIPT_PATHS = {
  deploy: join(__dirname, "../../script/main/DeployContracts.s.sol"),
  approve: join(__dirname, "../../script/main/ApproveHTLCToken.s.sol"),
  authorize: join(__dirname, "../../script/main/AuthorizeExecutor.s.sol"),
  permissions: join(__dirname, "../../script/main/GrantHTLCPermissions.s.sol"),
  initiate: join(__dirname, "../../script/main/InitiateHTLC.s.sol"),
  withdraw: join(__dirname, "../../script/main/WithdrawHTLC.s.sol"),
  withdrawNative: join(__dirname, "../../script/main/WithdrawNative.s.sol"),
  whitelist: join(__dirname, "../../script/main/WhitelistAddress.s.sol"),
  changeCooldown: join(
    __dirname,
    "../../script/main/ChangeCooldownPeriod.s.sol",
  ),
  setSpendLimit: join(__dirname, "../../script/main/SetSpendLimit.s.sol"),
};

export const DIGEST_PATTERNS = {
  approval: /Digest:\s+(0x[a-fA-F0-9]{64})/i,
  authorization: /AuthDigest:\s+(0x[a-fA-F0-9]{64})/i,
  permissions: /PermDigest:\s+(0x[a-fA-F0-9]{64})/i,
  withdrawal: /WithdrawDigest:\s+(0x[a-fA-F0-9]{64})/i,
  whitelist: /WhitelistDigest:\s+(0x[a-fA-F0-9]{64})/i,
  cooldown: /CooldownDigest:\s+(0x[a-fA-F0-9]{64})/i,
  setSpendLimit: /SetSpendLimitDigest:\s+(0x[a-fA-F0-9]{64})/i,
};
