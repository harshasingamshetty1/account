import { execSync } from "child_process";
import { runForgeScript } from "../helpers";
import { DeployedContracts } from "../types";

export function requireEnv(key: string): string {
  const value = process.env[key];
  if (!value) {
    throw new Error(`${key} gone, also need it to be in 0x prefix`);
  }
  return value;
}

export const createEnv = (
  overrides: Record<string, string | undefined> = {}
) => {
  const env: NodeJS.ProcessEnv = { ...process.env };
  for (const [key, value] of Object.entries(overrides)) {
    if (value === undefined) {
      delete env[key];
    } else {
      env[key] = value;
    }
  }
  return env;
};

export function buildBaseEnv(
  deployed: DeployedContracts,
  htlcs: string[],
  hardwareSigner: string,
  deployerKey: string,
  extra: Record<string, string | undefined> = {}
): NodeJS.ProcessEnv {
  return createEnv({
    GARDEN_SOLVER: deployed.gardenSolver,
    HTLC_ADDRESSES: htlcs.join(","),
    SIGNER_ADDRESS: hardwareSigner,
    SIGNER_ONE_ADDRESS: hardwareSigner,
    MULTISIG_SIGNER: deployed.multiSigSigner,
    MULTISIG_KEY_HASH: deployed.multisigKeyHash,
    DEPLOYER_PRIVATE_KEY: deployerKey,
    ...extra,
  });
}

export function extractDigest(
  output: string,
  pattern: RegExp,
  label: string,
  context: string
): string | null {
  const match = output.match(pattern);
  if (match) {
    return match[1];
  }

  const snippet = output
    .split("\n")
    .filter((line) => line.toLowerCase().includes(label.toLowerCase()))
    .slice(0, 4)
    .join("\n");

  console.warn(
    `[${context}] Unable to parse ${label} digest.${
      snippet ? ` Snippet:\n${snippet}` : ""
    }`
  );
  return null;
}

export function signDigest(message: string): string {
  const signatureOutput = execSync(`cast wallet sign --ledger ${message}`, {
    encoding: "utf-8",
    stdio: "pipe",
  })
    .toString()
    .trim();

  if (!signatureOutput.startsWith("0x")) {
    throw new Error("Ledger did not return a valid signature");
  }

  return signatureOutput;
}

export function ensureSignature(
  key: string,
  digest: string,
  label: string,
  context: string
): string {
  if (process.env[key]) {
    return process.env[key]!;
  }
  const signature = signDigest(digest);
  process.env[key] = signature;
  console.log(`[${context}] ${label} signature captured.`);
  return signature;
}

export interface SignatureOptions {
  scriptPath: string;
  rpc: string;
  envOverrides: Record<string, string | undefined>;
  digestPattern: RegExp;
  label: string;
  signatureKey: string;
  context: string;
}

export async function collectSignature(options: SignatureOptions) {
  if (process.env[options.signatureKey]) {
    return process.env[options.signatureKey]!;
  }

  const env = createEnv({
    ...options.envOverrides,
    [options.signatureKey]: undefined,
  });

  const output = runForgeScript({
    scriptPath: options.scriptPath,
    rpc: options.rpc,
    env,
  });

  const digest = extractDigest(
    output,
    options.digestPattern,
    options.label,
    options.context
  );

  if (!digest) {
    return null;
  }

  return ensureSignature(
    options.signatureKey,
    digest,
    options.label,
    options.context
  );
}
