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
  overrides: Record<string, string | undefined> = {},
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
  extra: Record<string, string | undefined> = {},
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
  context: string,
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
    }`,
  );
  return null;
}

export enum SignerType {
  EOA = "eoa",
  HARDWARE = "hardware",
}

function getPrivateKey(): string {
  const privateKey = process.env.SIGNER_PRIVATE_KEY?.trim();
  if (!privateKey || privateKey === "") {
    throw new Error("SIGNER_PRIVATE_KEY not set or empty");
  }
  if (!privateKey.startsWith("0x")) {
    throw new Error("SIGNER_PRIVATE_KEY must start with 0x prefix");
  }
  return privateKey;
}

export function getSignerType(): SignerType {
  const type = process.env.SIGNER_TYPE?.toLowerCase();
  const hasKey = !!process.env.SIGNER_PRIVATE_KEY?.trim();

  if (type === "eoa") {
    if (!hasKey) {
      throw new Error("SIGNER_TYPE=eoa requires SIGNER_PRIVATE_KEY");
    }
    return SignerType.EOA;
  }

  if (type === "hardware") {
    return SignerType.HARDWARE;
  }

  return hasKey ? SignerType.EOA : SignerType.HARDWARE;
}

function signWithEOA(digest: string): string {
  const privateKey = getPrivateKey();
  const signatureOutput = execSync(
    `cast wallet sign --private-key ${privateKey} ${digest}`,
    {
      encoding: "utf-8",
      stdio: "pipe",
    },
  )
    .toString()
    .trim();

  if (!signatureOutput.startsWith("0x")) {
    throw new Error("EOA signing did not return a valid signature");
  }

  return signatureOutput;
}

function signWithLedger(digest: string): string {
  const signatureOutput = execSync(`cast wallet sign --ledger ${digest}`, {
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

function signDigest(digest: string, signerType: SignerType): string {
  return signerType === SignerType.EOA
    ? signWithEOA(digest)
    : signWithLedger(digest);
}

export function ensureSignature(
  key: string,
  digest: string,
  label: string,
  context: string,
): string {
  if (process.env[key]) {
    return process.env[key]!;
  }

  const signerType = getSignerType();
  const signature = signDigest(digest, signerType);
  process.env[key] = signature;
  console.log(
    `[${context}] ${label} signature captured (${signerType.toUpperCase()})`,
  );
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
    options.context,
  );

  if (!digest) {
    return null;
  }

  return ensureSignature(
    options.signatureKey,
    digest,
    options.label,
    options.context,
  );
}

/**
 * executing a script with signature collection and broadcasting
 */
export interface ExecuteWithSignatureOptions {
  scriptPath: string;
  rpc: string;
  baseEnv: NodeJS.ProcessEnv;
  digestPattern: RegExp;
  digestLabel: string;
  signatureKey?: string;
  context: string;
  successMessage?: string;
}

export function executeWithSignature(
  options: ExecuteWithSignatureOptions,
): void {
  const signatureKey = options.signatureKey || "SIGNATURE";
     // Signature should already be collected before calling this
  const signature = process.env[signatureKey];

  if (!signature) {
    throw new Error(
      `[${options.context}] ${options.digestLabel} signature missing`,
    );
  }

  try {
    runForgeScript({
      scriptPath: options.scriptPath,
      rpc: options.rpc,
      env: createEnv({ ...options.baseEnv, [signatureKey]: signature }),
      broadcast: true,
    });

    if (options.successMessage) {
      console.log(`[${options.context}] ${options.successMessage}`);
    }
  } finally {
    delete process.env[signatureKey];
  }
}
