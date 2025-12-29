import { execSync } from "child_process";

const DEFAULT_FLAGS = "-vvv";
const DEFAULT_BUFFER = 10 * 1024 * 1024;

export interface ForgeScriptOptions {
  scriptPath: string;
  rpc: string;
  env?: NodeJS.ProcessEnv;
  broadcast?: boolean;
  flags?: string;
}

export function runForgeScript({
  scriptPath,
  rpc,
  env,
  broadcast = false,
  flags = DEFAULT_FLAGS,
}: ForgeScriptOptions): string {
  const envVars = { ...process.env, ...(env ?? {}) };
  const segments = [
    "forge script",
    scriptPath,
    "--rpc-url",
    rpc,
    broadcast ? "--broadcast" : "",
    flags,
  ]
    .filter(Boolean)
    .join(" ");

  try {
    const output = execSync(segments, {
      env: envVars,
      encoding: "utf-8",
      stdio: "pipe",
      maxBuffer: DEFAULT_BUFFER,
    });

    if (broadcast && output) {
      process.stdout.write(output);
    }

    if (!output) {
      throw new Error(`${scriptPath} gone, no output.`);
    }

    return output;
  } catch (error: any) {
    const combinedOutput =
      (error.stdout?.toString() || "") + (error.stderr?.toString() || "");

    if (broadcast) {
      process.stdout.write(combinedOutput);
      throw error;
    }

    // TODO: remove this later, i am using this for logs
    // Always return output even on error for digest extraction
    if (combinedOutput) {
      return combinedOutput;
    }

    throw error;
  }
}
