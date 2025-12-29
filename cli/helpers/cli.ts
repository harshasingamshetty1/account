import { existsSync } from "fs";
import path from "path";
import { readJson } from "./file";
import {
  Config,
  ChainConfig,
  DeploymentResults,
  DeployedContracts,
} from "../types";

const DEPLOYED_PATH = path.join(__dirname, "../deployed.json");

export interface CLIArgs {
  chainName: string;
  [key: string]: string | undefined;
}

/**
 * Loads deployment data and config, validates chain exists
 */
export function loadDeploymentData(chainName: string): {
  chain: ChainConfig;
  deployed: DeployedContracts;
} {
  if (!existsSync(DEPLOYED_PATH)) {
    throw new Error("deployed.json is missing, run deploy.ts first.");
  }

  const deployments = readJson<DeploymentResults>("deployed.json");
  const config: Config = readJson<Config>("config.json");

  const chain = config.chains.find((c) => c.name === chainName);
  if (!chain) {
    throw new Error(`Chain '${chainName}' not found in config.json`);
  }

  const deployed = deployments.deployments[chainName];
  if (!deployed) {
    throw new Error(
      `Deployment data for '${chainName}' not found in deployed.json`,
    );
  }

  return { chain, deployed };
}

/**
 * Validates and sanitizes a numeric string (removes commas)
 */
export function sanitizeNumber(value: string, fieldName: string): string {
  const sanitized = value.replace(/,/g, "");
  if (!/^\d+$/.test(sanitized)) {
    throw new Error(
      `Invalid ${fieldName}: ${value}. Must be a number (commas will be removed).`,
    );
  }
  return sanitized;
}

/**
 * Checks if a token address represents native token
 */
export function isNativeToken(token?: string): boolean {
  return (
    !token ||
    token === "0x0" ||
    token === "0x0000000000000000000000000000000000000000"
  );
}

/**
 * Gets the native token address representation
 */
export const NATIVE_TOKEN_ADDRESS =
  "0x0000000000000000000000000000000000000000";
