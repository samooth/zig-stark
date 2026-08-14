// Type definitions for the zig-stark Binius zero-check STARK wasm binding.

export interface Term {
  coeff: number;
  factors: number[];
}

export interface Constraint {
  terms: Term[];
}

export interface Pin {
  col: number;
  point: number;
  value: number;
}

export interface ProveInput {
  k: number;
  columns: Uint8Array[];
  constraints: Constraint[];
  pins?: Pin[];
  domain?: string;
}

export interface ProveResult {
  proof: Uint8Array;
  roots: Uint8Array[];
}

export interface VerifyInput {
  k: number;
  roots: Uint8Array[];
  constraints: Constraint[];
  pins?: Pin[];
  proof: Uint8Array;
  domain?: string;
}

export interface ZigStark {
  instance: WebAssembly.Instance;
  version(): string;
  proveColumns(input: ProveInput): ProveResult;
  verify(input: VerifyInput): boolean;
}

export function loadZigStark(wasmBytes: Uint8Array): Promise<ZigStark>;

export const ZS_OK: number;
export const ZS_ERR: { generic: number; invalid: number; oom: number; protocol: number };

export default loadZigStark;
