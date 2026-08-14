import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import loadZigStark from '../index.mjs';

const wasm = readFileSync(fileURLToPath(new URL('../zig_stark_capi.wasm', import.meta.url)));
const zs = await loadZigStark(wasm);
console.log('version:', zs.version());

const k = 3;
const n = 1 << k;

// Statement: the single witness column is boolean, i.e. w + w^2 = 0 everywhere.
const column = new Uint8Array(n);
for (let i = 0; i < n; i++) column[i] = (i * 3 + 1) % 2;
const constraints = [{ terms: [
  { coeff: 1, factors: [0] },
  { coeff: 1, factors: [0, 0] },
] }];

const { proof, roots } = zs.proveColumns({ k, columns: [column], constraints });
console.log('proof bytes:', proof.length, '| roots:', roots.length);

const ok = zs.verify({ k, roots, constraints, proof });
console.log('verify accepted:', ok);
if (!ok) process.exit(1);

proof[Math.floor(proof.length / 2)] ^= 1;
const okTampered = zs.verify({ k, roots, constraints, proof });
console.log('verify rejected tampered proof:', !okTampered);
if (okTampered) process.exit(1);

console.log('smoke OK');
