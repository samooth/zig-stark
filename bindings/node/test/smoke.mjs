import { createRequire } from 'node:module';
import { encodeColumns, encodeConstraints, encodePins } from '../../js/index.mjs';

const require = createRequire(import.meta.url);
const addon = require('../../../zig-out/lib/addon.node');

const k = 3;
const n = 1 << k;

// Statement: the single witness column is boolean, i.e. w + w^2 = 0 everywhere.
const column = new Uint8Array(n);
for (let i = 0; i < n; i++) column[i] = (i * 3 + 1) % 2;
const constraints = [{ terms: [
  { coeff: 1, factors: [0] },
  { coeff: 1, factors: [0, 0] },
] }];

const cols = encodeColumns([column]);
const cons = encodeConstraints(constraints);
const pins = encodePins([]);

const { proof, roots } = addon.proveColumns(k, cols, cons, pins, '');
console.log('proof bytes:', proof.length, '| roots:', (roots.length - 8) / 32);

const ok = addon.verify(k, roots, cons, pins, proof, '');
console.log('verify accepted:', ok);
if (!ok) process.exit(1);

proof[Math.floor(proof.length / 2)] ^= 1;
const okTampered = addon.verify(k, roots, cons, pins, proof, '');
console.log('verify rejected tampered proof:', !okTampered);
if (okTampered) process.exit(1);

console.log('addon smoke OK');
