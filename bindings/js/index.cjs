// CommonJS entry: resolves to the ESM module's namespace (promise). Use as
// `const { loadZigStark } = await require('zig-stark');`
module.exports = import('./index.mjs');
