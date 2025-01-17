// Copyright 2019-2022 @polkadot/wasm authors & contributors
// SPDX-License-Identifier: Apache-2.0

const fflate = require('fflate/node');
const fs = require('fs');
const mkdirp = require('mkdirp');
const { formatNumber } = require('@polkadot/util');

const DIR_DENO = `./${process.env.PKG_NAME}-wasm/build-deno/deno`;
const DIR_CJS = `./${process.env.PKG_NAME}-wasm/build/cjs`;
const HDR = `// Copyright 2019-${new Date().getFullYear()} @polkadot/${process.env.PKG_NAME}-wasm authors & contributors\n// SPDX-License-Identifier: Apache-2.0\n\n// Generated as part of the build, do not edit\n`;

const data = fs.readFileSync(`./${process.env.PKG_NAME}/build-wasm/wasm_opt.wasm`);
const compressed = Buffer.from(fflate.zlibSync(data, { level: 9 }));
const base64 = compressed.toString('base64');

console.log(`*** Compressed WASM: in=${formatNumber(data.length)}, out=${formatNumber(compressed.length)}, opt=${(100 * compressed.length / data.length).toFixed(2)}%, base64=${formatNumber(base64.length)}`);

mkdirp.sync(DIR_DENO);

fs.writeFileSync(`${DIR_CJS}/bytes.js`, `${HDR}
const lenIn = ${compressed.length};
const lenOut = ${data.length};
const bytes = '${base64}';

module.exports = { bytes, lenIn, lenOut };
`);

fs.writeFileSync(`${DIR_DENO}/bytes.js`, `${HDR}
export const lenIn = ${compressed.length};

export const lenOut = ${data.length};

export const bytes = '${base64}';
`);
