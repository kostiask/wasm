// Copyright 2019-2022 @polkadot/wasm-crypto-init authors & contributors
// SPDX-License-Identifier: Apache-2.0

import type { InitFn } from '@polkadot/wasm-bridge/types';
import type { WasmCryptoInstance } from './types';

import { createWasmFn } from '@polkadot/wasm-bridge';

export { packageInfo } from './packageInfo';

/**
 * @name createWasm
 * @description
 * Creates an interface using no WASM and no ASM.js
 */
export const createWasm: InitFn<WasmCryptoInstance> = createWasmFn('crypto', null, null);
