(function (global, factory) {
  typeof exports === 'object' && typeof module !== 'undefined' ? factory(exports, require('@polkadot/util')) :
  typeof define === 'function' && define.amd ? define(['exports', '@polkadot/util'], factory) :
  (global = typeof globalThis !== 'undefined' ? globalThis : global || self, factory(global.polkadotWasmCrypto = {}, global.polkadotUtil));
})(this, (function (exports, util) { 'use strict';

  const global = typeof globalThis !== "undefined" ? globalThis : typeof self !== "undefined" ? self : window;

  function evaluateThis(fn) {
    return fn('return this');
  }
  const xglobal = typeof globalThis !== 'undefined' ? globalThis : typeof global !== 'undefined' ? global : typeof self !== 'undefined' ? self : typeof window !== 'undefined' ? window : evaluateThis(Function);

  function getRandomValues(arr) {
    return xglobal.crypto.getRandomValues(arr);
  }

  const DEFAULT_CRYPTO = {
    getRandomValues
  };
  const DEFAULT_SELF = {
    crypto: DEFAULT_CRYPTO
  };
  class Wbg {
    #bridge;
    constructor(bridge) {
      this.#bridge = bridge;
    }
    abort = () => {
      throw new Error('abort');
    };
    __wbindgen_is_undefined = idx => {
      return this.#bridge.getObject(idx) === undefined;
    };
    __wbindgen_throw = (ptr, len) => {
      throw new Error(this.#bridge.getString(ptr, len));
    };
    __wbg_self_1b7a39e3a92c949c = () => {
      return this.#bridge.addObject(DEFAULT_SELF);
    };
    __wbg_require_604837428532a733 = (ptr, len) => {
      throw new Error(`Unable to require ${this.#bridge.getString(ptr, len)}`);
    };
    __wbg_crypto_968f1772287e2df0 = _idx => {
      return this.#bridge.addObject(DEFAULT_CRYPTO);
    };
    __wbg_getRandomValues_a3d34b4fee3c2869 = _idx => {
      return this.#bridge.addObject(DEFAULT_CRYPTO.getRandomValues);
    };
    __wbg_getRandomValues_f5e14ab7ac8e995d = (_arg0, ptr, len) => {
      DEFAULT_CRYPTO.getRandomValues(this.#bridge.getU8a(ptr, len));
    };
    __wbg_randomFillSync_d5bd2d655fdf256a = (_idx, _ptr, _len) => {
      throw new Error('randomFillsync is not available');
    };
    __wbindgen_object_drop_ref = idx => {
      this.#bridge.takeObject(idx);
    };
  }

  class Bridge {
    #cachegetInt32;
    #cachegetUint8;
    #createWasm;
    #heap;
    #heapNext;
    #wasm;
    #wasmError;
    #wasmPromise;
    #wbg;
    #type;
    constructor(createWasm) {
      this.#createWasm = createWasm;
      this.#cachegetInt32 = null;
      this.#cachegetUint8 = null;
      this.#heap = new Array(32).fill(undefined).concat(undefined, null, true, false);
      this.#heapNext = this.#heap.length;
      this.#type = 'none';
      this.#wasm = null;
      this.#wasmError = null;
      this.#wasmPromise = null;
      this.#wbg = {
        ...new Wbg(this)
      };
    }
    get error() {
      return this.#wasmError;
    }
    get type() {
      return this.#type;
    }
    get wasm() {
      return this.#wasm;
    }
    async init(createWasm) {
      if (!this.#wasmPromise || createWasm) {
        this.#wasmPromise = (createWasm || this.#createWasm)(this.#wbg);
      }
      const {
        error,
        type,
        wasm
      } = await this.#wasmPromise;
      this.#type = type;
      this.#wasm = wasm;
      this.#wasmError = error;
      return this.#wasm;
    }
    getObject(idx) {
      return this.#heap[idx];
    }
    dropObject(idx) {
      if (idx < 36) {
        return;
      }
      this.#heap[idx] = this.#heapNext;
      this.#heapNext = idx;
    }
    takeObject(idx) {
      const ret = this.getObject(idx);
      this.dropObject(idx);
      return ret;
    }
    addObject(obj) {
      if (this.#heapNext === this.#heap.length) {
        this.#heap.push(this.#heap.length + 1);
      }
      const idx = this.#heapNext;
      this.#heapNext = this.#heap[idx];
      this.#heap[idx] = obj;
      return idx;
    }
    getInt32() {
      if (this.#cachegetInt32 === null || this.#cachegetInt32.buffer !== this.#wasm.memory.buffer) {
        this.#cachegetInt32 = new Int32Array(this.#wasm.memory.buffer);
      }
      return this.#cachegetInt32;
    }
    getUint8() {
      if (this.#cachegetUint8 === null || this.#cachegetUint8.buffer !== this.#wasm.memory.buffer) {
        this.#cachegetUint8 = new Uint8Array(this.#wasm.memory.buffer);
      }
      return this.#cachegetUint8;
    }
    getU8a(ptr, len) {
      return this.getUint8().subarray(ptr / 1, ptr / 1 + len);
    }
    getString(ptr, len) {
      return util.u8aToString(this.getU8a(ptr, len));
    }
    allocU8a(arg) {
      const ptr = this.#wasm.__wbindgen_malloc(arg.length * 1);
      this.getUint8().set(arg, ptr / 1);
      return [ptr, arg.length];
    }
    allocString(arg) {
      return this.allocU8a(util.stringToU8a(arg));
    }
    resultU8a() {
      const r0 = this.getInt32()[8 / 4 + 0];
      const r1 = this.getInt32()[8 / 4 + 1];
      const ret = this.getU8a(r0, r1).slice();
      this.#wasm.__wbindgen_free(r0, r1 * 1);
      return ret;
    }
    resultString() {
      return util.u8aToString(this.resultU8a());
    }
  }

  function createWasmFn(root, wasmBytes, asmFn) {
    return async wbg => {
      const result = {
        error: null,
        type: 'none',
        wasm: null
      };
      try {
        if (!wasmBytes || !wasmBytes.length) {
          throw new Error('No WebAssembly provided for initialization');
        } else if (typeof WebAssembly !== 'object' || typeof WebAssembly.instantiate !== 'function') {
          throw new Error('WebAssembly is not available in your environment');
        }
        const source = await WebAssembly.instantiate(wasmBytes, {
          wbg
        });
        result.wasm = source.instance.exports;
        result.type = 'wasm';
      } catch (error) {
        if (typeof asmFn === 'function') {
          result.wasm = asmFn(wbg);
          result.type = 'asm';
        } else {
          result.error = `FATAL: Unable to initialize @polkadot/wasm-${root}:: ${error.message}`;
          console.error(result.error);
        }
      }
      return result;
    };
  }

  const chr = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';
  const map = new Array(256);
  for (let i = 0; i < chr.length; i++) {
    map[chr.charCodeAt(i)] = i;
  }
  function base64Decode(data, out) {
    const len = out.length;
    let byte = 0;
    let bits = 0;
    let pos = -1;
    for (let i = 0; pos < len; i++) {
      byte = byte << 6 | map[data.charCodeAt(i)];
      if ((bits += 6) >= 8) {
        out[++pos] = byte >>> (bits -= 8) & 0xff;
      }
    }
    return out;
  }

  const u8 = Uint8Array,
    u16 = Uint16Array,
    u32 = Uint32Array;
  const clim = new u8([16, 17, 18, 0, 8, 7, 9, 6, 10, 5, 11, 4, 12, 3, 13, 2, 14, 1, 15]);
  const fleb = new u8([0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 2, 2, 2, 2, 3, 3, 3, 3, 4, 4, 4, 4, 5, 5, 5, 5, 0, 0, 0, 0]);
  const fdeb = new u8([0, 0, 0, 0, 1, 1, 2, 2, 3, 3, 4, 4, 5, 5, 6, 6, 7, 7, 8, 8, 9, 9, 10, 10, 11, 11, 12, 12, 13, 13, 0, 0]);
  const freb = (eb, start) => {
    const b = new u16(31);
    for (let i = 0; i < 31; ++i) {
      b[i] = start += 1 << eb[i - 1];
    }
    const r = new u32(b[30]);
    for (let i = 1; i < 30; ++i) {
      for (let j = b[i]; j < b[i + 1]; ++j) {
        r[j] = j - b[i] << 5 | i;
      }
    }
    return [b, r];
  };
  const [fl, revfl] = freb(fleb, 2);
  fl[28] = 258, revfl[258] = 28;
  const [fd] = freb(fdeb, 0);
  const rev = new u16(32768);
  for (let i = 0; i < 32768; ++i) {
    let x = (i & 0xAAAA) >>> 1 | (i & 0x5555) << 1;
    x = (x & 0xCCCC) >>> 2 | (x & 0x3333) << 2;
    x = (x & 0xF0F0) >>> 4 | (x & 0x0F0F) << 4;
    rev[i] = ((x & 0xFF00) >>> 8 | (x & 0x00FF) << 8) >>> 1;
  }
  const hMap = (cd, mb, r) => {
    const s = cd.length;
    let i = 0;
    const l = new u16(mb);
    for (; i < s; ++i) ++l[cd[i] - 1];
    const le = new u16(mb);
    for (i = 0; i < mb; ++i) {
      le[i] = le[i - 1] + l[i - 1] << 1;
    }
    let co;
    if (r) {
      co = new u16(1 << mb);
      const rvb = 15 - mb;
      for (i = 0; i < s; ++i) {
        if (cd[i]) {
          const sv = i << 4 | cd[i];
          const r = mb - cd[i];
          let v = le[cd[i] - 1]++ << r;
          for (const m = v | (1 << r) - 1; v <= m; ++v) {
            co[rev[v] >>> rvb] = sv;
          }
        }
      }
    } else {
      co = new u16(s);
      for (i = 0; i < s; ++i) co[i] = rev[le[cd[i] - 1]++] >>> 15 - cd[i];
    }
    return co;
  };
  const flt = new u8(288);
  for (let i = 0; i < 144; ++i) flt[i] = 8;
  for (let i = 144; i < 256; ++i) flt[i] = 9;
  for (let i = 256; i < 280; ++i) flt[i] = 7;
  for (let i = 280; i < 288; ++i) flt[i] = 8;
  const fdt = new u8(32);
  for (let i = 0; i < 32; ++i) fdt[i] = 5;
  const flrm = hMap(flt, 9, 1);
  const fdrm = hMap(fdt, 5, 1);
  const bits = (d, p, m) => {
    const o = p >>> 3;
    return (d[o] | d[o + 1] << 8) >>> (p & 7) & m;
  };
  const bits16 = (d, p) => {
    const o = p >>> 3;
    return (d[o] | d[o + 1] << 8 | d[o + 2] << 16) >>> (p & 7);
  };
  const shft = p => (p >>> 3) + (p & 7 && 1);
  const slc = (v, s, e) => {
    if (s == null || s < 0) s = 0;
    if (e == null || e > v.length) e = v.length;
    const n = new (v instanceof u16 ? u16 : v instanceof u32 ? u32 : u8)(e - s);
    n.set(v.subarray(s, e));
    return n;
  };
  const max = a => {
    let m = a[0];
    for (let i = 1; i < a.length; ++i) {
      if (a[i] > m) m = a[i];
    }
    return m;
  };
  const inflt = (dat, buf, st) => {
    const noSt = !st || st.i;
    if (!st) st = {};
    const sl = dat.length;
    const noBuf = !buf || !noSt;
    if (!buf) buf = new u8(sl * 3);
    const cbuf = l => {
      let bl = buf.length;
      if (l > bl) {
        const nbuf = new u8(Math.max(bl << 1, l));
        nbuf.set(buf);
        buf = nbuf;
      }
    };
    let final = st.f || 0,
      pos = st.p || 0,
      bt = st.b || 0,
      lm = st.l,
      dm = st.d,
      lbt = st.m,
      dbt = st.n;
    if (final && !lm) return buf;
    const tbts = sl << 3;
    do {
      if (!lm) {
        st.f = final = bits(dat, pos, 1);
        const type = bits(dat, pos + 1, 3);
        pos += 3;
        if (!type) {
          const s = shft(pos) + 4,
            l = dat[s - 4] | dat[s - 3] << 8,
            t = s + l;
          if (t > sl) {
            if (noSt) throw 'unexpected EOF';
            break;
          }
          if (noBuf) cbuf(bt + l);
          buf.set(dat.subarray(s, t), bt);
          st.b = bt += l, st.p = pos = t << 3;
          continue;
        } else if (type == 1) lm = flrm, dm = fdrm, lbt = 9, dbt = 5;else if (type == 2) {
          const hLit = bits(dat, pos, 31) + 257,
            hcLen = bits(dat, pos + 10, 15) + 4;
          const tl = hLit + bits(dat, pos + 5, 31) + 1;
          pos += 14;
          const ldt = new u8(tl);
          const clt = new u8(19);
          for (let i = 0; i < hcLen; ++i) {
            clt[clim[i]] = bits(dat, pos + i * 3, 7);
          }
          pos += hcLen * 3;
          const clb = max(clt),
            clbmsk = (1 << clb) - 1;
          if (!noSt && pos + tl * (clb + 7) > tbts) break;
          const clm = hMap(clt, clb, 1);
          for (let i = 0; i < tl;) {
            const r = clm[bits(dat, pos, clbmsk)];
            pos += r & 15;
            const s = r >>> 4;
            if (s < 16) {
              ldt[i++] = s;
            } else {
              let c = 0,
                n = 0;
              if (s == 16) n = 3 + bits(dat, pos, 3), pos += 2, c = ldt[i - 1];else if (s == 17) n = 3 + bits(dat, pos, 7), pos += 3;else if (s == 18) n = 11 + bits(dat, pos, 127), pos += 7;
              while (n--) ldt[i++] = c;
            }
          }
          const lt = ldt.subarray(0, hLit),
            dt = ldt.subarray(hLit);
          lbt = max(lt);
          dbt = max(dt);
          lm = hMap(lt, lbt, 1);
          dm = hMap(dt, dbt, 1);
        } else throw 'invalid block type';
        if (pos > tbts) throw 'unexpected EOF';
      }
      if (noBuf) cbuf(bt + 131072);
      const lms = (1 << lbt) - 1,
        dms = (1 << dbt) - 1;
      const mxa = lbt + dbt + 18;
      while (noSt || pos + mxa < tbts) {
        const c = lm[bits16(dat, pos) & lms],
          sym = c >>> 4;
        pos += c & 15;
        if (pos > tbts) throw 'unexpected EOF';
        if (!c) throw 'invalid length/literal';
        if (sym < 256) buf[bt++] = sym;else if (sym == 256) {
          lm = undefined;
          break;
        } else {
          let add = sym - 254;
          if (sym > 264) {
            const i = sym - 257,
              b = fleb[i];
            add = bits(dat, pos, (1 << b) - 1) + fl[i];
            pos += b;
          }
          const d = dm[bits16(dat, pos) & dms],
            dsym = d >>> 4;
          if (!d) throw 'invalid distance';
          pos += d & 15;
          let dt = fd[dsym];
          if (dsym > 3) {
            const b = fdeb[dsym];
            dt += bits16(dat, pos) & (1 << b) - 1, pos += b;
          }
          if (pos > tbts) throw 'unexpected EOF';
          if (noBuf) cbuf(bt + 131072);
          const end = bt + add;
          for (; bt < end; bt += 4) {
            buf[bt] = buf[bt - dt];
            buf[bt + 1] = buf[bt + 1 - dt];
            buf[bt + 2] = buf[bt + 2 - dt];
            buf[bt + 3] = buf[bt + 3 - dt];
          }
          bt = end;
        }
      }
      st.l = lm, st.p = pos, st.b = bt;
      if (lm) final = 1, st.m = lbt, st.d = dm, st.n = dbt;
    } while (!final);
    return bt == buf.length ? buf : slc(buf, 0, bt);
  };
  const zlv = d => {
    if ((d[0] & 15) != 8 || d[0] >>> 4 > 7 || (d[0] << 8 | d[1]) % 31) throw 'invalid zlib data';
    if (d[1] & 32) throw 'invalid zlib data: preset dictionaries not supported';
  };
  function unzlibSync(data, out) {
    return inflt((zlv(data), data.subarray(2, -4)), out);
  }

  const lenIn = 1293575;
  const lenOut = 1475624;
  var bytes_1 = { bytes, lenIn, lenOut };

  const wasmBytes = unzlibSync(base64Decode(bytes_1.bytes, new Uint8Array(bytes_1.lenIn)), new Uint8Array(bytes_1.lenOut));

  const createWasm = createWasmFn('crypto', wasmBytes, null);

  const bridge = new Bridge(createWasm);
  async function initBridge(createWasm) {
    return bridge.init(createWasm);
  }

  const packageInfo = {
    name: '@polkadot/wasm-crypto',
    path: (({ url: (typeof document === 'undefined' && typeof location === 'undefined' ? new (require('u' + 'rl').URL)('file:' + __filename).href : typeof document === 'undefined' ? location.href : (document.currentScript && document.currentScript.src || new URL('bundle-polkadot-wasm-crypto.js', document.baseURI).href)) }) && (typeof document === 'undefined' && typeof location === 'undefined' ? new (require('u' + 'rl').URL)('file:' + __filename).href : typeof document === 'undefined' ? location.href : (document.currentScript && document.currentScript.src || new URL('bundle-polkadot-wasm-crypto.js', document.baseURI).href))) ? new URL((typeof document === 'undefined' && typeof location === 'undefined' ? new (require('u' + 'rl').URL)('file:' + __filename).href : typeof document === 'undefined' ? location.href : (document.currentScript && document.currentScript.src || new URL('bundle-polkadot-wasm-crypto.js', document.baseURI).href))).pathname.substring(0, new URL((typeof document === 'undefined' && typeof location === 'undefined' ? new (require('u' + 'rl').URL)('file:' + __filename).href : typeof document === 'undefined' ? location.href : (document.currentScript && document.currentScript.src || new URL('bundle-polkadot-wasm-crypto.js', document.baseURI).href))).pathname.lastIndexOf('/') + 1) : 'auto',
    type: 'esm',
    version: '6.3.2-36-x'
  };

  function withWasm(fn) {
    return (...params) => {
      if (!bridge.wasm) {
        throw new Error('The WASM interface has not been initialized. Ensure that you wait for the initialization Promise with waitReady() from @polkadot/wasm-crypto (or cryptoWaitReady() from @polkadot/util-crypto) before attempting to use WASM-only interfaces.');
      }
      return fn(bridge.wasm, ...params);
    };
  }
  const bip39Generate = withWasm((wasm, words) => {
    wasm.ext_bip39_generate(8, words);
    return bridge.resultString();
  });
  const bip39ToEntropy = withWasm((wasm, phrase) => {
    wasm.ext_bip39_to_entropy(8, ...bridge.allocString(phrase));
    return bridge.resultU8a();
  });
  const bip39ToMiniSecret = withWasm((wasm, phrase, password) => {
    wasm.ext_bip39_to_mini_secret(8, ...bridge.allocString(phrase), ...bridge.allocString(password));
    return bridge.resultU8a();
  });
  const bip39ToSeed = withWasm((wasm, phrase, password) => {
    wasm.ext_bip39_to_seed(8, ...bridge.allocString(phrase), ...bridge.allocString(password));
    return bridge.resultU8a();
  });
  const bip39Validate = withWasm((wasm, phrase) => {
    const ret = wasm.ext_bip39_validate(...bridge.allocString(phrase));
    return ret !== 0;
  });
  const ed25519KeypairFromSeed = withWasm((wasm, seed) => {
    wasm.ext_ed_from_seed(8, ...bridge.allocU8a(seed));
    return bridge.resultU8a();
  });
  const ed25519Sign = withWasm((wasm, pubkey, seckey, message) => {
    wasm.ext_ed_sign(8, ...bridge.allocU8a(pubkey), ...bridge.allocU8a(seckey), ...bridge.allocU8a(message));
    return bridge.resultU8a();
  });
  const ed25519Verify = withWasm((wasm, signature, message, pubkey) => {
    const ret = wasm.ext_ed_verify(...bridge.allocU8a(signature), ...bridge.allocU8a(message), ...bridge.allocU8a(pubkey));
    return ret !== 0;
  });
  const dilithium2KeypairFromSeed = withWasm((wasm, seed) => {
    wasm.ext_dilithium_from_seed(8, ...bridge.allocU8a(seed));
    return bridge.resultU8a();
  });
  const dilithium2Sign = withWasm((wasm, pubkey, seed, message) => {
    wasm.ext_dilithium_sign(8, ...bridge.allocU8a(pubkey), ...bridge.allocU8a(seed), ...bridge.allocU8a(message));
    return bridge.resultU8a();
  });
  const dilithium2Verify = withWasm((wasm, signature, message, pubkey) => {
    const ret = wasm.ext_dilithium_verify(...bridge.allocU8a(signature), ...bridge.allocU8a(message), ...bridge.allocU8a(pubkey));
    return ret !== 0;
  });
  const secp256k1FromSeed = withWasm((wasm, seckey) => {
    wasm.ext_secp_from_seed(8, ...bridge.allocU8a(seckey));
    return bridge.resultU8a();
  });
  const secp256k1Compress = withWasm((wasm, pubkey) => {
    wasm.ext_secp_pub_compress(8, ...bridge.allocU8a(pubkey));
    return bridge.resultU8a();
  });
  const secp256k1Expand = withWasm((wasm, pubkey) => {
    wasm.ext_secp_pub_expand(8, ...bridge.allocU8a(pubkey));
    return bridge.resultU8a();
  });
  const secp256k1Recover = withWasm((wasm, msgHash, sig, recovery) => {
    wasm.ext_secp_recover(8, ...bridge.allocU8a(msgHash), ...bridge.allocU8a(sig), recovery);
    return bridge.resultU8a();
  });
  const secp256k1Sign = withWasm((wasm, msgHash, seckey) => {
    wasm.ext_secp_sign(8, ...bridge.allocU8a(msgHash), ...bridge.allocU8a(seckey));
    return bridge.resultU8a();
  });
  const sr25519DeriveKeypairHard = withWasm((wasm, pair, cc) => {
    wasm.ext_sr_derive_keypair_hard(8, ...bridge.allocU8a(pair), ...bridge.allocU8a(cc));
    return bridge.resultU8a();
  });
  const sr25519DeriveKeypairSoft = withWasm((wasm, pair, cc) => {
    wasm.ext_sr_derive_keypair_soft(8, ...bridge.allocU8a(pair), ...bridge.allocU8a(cc));
    return bridge.resultU8a();
  });
  const sr25519DerivePublicSoft = withWasm((wasm, pubkey, cc) => {
    wasm.ext_sr_derive_public_soft(8, ...bridge.allocU8a(pubkey), ...bridge.allocU8a(cc));
    return bridge.resultU8a();
  });
  const sr25519KeypairFromSeed = withWasm((wasm, seed) => {
    wasm.ext_sr_from_seed(8, ...bridge.allocU8a(seed));
    return bridge.resultU8a();
  });
  const sr25519Sign = withWasm((wasm, pubkey, secret, message) => {
    wasm.ext_sr_sign(8, ...bridge.allocU8a(pubkey), ...bridge.allocU8a(secret), ...bridge.allocU8a(message));
    return bridge.resultU8a();
  });
  const sr25519Verify = withWasm((wasm, signature, message, pubkey) => {
    const ret = wasm.ext_sr_verify(...bridge.allocU8a(signature), ...bridge.allocU8a(message), ...bridge.allocU8a(pubkey));
    return ret !== 0;
  });
  const sr25519Agree = withWasm((wasm, pubkey, secret) => {
    wasm.ext_sr_agree(8, ...bridge.allocU8a(pubkey), ...bridge.allocU8a(secret));
    return bridge.resultU8a();
  });
  const vrfSign = withWasm((wasm, secret, context, message, extra) => {
    wasm.ext_vrf_sign(8, ...bridge.allocU8a(secret), ...bridge.allocU8a(context), ...bridge.allocU8a(message), ...bridge.allocU8a(extra));
    return bridge.resultU8a();
  });
  const vrfVerify = withWasm((wasm, pubkey, context, message, extra, outAndProof) => {
    const ret = wasm.ext_vrf_verify(...bridge.allocU8a(pubkey), ...bridge.allocU8a(context), ...bridge.allocU8a(message), ...bridge.allocU8a(extra), ...bridge.allocU8a(outAndProof));
    return ret !== 0;
  });
  const blake2b = withWasm((wasm, data, key, size) => {
    wasm.ext_blake2b(8, ...bridge.allocU8a(data), ...bridge.allocU8a(key), size);
    return bridge.resultU8a();
  });
  const hmacSha256 = withWasm((wasm, key, data) => {
    wasm.ext_hmac_sha256(8, ...bridge.allocU8a(key), ...bridge.allocU8a(data));
    return bridge.resultU8a();
  });
  const hmacSha512 = withWasm((wasm, key, data) => {
    wasm.ext_hmac_sha512(8, ...bridge.allocU8a(key), ...bridge.allocU8a(data));
    return bridge.resultU8a();
  });
  const keccak256 = withWasm((wasm, data) => {
    wasm.ext_keccak256(8, ...bridge.allocU8a(data));
    return bridge.resultU8a();
  });
  const keccak512 = withWasm((wasm, data) => {
    wasm.ext_keccak512(8, ...bridge.allocU8a(data));
    return bridge.resultU8a();
  });
  const pbkdf2 = withWasm((wasm, data, salt, rounds) => {
    wasm.ext_pbkdf2(8, ...bridge.allocU8a(data), ...bridge.allocU8a(salt), rounds);
    return bridge.resultU8a();
  });
  const scrypt = withWasm((wasm, password, salt, log2n, r, p) => {
    wasm.ext_scrypt(8, ...bridge.allocU8a(password), ...bridge.allocU8a(salt), log2n, r, p);
    return bridge.resultU8a();
  });
  const sha256 = withWasm((wasm, data) => {
    wasm.ext_sha256(8, ...bridge.allocU8a(data));
    return bridge.resultU8a();
  });
  const sha512 = withWasm((wasm, data) => {
    wasm.ext_sha512(8, ...bridge.allocU8a(data));
    return bridge.resultU8a();
  });
  const twox = withWasm((wasm, data, rounds) => {
    wasm.ext_twox(8, ...bridge.allocU8a(data), rounds);
    return bridge.resultU8a();
  });
  function isReady() {
    return !!bridge.wasm;
  }
  async function waitReady() {
    try {
      const wasm = await initBridge();
      return !!wasm;
    } catch {
      return false;
    }
  }

  exports.bip39Generate = bip39Generate;
  exports.bip39ToEntropy = bip39ToEntropy;
  exports.bip39ToMiniSecret = bip39ToMiniSecret;
  exports.bip39ToSeed = bip39ToSeed;
  exports.bip39Validate = bip39Validate;
  exports.blake2b = blake2b;
  exports.bridge = bridge;
  exports.dilithium2KeypairFromSeed = dilithium2KeypairFromSeed;
  exports.dilithium2Sign = dilithium2Sign;
  exports.dilithium2Verify = dilithium2Verify;
  exports.ed25519KeypairFromSeed = ed25519KeypairFromSeed;
  exports.ed25519Sign = ed25519Sign;
  exports.ed25519Verify = ed25519Verify;
  exports.hmacSha256 = hmacSha256;
  exports.hmacSha512 = hmacSha512;
  exports.isReady = isReady;
  exports.keccak256 = keccak256;
  exports.keccak512 = keccak512;
  exports.packageInfo = packageInfo;
  exports.pbkdf2 = pbkdf2;
  exports.scrypt = scrypt;
  exports.secp256k1Compress = secp256k1Compress;
  exports.secp256k1Expand = secp256k1Expand;
  exports.secp256k1FromSeed = secp256k1FromSeed;
  exports.secp256k1Recover = secp256k1Recover;
  exports.secp256k1Sign = secp256k1Sign;
  exports.sha256 = sha256;
  exports.sha512 = sha512;
  exports.sr25519Agree = sr25519Agree;
  exports.sr25519DeriveKeypairHard = sr25519DeriveKeypairHard;
  exports.sr25519DeriveKeypairSoft = sr25519DeriveKeypairSoft;
  exports.sr25519DerivePublicSoft = sr25519DerivePublicSoft;
  exports.sr25519KeypairFromSeed = sr25519KeypairFromSeed;
  exports.sr25519Sign = sr25519Sign;
  exports.sr25519Verify = sr25519Verify;
  exports.twox = twox;
  exports.vrfSign = vrfSign;
  exports.vrfVerify = vrfVerify;
  exports.waitReady = waitReady;

}));