import * as bcu from 'bigint-crypto-utils'

class RsaPrivKey {
  d: bigint;
  n: bigint;

  constructor(d: bigint, n: bigint) {
    this.d = d;
    this.n = n;
  }

  decrypt(c: bigint): bigint {
    // m = c^d mod n
    return bcu.modPow(c, this.d, this.n);
  }

  sign(m: bigint): bigint {
    // s = m^d mod n
    return bcu.modPow(m, this.d, this.n);
  }
}

export default RsaPrivKey;