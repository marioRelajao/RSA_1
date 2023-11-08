import RsaPubKey from './RsaPubKey';
import RsaPrivKey from './RsaPrivKey';
import * as bcu from 'bigint-crypto-utils'

export interface RsaKeyPair {
  publicKey: RsaPubKey
  privateKey: RsaPrivKey
}
export async function generateRSAKeys(bitLength: number): Promise<RsaKeyPair> {
  let p: bigint, q: bigint, n: bigint, phin: bigint
  const e: bigint = 65537n
  // if p and q are bitLength/2 long ->  2**(bitLength - 2) <= n < 2**(bitLength)
  do {
    p = await bcu.prime(Math.floor(bitLength / 2) + 1)
    q = await bcu.prime(Math.floor(bitLength / 2))
    n = p * q
    phin = (p - 1n) * (q - 1n)
  } while (q === p || bcu.bitLength(n) !== bitLength || bcu.gcd(e, phin) !== 1n)

  const d: bigint = bcu.modInv(e, phin)

  const rsaPubKey = new RsaPubKey(e, n);
  const rsaPrivKey = new RsaPrivKey(d, n);

  console.log('Clave pública:');
  console.log(rsaPubKey);

  console.log('\nClave privada:');
  console.log(rsaPrivKey);

  return {
    publicKey: rsaPubKey,
    privateKey: rsaPrivKey
  }
}