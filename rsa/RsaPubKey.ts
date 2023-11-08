import { base64ToBigint, bigintToBase64} from 'bigint-conversion';
import * as bcu from 'bigint-crypto-utils'

export default class RsaPubKey {
  e: bigint
  n: bigint

  constructor(e: bigint, n: bigint) {
    this.e = e;
    this.n = n;
  }

  encrypt(m: bigint): bigint {
    // C = m^e mod n
    return bcu.modPow(m, this.e, this.n);
  }

  verify(s: bigint): bigint {
    // m = s^e mod n
    return bcu.modPow(s, this.e, this.n);
  }

  toJSON(){
    const pubKeyJson = {
      e: bigintToBase64(this.e),
      n: bigintToBase64(this.n)
    }
    return pubKeyJson
  }
  
  fromJSON(pubKeyJson: { e: string, n: string }){
    return new RsaPubKey(base64ToBigint
     (pubKeyJson.e), base64ToBigint(pubKeyJson.n))
  }

}