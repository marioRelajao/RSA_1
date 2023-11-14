import express, { NextFunction, Request, Response } from 'express'
import logger from 'morgan'  // logger
import cors from 'cors'  // allow us to permit connection from origins that are not our domain. Needed to allow the client (whose javascript is downloaded from another server) to connect 
import { RsaKeyPair, generateRSAKeys } from './rsa/genRSA'
import RsaPubKey from './rsa/RsaPubKey'
import RsaPrivKey from './rsa/RsaPrivKey'
import { textToBigint ,bigintToBase64, base64ToBigint, bigintToText } from 'bigint-conversion'


const app = express()
const port = 3000
let keyPair: RsaKeyPair | null = null;
app.use(logger('dev')) // we use the morgan middleware to log some information regarding every request.

app.use(cors({
  origin: (origin, allowFn) => {
    allowFn(null, 'http://localhost:4200') // Our angular client
    //allowFn(null, '<otherOrigin>') // We could add more origins
  }
}))

app.use(express.json()) // let us load the json parser middleware, which will place JSON requests as a json in `req.body`

/**
 * Let us define to type of JSON messages we can receive and send.
 */
interface RequestMsg {
  name?: string // and optional request field
}
interface ResponseMsg {
  pubKey?: RsaPubKey
  error?: string
}
interface CipherMsg {
  ciphertext?: string
  error?: string
}
interface DecryptionResponse {
  decryptedMessage?: string;
  error?: string;
}


async function initializeRSAKeyPair() {
    try {
      keyPair = await generateRSAKeys(1024);
      console.log('RSA key pair generated and saved globally.');
    } catch (error) {
      console.error('Error generating RSA keys:', error);
    }
  }


app.get('/getRSA', (req: Request<{}, ResponseMsg, {}, RequestMsg, {}>, res) => {
    if (keyPair) {
        res.json({
          pubKey: keyPair.publicKey,
        });
      } else {
        res.status(500).json({ error: 'RSA key pair not available' });
      }
})



app.post('/encrypt', (req: Request<{}, CipherMsg, { message: string }, RequestMsg, {}>, res) => {
  if (keyPair && req.body.message) {
    const messageToEncrypt = req.body.message;
    const publicKey = keyPair.publicKey;
    const encryptedMessage = publicKey.encrypt(textToBigint(messageToEncrypt));
    const encryptedMessageBase64 = bigintToBase64(encryptedMessage);
    res.json({ 
      ciphertext: encryptedMessageBase64
     });
  } else {
    res.status(500).json({ error: 'RSA key pair not available or message missing' });
  }
});

app.post('/decrypt', (req: Request<{}, DecryptionResponse, { encryptedMessage: string }, RequestMsg, {}>, res) => {
  if (keyPair && req.body.encryptedMessage) {
    const encryptedMessageBase64 = req.body.encryptedMessage;
    const encryptedMessageBigInt = base64ToBigint(encryptedMessageBase64);
    const privKey = keyPair.privateKey;
    try {
      const decryptedMessageBigInt = privKey.decrypt(encryptedMessageBigInt);
      const decryptedMessage = bigintToText(decryptedMessageBigInt);

      res.json({ decryptedMessage });
    } catch (error) {
      console.error('Error al descifrar el mensaje:', error);
      res.status(500).json({ error: 'Error al descifrar el mensaje' });
    }
  } else {
    res.status(500).json({ error: 'RSA key pair not available or encrypted message missing' });
  }
});


app.listen(port, () => {
  console.log(`Example app listening at http://localhost:${port}`);
  initializeRSAKeyPair();
})