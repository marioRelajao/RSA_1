import express, { NextFunction, Request, Response, response } from 'express'
import logger from 'morgan'  // logger
import cors from 'cors'  // allow us to permit connection from origins that are not our domain. Needed to allow the client (whose javascript is downloaded from another server) to connect 
import { RsaKeyPair, generateRSAKeys } from './rsa/genRSA'
import RsaPubKey from './rsa/RsaPubKey'
import RsaPrivKey from './rsa/RsaPrivKey'
import { split, combine } from 'shamirs-secret-sharing-ts'
import { textToBigint ,bigintToBase64, base64ToBigint, bigintToText, bufToHex, hexToBuf } from 'bigint-conversion'
import { hexToBigint } from 'bigint-crypto-utils'
import e from 'express'


const app = express()
const port = 3000
const crypto = require('crypto');
let testSecret = crypto.randomBytes(64)
let keyPair: RsaKeyPair;
let pubKeyClient: RsaPubKey | null = null
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

//Enviar RSA cuando se nos solicita (✅)
app.get('/getRSA', (req: Request<{}, ResponseMsg, {}, RequestMsg, {}>, res) => {
    if (keyPair) {
      res.status(200).json({
          pubKey: keyPair.publicKey,
        });
      } else {
        res.status(500).json({ error: 'RSA key pair not available' });
      }
})

app.get('/secret', async (req: Request, res: Response) => {
  try {
    const secret = Buffer.from(testSecret)
    console.log(`Valor de Secret: ${bufToHex(secret)}`)
    let slices:Array<string> = await sliceSecret(secret)
    console.log(`Valor de las slices: ${slices}`)
    res.status(200).json({
      clave: bufToHex(secret),
      shares:slices})
  }
  catch(err){
    console.log(err)
    res.status(500).json({message:"Server Error UwU 👉👈"})
  }
})

async function sliceSecret (secret:Uint8Array): Promise<Array<string>>{
  console.log('Slicing usando 10 slices, 4 threshold')
  let buffers = split(secret, { shares: 10, threshold: 4 })
  let slices: Array<string> = []
  buffers.forEach((buffer: any) => slices.push(bufToHex(buffer)))
  return slices
}

//Recibir la PKey de cliente (✅)
app.post('/postRSA', (req:Request, res:Response) => {
  try {
    let e = req.body.e
    let n = req.body.n
    console.log(`Valor de generadores RSA PUBLICA CLIENTE --> e: ${base64ToBigint(e)}\nn: ${base64ToBigint(n)}`)
    pubKeyClient = new RsaPubKey(base64ToBigint(e),base64ToBigint(n))
    console.log(`PubKey de cliente recibida`)
    return res.status(200).json({message:"Clave enviada a server gucci"})
  }
  catch(err){
    console.log(err)
    res.status(500).json({message:"Server Error UwU 👉👈"})
  }
})

//Ciframos el mensaje al cliente (✅)
app.post('/encrypt', (req: Request<{}, CipherMsg, { message: string }, RequestMsg, {}>, res) => {
  if (pubKeyClient && req.body.message) {
    const messageToEncrypt = "El servidor ha cifrado con tu publica el siguiente mensaje:" + req.body.message;
    const encryptedMessage = pubKeyClient.encrypt(textToBigint(messageToEncrypt));
    const encryptedMessageBase64 = bigintToBase64(encryptedMessage);
    res.status(200).json({ 
      ciphertext: encryptedMessageBase64
     });
  } else {
    res.status(500).json({ error: 'RSA key pair not available or message missing' });
  }
});

//Desciframos el mensake del cliente (Falta ver si funciona)
app.post('/decrypt', (req: Request, res: Response) => {
  if (keyPair && req.body) {
    const encryptedMessageBase64 = req.body.encryptedMessage;
    const encryptedMessageBigInt = base64ToBigint(encryptedMessageBase64);
    const privKey = keyPair.privateKey;
    try {
      const decryptedMessageBigInt = privKey.decrypt(encryptedMessageBigInt);
      const decryptedMessage = bigintToText(decryptedMessageBigInt);
      console.log(`Decrypted message from client: ${decryptedMessage}`)
      res.status(200).json({ message: "Todo OK mi pana" });
    } catch (error) {
      console.error('Error al descifrar el mensaje:', error);
      res.status(500).json({ error: 'Error al descifrar el mensaje' });
    }
  } else {
    res.status(500).json({ error: 'RSA key pair not available or encrypted message missing' });
  }
});

app.post('/recover', async (req: Request, res: Response) => {
  try {
    const elements: string[] = req.body.shares;
    const recoveredSecret = await recoverSecret(elements);
    res.status(200).json({
      recoveredSecret: bufToHex(recoveredSecret),
    });
  } catch (error) {
    console.error('Error recovering secret:', error);
    res.status(500).json({ error: 'Error recovering secret' });
  }
});

async function recoverSecret(elements: string[] | null | undefined): Promise<Uint8Array> {
  //console.log(elements)
  if (elements == null) {
    throw new Error('Array of elements is null or undefined.');
  }
  const buffers = elements.map((element) => {
    if (element == null) {
      throw new Error('Hex string in the array is null or undefined.');
    }
    return hexToBuf(element);
  });
  console.log(buffers);
  const recoveredSecret = combine(buffers);
  return recoveredSecret;
}

//Firmamos el mensaje que nos envie el cliente (✅)
app.post('/sign', (req: Request, res: Response) => {
  if (keyPair && req.body) {
    try {
      const msgToSign = req.body.message;
      console.log(`Message to sign: ${msgToSign}`)
      const signed = keyPair.privateKey.sign(textToBigint(msgToSign))
      const sign64 = bigintToBase64(signed)
      res.status(200).json({ 
        msgFirmado: sign64})
    } catch (error) {
      console.error('Error al firmar el mensaje:', error);
      res.status(500).json({ error: 'Error al firmar el mensaje' });
    }
  } else {
    res.status(500).json({ error: 'RSA key pair not available or encrypted message missing' });
  }
});

app.listen(port, () => {
  console.log(`Example app listening at http://localhost:${port}`);
  initializeRSAKeyPair();
})