import express, { NextFunction, Request, Response } from 'express'
import logger from 'morgan'  // logger
import cors from 'cors'  // allow us to permit connection from origins that are not our domain. Needed to allow the client (whose javascript is downloaded from another server) to connect 
import { RsaKeyPair, generateRSAKeys } from './rsa/genRSA'
import RsaPubKey from './rsa/RsaPubKey'


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

/**
 * Now we add the types and then TypeScript will infer the JSON.
 * A request is typed as Request<ParamsDictionary, ResBody, ReqBody, ReqQuery, Locals>
 * We will not use neither ParamsDictionary nor Locals (we will ignore them by setting the type to {}); for us the important ones are:
 *  - ResBody. The interface of our JSON response body. In our case it will be ResponseMsg
 *  - ReqQuery. The interface of the received query parametrs. Using RequestMsg would allow the case of http://localhost:3000/hello?name=Alice or just http://localhost:3000/hello, since `name` is an optional field.
 *  - ReqBody. The interface of the request body in an HTTP POST or PUT.
 */

async function initializeRSAKeyPair() {
    try {
      keyPair = await generateRSAKeys(1024);
      console.log('RSA key pair generated and saved globally.');
    } catch (error) {
      console.error('Error generating RSA keys:', error);
    }
  }

// app.get('/hello', (req: Request<{}, ResponseMsg, {}, RequestMsg, {}>, res) => {
//   res.send({
//     msg: 'Hello ' + (req.query.name ??'anonymous')
//   })
// })
app.get('/UwU', (req: Request<{}, ResponseMsg, {}, RequestMsg, {}>, res) => {
    if (keyPair) {
        res.json({
          pubKey: keyPair.publicKey,
        });
      } else {
        res.status(500).json({ error: 'RSA key pair not available' });
      }
})

// app.post('/hello', (req: Request<{}, ResponseMsg, RequestMsg, {}, {}>, res) => {
//   res.send({
//     msg: 'Hello ' + (req.body.name ??'anonymous')
//   })
// })


// This is our error middleware. If there is any error server side, we log it (server-side), and we answer with empty message and an error messgae 
// app.use((err: Error, req: Request, res: Response<ResponseMsg>, next: NextFunction) => {
//   console.error(err.stack)
//   res.status(500).json({
//     msg: '',
//     error: 'something went bad'
//   })
// })

app.listen(port, () => {
  console.log(`Example app listening at http://localhost:${port}`);
  initializeRSAKeyPair();
})