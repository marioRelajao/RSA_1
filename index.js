"use strict";
var __awaiter = (this && this.__awaiter) || function (thisArg, _arguments, P, generator) {
    function adopt(value) { return value instanceof P ? value : new P(function (resolve) { resolve(value); }); }
    return new (P || (P = Promise))(function (resolve, reject) {
        function fulfilled(value) { try { step(generator.next(value)); } catch (e) { reject(e); } }
        function rejected(value) { try { step(generator["throw"](value)); } catch (e) { reject(e); } }
        function step(result) { result.done ? resolve(result.value) : adopt(result.value).then(fulfilled, rejected); }
        step((generator = generator.apply(thisArg, _arguments || [])).next());
    });
};
var __generator = (this && this.__generator) || function (thisArg, body) {
    var _ = { label: 0, sent: function() { if (t[0] & 1) throw t[1]; return t[1]; }, trys: [], ops: [] }, f, y, t, g;
    return g = { next: verb(0), "throw": verb(1), "return": verb(2) }, typeof Symbol === "function" && (g[Symbol.iterator] = function() { return this; }), g;
    function verb(n) { return function (v) { return step([n, v]); }; }
    function step(op) {
        if (f) throw new TypeError("Generator is already executing.");
        while (g && (g = 0, op[0] && (_ = 0)), _) try {
            if (f = 1, y && (t = op[0] & 2 ? y["return"] : op[0] ? y["throw"] || ((t = y["return"]) && t.call(y), 0) : y.next) && !(t = t.call(y, op[1])).done) return t;
            if (y = 0, t) op = [op[0] & 2, t.value];
            switch (op[0]) {
                case 0: case 1: t = op; break;
                case 4: _.label++; return { value: op[1], done: false };
                case 5: _.label++; y = op[1]; op = [0]; continue;
                case 7: op = _.ops.pop(); _.trys.pop(); continue;
                default:
                    if (!(t = _.trys, t = t.length > 0 && t[t.length - 1]) && (op[0] === 6 || op[0] === 2)) { _ = 0; continue; }
                    if (op[0] === 3 && (!t || (op[1] > t[0] && op[1] < t[3]))) { _.label = op[1]; break; }
                    if (op[0] === 6 && _.label < t[1]) { _.label = t[1]; t = op; break; }
                    if (t && _.label < t[2]) { _.label = t[2]; _.ops.push(op); break; }
                    if (t[2]) _.ops.pop();
                    _.trys.pop(); continue;
            }
            op = body.call(thisArg, _);
        } catch (e) { op = [6, e]; y = 0; } finally { f = t = 0; }
        if (op[0] & 5) throw op[1]; return { value: op[0] ? op[1] : void 0, done: true };
    }
};
exports.__esModule = true;
var express_1 = require("express");
var morgan_1 = require("morgan"); // logger
var cors_1 = require("cors"); // allow us to permit connection from origins that are not our domain. Needed to allow the client (whose javascript is downloaded from another server) to connect 
var genRSA_1 = require("./rsa/genRSA");
var app = (0, express_1["default"])();
var port = 3000;
var keyPair = null;
app.use((0, morgan_1["default"])('dev')); // we use the morgan middleware to log some information regarding every request.
app.use((0, cors_1["default"])({
    origin: function (origin, allowFn) {
        allowFn(null, 'http://localhost:4200'); // Our angular client
        //allowFn(null, '<otherOrigin>') // We could add more origins
    }
}));
app.use(express_1["default"].json()); // let us load the json parser middleware, which will place JSON requests as a json in `req.body`
/**
 * Now we add the types and then TypeScript will infer the JSON.
 * A request is typed as Request<ParamsDictionary, ResBody, ReqBody, ReqQuery, Locals>
 * We will not use neither ParamsDictionary nor Locals (we will ignore them by setting the type to {}); for us the important ones are:
 *  - ResBody. The interface of our JSON response body. In our case it will be ResponseMsg
 *  - ReqQuery. The interface of the received query parametrs. Using RequestMsg would allow the case of http://localhost:3000/hello?name=Alice or just http://localhost:3000/hello, since `name` is an optional field.
 *  - ReqBody. The interface of the request body in an HTTP POST or PUT.
 */
function initializeRSAKeyPair() {
    return __awaiter(this, void 0, void 0, function () {
        var error_1;
        return __generator(this, function (_a) {
            switch (_a.label) {
                case 0:
                    _a.trys.push([0, 2, , 3]);
                    return [4 /*yield*/, (0, genRSA_1.generateRSAKeys)(1024)];
                case 1:
                    keyPair = _a.sent();
                    console.log('RSA key pair generated and saved globally.');
                    return [3 /*break*/, 3];
                case 2:
                    error_1 = _a.sent();
                    console.error('Error generating RSA keys:', error_1);
                    return [3 /*break*/, 3];
                case 3: return [2 /*return*/];
            }
        });
    });
}
// app.get('/hello', (req: Request<{}, ResponseMsg, {}, RequestMsg, {}>, res) => {
//   res.send({
//     msg: 'Hello ' + (req.query.name ??'anonymous')
//   })
// })
app.get('/UwU', function (req, res) {
    if (keyPair) {
        res.json({
            pubKey: keyPair.publicKey
        });
    }
    else {
        res.status(500).json({ error: 'RSA key pair not available' });
    }
});
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
app.listen(port, function () {
    console.log("Example app listening at http://localhost:".concat(port));
    initializeRSAKeyPair();
});
