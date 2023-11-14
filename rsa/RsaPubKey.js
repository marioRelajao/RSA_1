"use strict";
exports.__esModule = true;
var bigint_conversion_1 = require("bigint-conversion");
var bcu = require("bigint-crypto-utils");
var RsaPubKey = /** @class */ (function () {
    function RsaPubKey(e, n) {
        this.e = e;
        this.n = n;
    }
    RsaPubKey.prototype.encrypt = function (m) {
        // C = m^e mod n
        return bcu.modPow(m, this.e, this.n);
    };
    RsaPubKey.prototype.verify = function (s) {
        // m = s^e mod n
        return bcu.modPow(s, this.e, this.n);
    };
    RsaPubKey.prototype.toJSON = function () {
        var pubKeyJson = {
            e: (0, bigint_conversion_1.bigintToBase64)(this.e),
            n: (0, bigint_conversion_1.bigintToBase64)(this.n)
        };
        return pubKeyJson;
    };
    RsaPubKey.prototype.fromJSON = function (pubKeyJson) {
        return new RsaPubKey((0, bigint_conversion_1.base64ToBigint)(pubKeyJson.e), (0, bigint_conversion_1.base64ToBigint)(pubKeyJson.n));
    };
    return RsaPubKey;
}());
exports["default"] = RsaPubKey;
