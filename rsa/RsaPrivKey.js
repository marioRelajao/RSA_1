"use strict";
exports.__esModule = true;
var bcu = require("bigint-crypto-utils");
var RsaPrivKey = /** @class */ (function () {
    function RsaPrivKey(d, n) {
        this.d = d;
        this.n = n;
    }
    RsaPrivKey.prototype.decrypt = function (c) {
        // m = c^d mod n
        return bcu.modPow(c, this.d, this.n);
    };
    RsaPrivKey.prototype.sign = function (m) {
        // s = m^d mod n
        return bcu.modPow(m, this.d, this.n);
    };
    return RsaPrivKey;
}());
exports["default"] = RsaPrivKey;
