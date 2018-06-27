require=(function e(t,n,r){function s(o,u){if(!n[o]){if(!t[o]){var a=typeof require=="function"&&require;if(!u&&a)return a(o,!0);if(i)return i(o,!0);var f=new Error("Cannot find module '"+o+"'");throw f.code="MODULE_NOT_FOUND",f}var l=n[o]={exports:{}};t[o][0].call(l.exports,function(e){var n=t[o][1][e];return s(n?n:e)},l,l.exports,e,t,n,r)}return n[o].exports}var i=typeof require=="function"&&require;for(var o=0;o<r.length;o++)s(r[o]);return s})({1:[function(require,module,exports){
"use strict";

var Buffer = require('safe-buffer').Buffer;
var Base58 = require('bs58');
var cryptoUtils = require('./utils/crypto-utils.js');
var utils = require('./utils/utils.js');

var AddressLength = 26;
var AddressPrefix = 25;
var NormalType = 87;
var ContractType = 88;

var KeyVersion3 = 3;
var KeyCurrentVersion = 4;

/**
 * @typedef {Object} KeyOptions
 * @property {Buffer} salt
 * @property {Buffer} iv
 * @property {String} kdf
 * @property {Number} dklen
 * @property {Number} c
 * @property {Number} n
 * @property {Number} r
 * @property {Number} p
 * @property {String} cipher
 * @property {Buffer} uuid
 * @global
 */

/**
 * Key Object.
 * @typedef {Object} Key
 * @property {Number} version
 * @property {Buffer} id
 * @property {HexString} address
 * @property {Object} crypto
 * @global
 */

/**
 * Account constructor.
 * Class encapsulate main operation with account entity.
 * @constructor
 *
 * @param {Hash} priv Account private key.
 * @param {String} path
 *
 * @example var account = new Account(new Buffer("ac3773e06ae74c0fa566b0e421d4e391333f31aef90b383f0c0e83e4873609d6", "hex") );
 *
 */
var Account = function (priv, path) {
    this.setPrivateKey(priv);
    this.path = path;
};

/**
 * Account factory method.
 * Create random account.
 * @static
 *
 * @return {Account} Instance of Account constructor.
 *
 * @example var account = Account.NewAccount();
 */
Account.NewAccount = function () {
    return new Account(cryptoUtils.crypto.randomBytes(32));
};

/**
 * Address validation method.
 *
 * @static
 * @param {String/Hash} addr - Account address.
 * @param {Number} type - NormalType / ContractType
 *
 * @return {Boolean} Is address has correct format.
 *
 * @example
 * if ( Account.isValidAddress("n1QZMXSZtW7BUerroSms4axNfyBGyFGkrh5") ) {
 *     // some code
 * };
 */
Account.isValidAddress = function (addr, type) {
    /*jshint maxcomplexity:10 */

    if (utils.isString(addr)) {
        try {
            addr = Base58.decode(addr);
        } catch (e) {
            console.log("invalid address.");
            // if address can't be base58 decode, return false.
            return false;
        }
    } else if (!Buffer.isBuffer(addr)) {
        return false;
    }
    // address not equal to 26
    if (addr.length !== AddressLength) {
        return false;
    }

    // check if address start with AddressPrefix
    var buff = Buffer.from(addr);
    if (buff.readUIntBE(0, 1) !== AddressPrefix) {
        return false;
    }

    // check if address type is NormalType or ContractType
    var t = buff.readUIntBE(1, 1);
    if (utils.isNumber(type) && (type === NormalType || type === ContractType)) {
        if (t !== type) {
            return false;
        }
    } else if (t !== NormalType && t !== ContractType) {
        return false;
    }
    var content = addr.slice(0, 22);
    var checksum = addr.slice(-4);
    return Buffer.compare(cryptoUtils.sha3(content).slice(0, 4), checksum) === 0;
};

/**
 * Restore account from address.
 * Receive addr or Account instance.
 * If addr is Account instance return new Account instance with same PrivateKey.
 *
 * @static
 * @param {(Hash|Object)} - Client address or Account instance.
 *
 * @return {Account} Instance of Account restored from address.
 *
 * @example var account = Account.fromAddress("n1QZMXSZtW7BUerroSms4axNfyBGyFGkrh5");
 */
Account.fromAddress = function (addr) {
    var acc = new Account();
    if (addr instanceof Account) {
        acc.setPrivateKey(addr.getPrivateKey());
        return acc;
    }
    if (utils.isString(addr) && this.isValidAddress(addr)) {
        acc.address = Base58.decode(addr);
        return acc;
    }

    var buf = cryptoUtils.toBuffer(addr);
    if (this.isValidAddress(buf)) {
        acc.address = buf;
        return acc;
    }
    throw new Error("invalid address");
};

Account.getNormalType = function () {
    return NormalType;
};

Account.getContractType = function () {
    return ContractType;
};

Account.prototype = {
    /**
     * Private Key setter.
     *
     * @param {Hash} priv - Account private key.
     *
     * @example account.setPrivateKey("ac3773e06ae74c0fa566b0e421d4e391333f31aef90b383f0c0e83e4873609d6");
     */
    setPrivateKey: function (priv) {
        if (utils.isString(priv) || Buffer.isBuffer(priv)) {
            this.privKey = priv.length === 32 ? priv : Buffer(priv, 'hex');
            this.pubKey = null;
            this.address = null;
        }
    },
    /**
     * Private Key getter.
     *
     * @return {Buffer} Account private key.
     *
     * @example var privKey = account.getPrivateKey();
     * //<Buffer 5b ed 67 f9 9c b3 31 9e 0c 6f 6a 03 54 8b e3 c8 c5 2a 83 64 46 4f 88 6f> 24
     */
    getPrivateKey: function () {
        return this.privKey;
    },
    /**
     * Get Private Key in hex string format.
     *
     * @return {HexString} Account private key in String format.
     *
     * @example var privKey = account.getPrivateKeyString();
     * //"ac3773e06ae74c0fa566b0e421d4e391333f31aef90b383f0c0e83e4873609d6"
     */
    getPrivateKeyString: function () {
        return this.getPrivateKey().toString('hex');
    },
    /**
     * Public Key getter.
     *
     * @return {Buffer} Account public key.
     *
     * @example var publicKey = account.getPublicKey();
     * //<Buffer c0 96 aa 4e 66 c7 4a 9a c7 18 31 f1 24 72 2a c1 3e b5 df 7f 97 1b 13 1d 46 a2 8a e6 81 c6 1d 96 f7 07 d0 aa e9 a7 67 436b 68 af a8 f0 96 65 17 24 29 ... >
     */
    getPublicKey: function () {
        if (utils.isNull(this.pubKey)) {
            this.pubKey = cryptoUtils.privateToPublic(this.privKey);
        }
        return this.pubKey;
    },
    /**
     * Get Public Key in hex string format.
     *
     * @return {HexString} Account public key in String format.
     *
     * @example var publicKey = account.getPublicKey();
     * //"f18ec04019dd131bbcfada4020b001d547244d768f144ef947577ce53a13ad690eb43e4b02a8daa3c168045cd122c0685f083e1656756ba7982721322ebe4da7"
     */
    getPublicKeyString: function () {
        return this.getPublicKey().toString('hex');
    },
    /**
     * Accaunt address getter.
     *
     * @return {Buffer} Account address.
     *
     * @example var publicKey = account.getAddress();
     * //<Buffer 7f 87 83 58 46 96 12 7d 1a c0 57 1a 42 87 c6 25 36 08 ff 32 61 36 51 7c>
     */
    getAddress: function () {
        if (utils.isNull(this.address)) {

            var pubKey = this.getPublicKey();
            if (pubKey.length !== 64) {
                pubKey = cryptoUtils.secp256k1.publicKeyConvert(pubKey, false).slice(1);
            }

            // The uncompressed form consists of a 0x04 (in analogy to the DER OCTET STRING tag) plus
            // the concatenation of the binary representation of the X coordinate plus the binary
            // representation of the y coordinate of the public point.
            pubKey = Buffer.concat([cryptoUtils.toBuffer(4), pubKey]);

            // Only take the lower 160bits of the hash
            var content = cryptoUtils.sha3(pubKey);
            content = cryptoUtils.ripemd160(content);
            // content = AddressPrefix + NormalType + content(local address only use normal type)
            content = Buffer.concat([cryptoUtils.toBuffer(AddressPrefix), cryptoUtils.toBuffer(NormalType), content]);
            var checksum = cryptoUtils.sha3(content).slice(0, 4);
            this.address = Buffer.concat([content, checksum]);
        }
        return this.address;
    },
    /**
     * Get account address in hex string format.
     *
     * @return {HexString} Account address in String format.
     *
     * @example var publicKey = account.getAddressString();
     * //"802d529bf55d6693b3ac72c59b4a7d159da53cae5a7bf99c"
     */
    getAddressString: function () {
        var addr = this.getAddress();
        return Base58.encode(addr);
    },
    /**
     * Generate key buy passphrase and options.
     *
     * @param {Password} password - Provided password.
     * @param {KeyOptions} opts - Key options.
     *
     * @return {Key} Key Object.
     *
     * @example var key = account.toKey("passphrase");
     */
    toKey: function (password, opts) {
        /*jshint maxcomplexity:16 */

        opts = opts || {};
        var salt = opts.salt || cryptoUtils.crypto.randomBytes(32);
        var iv = opts.iv || cryptoUtils.crypto.randomBytes(16);
        var derivedKey;
        var kdf = opts.kdf || 'scrypt';
        var kdfparams = {
            dklen: opts.dklen || 32,
            salt: salt.toString('hex')
        };
        if (kdf === 'pbkdf2') {
            kdfparams.c = opts.c || 262144;
            kdfparams.prf = 'hmac-sha256';
            derivedKey = cryptoUtils.crypto.pbkdf2Sync(new Buffer(password), salt, kdfparams.c, kdfparams.dklen, 'sha256');
        } else if (kdf === 'scrypt') {
            kdfparams.n = opts.n || 4096;
            kdfparams.r = opts.r || 8;
            kdfparams.p = opts.p || 1;
            derivedKey = cryptoUtils.scrypt(new Buffer(password), salt, kdfparams.n, kdfparams.r, kdfparams.p, kdfparams.dklen);
        } else {
            throw new Error('Unsupported kdf');
        }
        var cipher = cryptoUtils.crypto.createCipheriv(opts.cipher || 'aes-128-ctr', derivedKey.slice(0, 16), iv);
        if (!cipher) {
            throw new Error('Unsupported cipher');
        }
        var ciphertext = Buffer.concat([cipher.update(this.privKey), cipher.final()]);
        // var mac = cryptoUtils.sha3(Buffer.concat([derivedKey.slice(16, 32), new Buffer(ciphertext, 'hex')]));   // KeyVersion3 deprecated
        var mac = cryptoUtils.sha3(Buffer.concat([derivedKey.slice(16, 32), new Buffer(ciphertext, 'hex'), iv, new Buffer(opts.cipher || 'aes-128-ctr')]));
        return {
            version: KeyCurrentVersion,
            id: cryptoUtils.uuid.v4({
                random: opts.uuid || cryptoUtils.crypto.randomBytes(16)
            }),
            address: this.getAddressString(),
            crypto: {
                ciphertext: ciphertext.toString('hex'),
                cipherparams: {
                    iv: iv.toString('hex')
                },
                cipher: opts.cipher || 'aes-128-ctr',
                kdf: kdf,
                kdfparams: kdfparams,
                mac: mac.toString('hex'),
                machash: "sha3256"
            }
        };
    },
    /**
     * Generate key buy passphrase and options.
     * Return in JSON format.
     *
     * @param {Password} password - Provided password.
     * @param {KeyOptions} opts - Key options.
     *
     * @return {String} JSON stringify Key.
     *
     * @example var key = account.toKeyString("passphrase");
     */
    toKeyString: function (password, opts) {
        return JSON.stringify(this.toKey(password, opts));
    },
    /**
     * Restore account from key and passphrase.
     *
     * @param {Key} input - Key Object.
     * @param {Password} password - Provided password.
     * @param {Boolean} nonStrict - Strict сase sensitivity flag.
     *
     * @return {@link Account} - Instance of Account restored from key and passphrase.
     */
    fromKey: function (input, password, nonStrict) {
        /*jshint maxcomplexity:9 */

        var json = typeof input === 'object' ? input : JSON.parse(nonStrict ? input.toLowerCase() : input);
        if (json.version !== KeyVersion3 && json.version !== KeyCurrentVersion) {
            throw new Error('Not supported wallet version');
        }
        var derivedKey;
        var kdfparams;
        if (json.crypto.kdf === 'scrypt') {
            kdfparams = json.crypto.kdfparams;
            derivedKey = cryptoUtils.scrypt(new Buffer(password), new Buffer(kdfparams.salt, 'hex'), kdfparams.n, kdfparams.r, kdfparams.p, kdfparams.dklen);
        } else if (json.crypto.kdf === 'pbkdf2') {
            kdfparams = json.crypto.kdfparams;
            if (kdfparams.prf !== 'hmac-sha256') {
                throw new Error('Unsupported parameters to PBKDF2');
            }
            derivedKey = cryptoUtils.crypto.pbkdf2Sync(new Buffer(password), new Buffer(kdfparams.salt, 'hex'), kdfparams.c, kdfparams.dklen, 'sha256');
        } else {
            throw new Error('Unsupported key derivation scheme');
        }
        var ciphertext = new Buffer(json.crypto.ciphertext, 'hex');
        var mac;

        if (json.version === KeyCurrentVersion) {
            mac = cryptoUtils.sha3(Buffer.concat([derivedKey.slice(16, 32), ciphertext, new Buffer(json.crypto.cipherparams.iv, 'hex'), new Buffer(json.crypto.cipher)]));
        } else {
            // KeyVersion3
            mac = cryptoUtils.sha3(Buffer.concat([derivedKey.slice(16, 32), ciphertext]));
        }

        if (mac.toString('hex') !== json.crypto.mac) {
            throw new Error('Key derivation failed - possibly wrong passphrase');
        }
        var decipher = cryptoUtils.crypto.createDecipheriv(json.crypto.cipher, derivedKey.slice(0, 16), new Buffer(json.crypto.cipherparams.iv, 'hex'));
        var seed = Buffer.concat([decipher.update(ciphertext), decipher.final()]);
        while (seed.length < 32) {
            var nullBuff = new Buffer([0x00]);
            seed = Buffer.concat([nullBuff, seed]);
        }
        this.setPrivateKey(seed);
        return this;
    }

};

module.exports = Account;

},{"./utils/crypto-utils.js":8,"./utils/utils.js":10,"bs58":94,"safe-buffer":234}],2:[function(require,module,exports){

"use strict";

var utils = require('./utils/utils.js');

/**
 * Admin API constructor.
 * Class encapsulate methods for admin APIs commands.
 * @see [Admin API documentation:]{@link https://github.com/nebulasio/wiki/blob/master/rpc_admin.md}.
 * @constructor
 *
 * @param {Neb} neb - Instance of Neb library.
 *
 * @example
 * var admin = new Admin( new Neb() );
 * // or just
 * var admin = new Neb().admin;
 */
var Admin = function (neb) {
    this._setRequest(neb._request);
};

/**
 * @private
 * @param {Request} request - transport wrapper.
 */
Admin.prototype._setRequest = function (request) {
    this._request = request;
    this._path = '/admin';
};

/**
 * Method get info about nodes in Nebulas Network.
 * @see {@link https://github.com/nebulasio/wiki/blob/master/rpc_admin.md#nodeinfo}
 *
 * @return [nodeInfoObject]{@link https://github.com/nebulasio/wiki/blob/master/rpc_admin.md#nodeinfo}
 *
 * @example
 * var admin = new Neb().admin;
 * admin.nodeInfo().then(function(info) {
 * //code
 * });
 */
Admin.prototype.nodeInfo = function () {
    return this._sendRequest("get", "/nodeinfo", null);
};

/**
 * Method get list of available addresses.
 * @see {@link https://github.com/nebulasio/wiki/blob/master/rpc_admin.md#accounts}
 *
 * @return [accountsList]{@link https://github.com/nebulasio/wiki/blob/master/rpc_admin.md#accounts}
 *
 * @example
 * var admin = new Neb().admin;
 * admin.accounts().then(function(accounts) {
 * //code
 * });
 */
Admin.prototype.accounts = function () {
    return this._sendRequest("get", "/accounts", null);
};

/**
 * Method create a new account in Nebulas network with provided passphrase.
 * @see {@link https://github.com/nebulasio/wiki/blob/master/rpc_admin.md#newaccount}
 *
 * @param {Object} options
 * @param {Password} options.passphrase
 *
 * @return [address]{@link https://github.com/nebulasio/wiki/blob/master/rpc_admin.md#newaccount}
 *
 * @example
 * var admin = new Neb().admin;
 * admin.newAccount({passphrase: "passphrase"}).then(function(address) {
 * //code
 * });
 */
Admin.prototype.newAccount = function (options) {
    options = utils.argumentsToObject(['passphrase'], arguments);
    var params = { "passphrase": options.passphrase };
    return this._sendRequest("post", "/account/new", params);
};

/**
 * Method unlock account with provided passphrase.
 * After the default unlock time, the account will be locked.
 * @see {@link https://github.com/nebulasio/wiki/blob/master/rpc_admin.md#unlockaccount}
 *
 * @param {Object} options
 * @param {HexString} options.address
 * @param {Password} options.passphrase
 * @param {Number} options.duration
 *
 * @return [isUnLocked]{@link https://github.com/nebulasio/wiki/blob/master/rpc_admin.md#unlockaccount}
 *
 * @example
 * var admin = new Neb().admin;
 * admin.unlockAccount({
 *     address: "n1cYKNHTeVW9v1NQRWuhZZn9ETbqAYozckh",
 *     passphrase: "passphrase",
 *     duration: 1000000000
 * }).then(function(isUnLocked) {
 * //code
 * });
 */
Admin.prototype.unlockAccount = function (options) {
    options = utils.argumentsToObject(['address', 'passphrase', 'duration'], arguments);
    var params = {
        "address": options.address,
        "passphrase": options.passphrase,
        "duration": options.duration
    };
    return this._sendRequest("post", "/account/unlock", params);
};

/**
 * Method lock account.
 * @see {@link https://github.com/nebulasio/wiki/blob/master/rpc_admin.md#lockaccount}
 *
 * @param {Object} options
 * @param {HexString} options.address
 *
 * @return [isLocked]{@link https://github.com/nebulasio/wiki/blob/master/rpc_admin.md#lockaccount}
 *
 * @example
 * var admin = new Neb().admin;
 * admin.lockAccount({address: "n1cYKNHTeVW9v1NQRWuhZZn9ETbqAYozckh"}).then(function(isLocked) {
 * //code
 * });
 */
Admin.prototype.lockAccount = function (options) {
    options = utils.argumentsToObject(['address'], arguments);
    var params = { "address": options.address };
    return this._sendRequest("post", "/account/lock", params);
};

/**
 * Method wrap transaction sending functionality.
 * @see {@link https://github.com/nebulasio/wiki/blob/master/rpc_admin.md#sendtransaction}
 *
 * @param {TransactionOptions} options
 *
 * @return [Transcation hash and contract address]{@link https://github.com/nebulasio/wiki/blob/master/rpc_admin.md#sendtransaction}
 *
 * @example
 * var admin = new Neb().admin;
 * admin.sendTransaction({
 *    from: "n1QZMXSZtW7BUerroSms4axNfyBGyFGkrh5",
 *    to: "n1SAeQRVn33bamxN4ehWUT7JGdxipwn8b17",
 *    value: 10,
 *    nonce: 12,
 *    gasPrice: 1000000,
 *    gasLimit: 2000000
 * }).then(function(tx) {
 * //code
 * });
 */
Admin.prototype.sendTransaction = function (options) {
    options = utils.argumentsToObject(['from', 'to', 'value', 'nonce', 'gasPrice', 'gasLimit', 'contract', 'binary'], arguments);
    var params = {
        "from": options.from,
        "to": options.to,
        "value": utils.toString(options.value),
        "nonce": options.nonce,
        "gasPrice": utils.toString(options.gasPrice),
        "gasLimit": utils.toString(options.gasLimit),
        "contract": options.contract,
        "binary": options.binary
    };
    return this._sendRequest("post", "/transaction", params);
};

/**
 * Method sign hash.
 * @see {@link https://github.com/nebulasio/wiki/blob/master/rpc_admin.md#signhash}
 *
 * @param {Object} options
 * @param {HexString} options.address
 * @param {Base64} options.hash of hash bytes with base64 encode.
 * @param {UInt32} options.alg
 *
 * @return [data]{@link https://github.com/nebulasio/wiki/blob/master/rpc_admin.md#signhash}
 *
 * @example
 * var admin = new Neb().admin;
 * admin.SignHash({
 *     address: "n1cYKNHTeVW9v1NQRWuhZZn9ETbqAYozckh",
 *     hash: "OGQ5NjllZWY2ZWNhZDNjMjlhM2E2MjkyODBlNjg2Y2YwYzNmNWQ1YTg2YWZmM2NhMTIwMjBjOTIzYWRjNmM5Mg==",
 *     alg: 1
 * }).then(function(data) {
 * //code
 * });
 */
Admin.prototype.signHash = function (options) {
    options = utils.argumentsToObject(['address', 'hash', 'alg'], arguments);
    var params = {
        "address": options.address,
        "hash": options.hash,
        "alg": options.alg
    };
    return this._sendRequest("post", "/sign/hash", params);
};

/**
 * Method sign transaction with passphrase.
 * The transaction's from addrees must be unlock before sign call.
 * @see {@link https://github.com/nebulasio/wiki/blob/master/rpc_admin.md#signtransactionwithpassphrase}
 *
 * @param {TransactionOptions} options
 * @param {Password} options.passphrase
 *
 * @return [Transcation hash and contract address]{@link https://github.com/nebulasio/wiki/blob/master/rpc_admin.md#signtransactionwithpassphrase}
 *
 * @example
 * var admin = new Neb().admin;
 * admin.signTransactionWithPassphrase({
 *    from: "n1QZMXSZtW7BUerroSms4axNfyBGyFGkrh5",
 *    to: "n1SAeQRVn33bamxN4ehWUT7JGdxipwn8b17",
 *    value: 10,
 *    nonce: 12,
 *    gasPrice: 1000000,
 *    gasLimit: 2000000,
 *    passphrase: "passphrase"
 * }).then(function(tx) {
 * //code
 * });
 */
Admin.prototype.signTransactionWithPassphrase = function (options) {
    options = utils.argumentsToObject(['from', 'to', 'value', 'nonce', 'gasPrice', 'gasLimit', 'contract', 'binary', 'passphrase'], arguments);
    var tx = {
        "from": options.from,
        "to": options.to,
        "value": utils.toString(options.value),
        "nonce": options.nonce,
        "gasPrice": utils.toString(options.gasPrice),
        "gasLimit": utils.toString(options.gasLimit),
        "contract": options.contract,
        "binary": options.binary
    };
    var params = {
        "transaction": tx,
        "passphrase": options.passphrase
    };
    return this._sendRequest("post", "/sign", params);
};

/**
 * Method send transaction with passphrase.
 * @see {@link https://github.com/nebulasio/wiki/blob/master/rpc_admin.md#sendtransactionwithpassphrase}
 *
 * @param {TransactionOptions} options
 * @param {Password} options.passphrase
 *
 * @return [data]{@link https://github.com/nebulasio/wiki/blob/master/rpc_admin.md#sendtransactionwithpassphrase}
 *
 * @example
 * var admin = new Neb().admin;
 * admin.sendTransactionWithPassphrase({
 *    from: "n1QZMXSZtW7BUerroSms4axNfyBGyFGkrh5",
 *    to: "n1SAeQRVn33bamxN4ehWUT7JGdxipwn8b17",
 *    value: 10,
 *    nonce: 12,
 *    gasPrice: 1000000,
 *    gasLimit: 2000000,
 *    passphrase: "passphrase"
 * }).then(function(tx) {
 * //code
 * });
 */
Admin.prototype.sendTransactionWithPassphrase = function (options) {
    options = utils.argumentsToObject(['from', 'to', 'value', 'nonce', 'gasPrice', 'gasLimit', 'contract', 'binary', 'passphrase'], arguments);
    var tx = {
        "from": options.from,
        "to": options.to,
        "value": utils.toString(options.value),
        "nonce": options.nonce,
        "gasPrice": utils.toString(options.gasPrice),
        "gasLimit": utils.toString(options.gasLimit),
        "contract": options.contract,
        "binary": options.binary
    };
    var params = {
        "transaction": tx,
        "passphrase": options.passphrase
    };
    return this._sendRequest("post", "/transactionWithPassphrase", params);
};

/**
 * Method start listen provided port.
 * @see {@link https://github.com/nebulasio/wiki/blob/master/rpc_admin.md#startpprof}
 *
 * @param {Object} options
 * @param {String} options.listen - Listen port.
 *
 * @return [isListenStrted]{@link https://github.com/nebulasio/wiki/blob/master/rpc_admin.md#startpprof}
 *
 * @example
 * var admin = new Neb().admin;
 * admin.startPprof({listen: '8080'}).then(function(isListenStrted) {
 * //code
 * });
 */
Admin.prototype.startPprof = function (options) {
    options = utils.argumentsToObject(['listen'], arguments);
    var params = { "listen": options.listen };
    return this._sendRequest("post", "/pprof", params);
};

/**
 * Method get config of node in Nebulas Network.
 * @see {@link https://github.com/nebulasio/wiki/blob/master/rpc_admin.md#getConfig}
 *
 * @return [config]{@link https://github.com/nebulasio/wiki/blob/master/rpc_admin.md#getConfig}
 *
 * @example
 * var admin = new Neb().admin;
 * admin.getConfig().then(function(info) {
 * //code
 * });
 */
Admin.prototype.getConfig = function () {
    return this._sendRequest("get", "/getConfig", null);
};

Admin.prototype._sendRequest = function (method, api, params, callback) {
    var action = this._path + api;
    if (typeof callback === "function") {
        return this._request.asyncRequest(method, action, params, callback);
    } else {
        return this._request.request(method, action, params);
    }
};

module.exports = Admin;

},{"./utils/utils.js":10}],3:[function(require,module,exports){

"use strict";

var utils = require('./utils/utils.js');

/**
 * User API constructor.
 * Class encapsulate methods for building distributed applications and services.
 *
 * @see [API documentation]{@link https://github.com/nebulasio/wiki/blob/master/rpc.md}
 * @constructor
 *
 * @param {Neb} neb - Instance of Neb library.
 *
 * @example
 * var api = new API ( new Neb() );
 * // or just
 * var api = new Neb().api;
 */
var API = function (neb) {
    this._setRequest(neb._request);
};

/**
 * @private
 * @param {Request} request - transport wrapper.
 */
API.prototype._setRequest = function (request) {
    this._request = request;
    this._path = '/user';
};

/**
 * Method get state of Nebulas Network.
 * @see {@link https://github.com/nebulasio/wiki/blob/master/rpc.md#getnebstate}
 *
 * @return [NebStateObject]{@link https://github.com/nebulasio/wiki/blob/master/rpc.md#getnebstate}
 *
 * @example
 * var api = new Neb().api;
 * api.getNebState().then(function(state) {
 * //code
 * });
 */
API.prototype.getNebState = function () {
    return this._sendRequest("get", "/nebstate", null);
};

/**
 * Method get latest irreversible block of Nebulas Network.
 * @see {@link https://github.com/nebulasio/wiki/blob/master/rpc.md#latestirreversibleblock}
 *
 * @return [dataBlockInfo.]{@link https://github.com/nebulasio/wiki/blob/master/rpc.md#latestirreversibleblock}
 *
 * @example
 * var api = new Neb().api;
 * api.latestIrreversibleBlock().then(function(blockData) {
 * //code
 * });
 */
API.prototype.latestIrreversibleBlock = function () {
    return this._sendRequest("get", "/lib", null);
};

/**
 * Method return the state of the account. Balance and nonce.
 * @see {@link https://github.com/nebulasio/wiki/blob/master/rpc.md#getaccountstate}
 *
 * @param {Object} options
 * @param {HexString} options.address
 * @param {String} options.height
 *
 * @return [accaountStateObject]{@link https://github.com/nebulasio/wiki/blob/master/rpc.md#getaccountstate}
 *
 * @example
 * var api = new Neb().api;
 * api.getAccountState({address: "n1QsosVXKxiV3B4iDWNmxfN4VqpHn2TeUcn"}).then(function(state) {
 * //code
 * });
 */
API.prototype.getAccountState = function (options) {
    options = utils.argumentsToObject(['address', 'height'], arguments);
    var params = { "address": options.address, "height": options.height };
    return this._sendRequest("post", "/accountstate", params);
};

/**
 * Method wrap smart contract call functionality.
 * @see {@link https://github.com/nebulasio/wiki/blob/master/rpc.md#call}
 *
 * @param {TransactionOptions} options
 *
 * @return [Transcation hash]{@link https://github.com/nebulasio/wiki/blob/master/rpc.md#call}
 *
 * @example
 * var api = new Neb().api;
 * api.call({
 *    chainID: 1,
 *    from: "n1QZMXSZtW7BUerroSms4axNfyBGyFGkrh5",
 *    to: "n1SAeQRVn33bamxN4ehWUT7JGdxipwn8b17",
 *    value: 10,
 *    nonce: 12,
 *    gasPrice: 1000000,
 *    gasLimit: 2000000,
 *    contract: {
 *        function: "save",
 *        args: "[0]"
 *    }
 * }).then(function(tx) {
 *     //code
 * });
 */
API.prototype.call = function (options) {
    options = utils.argumentsToObject(['from', 'to', 'value', 'nonce', 'gasPrice', 'gasLimit', 'contract'], arguments);
    var params = {
        "from": options.from,
        "to": options.to,
        "value": utils.toString(options.value),
        "nonce": options.nonce,
        "gasPrice": utils.toString(options.gasPrice),
        "gasLimit": utils.toString(options.gasLimit),
        "contract": options.contract
    };
    return this._sendRequest("post", "/call", params);
};

/**
 * Method wrap submit the signed transaction.
 * @see {@link https://github.com/nebulasio/wiki/blob/master/rpc.md#sendrawtransaction}
 *
 * @param {Object} options
 * @param {String} options.data
 *
 * @return [Transcation hash]{@link https://github.com/nebulasio/wiki/blob/master/rpc.md#sendrawtransaction}
 *
 * @example
 * var api = new Neb().api;
 * var tx = new Transaction({
 *    chainID: 1,
 *    from: acc1,
 *    to: acc2,
 *    value: 10,
 *    nonce: 12,
 *    gasPrice: 1000000,
 *    gasLimit: 2000000
 * });
 * tx.signTransaction();
 * api.sendRawTransaction( {data: tx.toProtoString()} ).then(function(hash) {
 * //code
 * });
 */
API.prototype.sendRawTransaction = function (options) {
    options = utils.argumentsToObject(['data'], arguments);
    var params = { "data": options.data };
    return this._sendRequest("post", "/rawtransaction", params);
};

/**
 * Get block header info by the block hash.
 * @see {@link https://github.com/nebulasio/wiki/blob/master/rpc.md#getblockbyhash}
 *
 * @param {Object} options
 * @param {HexString} options.hash
 * @param {Boolean} options.fullTransaction
 *
 * @return [Block]{@link https://github.com/nebulasio/wiki/blob/master/rpc.md#getblockbyhash}
 *
 * @example
 * var api = new Neb().api;
 * api.getBlockByHash({
 *     hash: "00000658397a90df6459b8e7e63ad3f4ce8f0a40b8803ff2f29c611b2e0190b8",
 *     fullTransaction: true
 * }).then(function(block) {
 * //code
 * });
 */
API.prototype.getBlockByHash = function (options) {
    options = utils.argumentsToObject(['hash', 'fullTransaction'], arguments);
    var params = { "hash": options.hash, "full_fill_transaction": options.fullTransaction };
    return this._sendRequest("post", "/getBlockByHash", params);
};

/**
 * Get block header info by the block height.
 * @see {@link https://github.com/nebulasio/wiki/blob/master/rpc.md#getblockbyheight}
 *
 * @param {Object} options
 * @param {Number} options.height
 * @param {Boolean} options.fullTransaction
 *
 * @return [Block]{@link https://github.com/nebulasio/wiki/blob/master/rpc.md#getblockbyheight}
 *
 * @example
 * var api = new Neb().api;
 * api.getBlockByHeight({height:2, fullTransaction:true}).then(function(block) {
 * //code
 * });
 */
API.prototype.getBlockByHeight = function (options) {
    options = utils.argumentsToObject(['height', 'fullTransaction'], arguments);
    var params = { "height": options.height, "full_fill_transaction": options.fullTransaction };
    return this._sendRequest("post", "/getBlockByHeight", params);
};

/**
 * Get transactionReceipt info by tansaction hash.
 * @see {@link https://github.com/nebulasio/wiki/blob/master/rpc.md#gettransactionreceipt}
 *
 * @param {Object} options
 * @param {HexString} options.hash
 *
 * @return [TransactionReceipt]{@link https://github.com/nebulasio/wiki/blob/master/rpc.md#gettransactionreceipt}
 *
 * @example
 * var api = new Neb().api;
 * api.getTransactionReceipt({hash: "cc7133643a9ae90ec9fa222871b85349ccb6f04452b835851280285ed72b008c"}).then(function(receipt) {
 * //code
 * });
 */
API.prototype.getTransactionReceipt = function (options) {
    options = utils.argumentsToObject(['hash'], arguments);
    var params = { "hash": options.hash };
    return this._sendRequest("post", "/getTransactionReceipt", params);
};

/**
 * Get transactionReceipt info by contract address.
 * @see {@link https://github.com/nebulasio/wiki/blob/master/rpc.md#gettransactionbycontract}
 * 
 * @param {Object} options
 * @param {HexString} options.address contract address
 * 
 * @returns the same as [TransactionReceipt]{@link https://github.com/nebulasio/wiki/blob/master/rpc.md#gettransactionreceipt}
 * 
 * @example
 * var api = new Neb().api;
 * api.getTransactionByContract({address: "n1sqDHGjYtX6rMqFoq5Tow3s3LqF4ZxBvE3"}).then(function(receipt) {
 *  //code
 * });
 */
API.prototype.getTransactionByContract = function (options) {
    options = utils.argumentsToObject(['address'], arguments);
    var params = { "address": options.address };
    return this._sendRequest("post", "/getTransactionByContract", params);
};

/**
 * Return the subscribed events of transaction & block.
 * @see {@link https://github.com/nebulasio/wiki/blob/master/rpc.md#subscribe}
 *
 * @param {Object} options
 * @param {Array|String} options.topics
 * @param {Function} options.onDownloadProgress - On progress callback function. Recive chunk.
 *
 * @return [eventData]{@link https://github.com/nebulasio/wiki/blob/master/rpc.md#subscribe}
 *
 * @example
 * var api = new Neb().api;
 * api.subscribe({topics: ["chain.linkBlock", "chain.pendingTransaction"]}).then(function(eventData) {
 * //code
 * });
 */
API.prototype.subscribe = function (options) {
    options = utils.argumentsToObject(['topics', 'onDownloadProgress'], arguments);
    var params = { "topics": options.topics };
    var axiosOptions;
    if (typeof options.onDownloadProgress === 'function') {
        axiosOptions = {
            onDownloadProgress: function (e) {
                if (typeof e.target._readLength === 'undefined') {
                    e.target._readLength = 0;
                }
                var chunk = e.target.responseText.substr(e.target._readLength);
                // TODO check and split multi events
                if (chunk && chunk.trim().length > 0) {
                    e.target._readLength += chunk.length;
                    options.onDownloadProgress(chunk);
                }
            }
        };
    }
    return this._sendRequest("post", "/subscribe", params, null, axiosOptions);
};

/**
 * Return current gasPrice.
 * @see {@link https://github.com/nebulasio/wiki/blob/master/rpc.md#getgasprice}
 *
 * @return [Gas Price]{@link https://github.com/nebulasio/wiki/blob/master/rpc.md#getgasprice}
 *
 * @example
 * var api = new Neb().api;
 * api.gasPrice().then(function(gasPrice) {
 * //code
 * });
 */
API.prototype.gasPrice = function () {
    return this._sendRequest("get", "/getGasPrice", null);
};

/**
 * Return the estimate gas of transaction.
 * @see {@link https://github.com/nebulasio/wiki/blob/master/rpc.md#estimategas}
 *
 * @param {TransactionOptions} options
 *
 * @return [Gas]{@link https://github.com/nebulasio/wiki/blob/master/rpc.md#estimategas}
 *
 * @example
 * var api = new Neb().api;
 * api.estimateGas({
 *    chainID: 1,
 *    from: "n1QZMXSZtW7BUerroSms4axNfyBGyFGkrh5",
 *    to: "n1SAeQRVn33bamxN4ehWUT7JGdxipwn8b17",
 *    value: 10,
 *    nonce: 12,
 *    gasPrice: 1000000,
 *    gasLimit: 2000000
 * }).then(function(gas) {
 * //code
 * });
 */
API.prototype.estimateGas = function (options) {
    options = utils.argumentsToObject(['from', 'to', 'value', 'nonce', 'gasPrice', 'gasLimit', 'contract', 'binary'], arguments);
    var params = {
        "from": options.from,
        "to": options.to,
        "value": utils.toString(options.value),
        "nonce": options.nonce,
        "gasPrice": utils.toString(options.gasPrice),
        "gasLimit": utils.toString(options.gasLimit),
        "contract": options.contract,
        "binary": options.binary
    };
    return this._sendRequest("post", "/estimateGas", params);
};

/**
 * Return the events list of transaction.
 * @see {@link https://github.com/nebulasio/wiki/blob/master/rpc.md#geteventsbyhash}
 *
 * @param {Object} options
 * @param {HexString} options.hash
 *
 * @return [Events]{@link https://github.com/nebulasio/wiki/blob/master/rpc.md#geteventsbyhash}
 *
 * @example
 * var api = new Neb().api;
 * api.getEventsByHash({hash: "ec239d532249f84f158ef8ec9262e1d3d439709ebf4dd5f7c1036b26c6fe8073"}).then(function(events) {
 * //code
 * });
 */
API.prototype.getEventsByHash = function (options) {
    options = utils.argumentsToObject(['hash'], arguments);
    var params = { "hash": options.hash };
    return this._sendRequest("post", "/getEventsByHash", params);
};

/**
 * Method getter for dpos dynasty.
 * @see {@link https://github.com/nebulasio/wiki/blob/master/rpc.md#getdynasty}
 *
 * @param {Object} options
 * @param {Number} options.height
 *
 * @return [delegatees]{@link https://github.com/nebulasio/wiki/blob/master/rpc.md#getdynasty}
 *
 * @example
 * var api = new Neb().api;
 * api.getDynasty({height: 1}).then(function(delegatees) {
 * //code
 * });
 */
API.prototype.getDynasty = function (options) {
    var params = { "height": options.height };
    return this._sendRequest("post", "/dynasty", params);
};

API.prototype._sendRequest = function (method, api, params, callback, axiosOptions) {
    var action = this._path + api;
    if (typeof callback === "function") {
        return this._request.asyncRequest(method, action, params, callback);
    } else {
        return this._request.request(method, action, params, axiosOptions);
    }
};

module.exports = API;

},{"./utils/utils.js":10}],4:[function(require,module,exports){
"use strict";

var axios = require("axios");

var debugLog = false;

var HttpRequest = function (host, timeout, apiVersion) {
    this.host = host || "http://localhost:8685";
    this.timeout = timeout || 0;
    this.apiVersion = apiVersion || "v1";
};

HttpRequest.prototype.setHost = function (host) {
    this.host = host;
};

HttpRequest.prototype.setAPIVersion = function (apiVersion) {
    this.apiVersion = apiVersion;
};

HttpRequest.prototype.createUrl = function (api) {
    return this.host + "/" + this.apiVersion + api;
};

HttpRequest.prototype.request = function (method, api, payload, axiosOptions) {
    if (debugLog) {
        console.log("[debug] HttpRequest: " + method + " " + this.createUrl(api) + " " + JSON.stringify(payload));
    }

    var axiosParams = {
        method: method,
        url: this.createUrl(api),
        data: payload,
        transformResponse: [function (resp) {
            if (typeof resp === "string") {
                resp = JSON.parse(resp);
            }
            return resp.result || resp;
        }]
    };
    if (axiosOptions && typeof axiosOptions.onDownloadProgress === 'function') {
        axiosParams.onDownloadProgress = axiosOptions.onDownloadProgress;
    }
    return axios(axiosParams).then(function (resp) {
        return resp.data;
    }).catch(function (e) {
        if (typeof e.response !== "undefined") {
            throw new Error(e.response.data.error);
        } else {
            throw new Error(e.message);
        }
    });
};

HttpRequest.prototype.asyncRequest = function (method, api, payload, callback) {
    return this.request(method, api, payload).then(function (data) {
        callback(data);
    }).catch(function (err) {
        callback(err);
    });
};

module.exports = HttpRequest;

},{"axios":35}],5:[function(require,module,exports){

"use strict";

var API = require("./api.js");
var Admin = require("./admin.js");

var Unit = require("./utils/unit.js");

/**
 * Neb API library constructor.
 * @constructor
 * @param {Request} request - transport wrapper.
 */
var Neb = function (request) {
	if (request) {
		this._request = request;
	}

	this.api = new API(this);
	this.admin = new Admin(this);
};

Neb.prototype.setRequest = function (request) {
	this._request = request;
	this.api._setRequest(request);
	this.admin._setRequest(request);
};

Neb.prototype.toBasic = Unit.toBasic;
Neb.prototype.fromBasic = Unit.fromBasic;
Neb.prototype.nasToBasic = Unit.nasToBasic;

module.exports = Neb;

},{"./admin.js":2,"./api.js":3,"./utils/unit.js":9}],6:[function(require,module,exports){
module.exports={
  "nested": {
    "corepb": {
      "nested": {
        "Data": {
          "fields": {
            "type": {
              "type": "string",
              "id": 1
            },
            "payload": {
              "type": "bytes",
              "id": 2
            }
          }
        },
        "Transaction": {
          "fields": {
            "hash": {
              "type": "bytes",
              "id": 1
            },
            "from": {
              "type": "bytes",
              "id": 2
            },
            "to": {
              "type": "bytes",
              "id": 3
            },
            "value": {
              "type": "bytes",
              "id": 4
            },
            "nonce": {
              "type": "uint64",
              "id": 5
            },
            "timestamp": {
              "type": "int64",
              "id": 6
            },
            "data": {
              "type": "Data",
              "id": 7
            },
            "chainId": {
              "type": "uint32",
              "id": 8
            },
            "gasPrice": {
              "type": "bytes",
              "id": 9
            },
            "gasLimit": {
              "type": "bytes",
              "id": 10
            },
            "alg": {
              "type": "uint32",
              "id": 11
            },
            "sign": {
              "type": "bytes",
              "id": 12
            }
          }
        }
      }
    }
  }
}
},{}],7:[function(require,module,exports){
"use strict";

var protobuf = require('protobufjs');
var utils = require('./utils/utils.js');
var cryptoUtils = require('./utils/crypto-utils.js');
var account = require("./account.js");
var htmlescape = require('htmlescape');
var BigNumber = require('bignumber.js');

var SECP256K1 = 1;
var root = protobuf.Root.fromJSON(require("./transaction.json"));

var TxPayloadBinaryType = "binary";
var TxPayloadDeployType = "deploy";
var TxPayloadCallType = "call";

/**
 * @typedef TransactionInit
 * @example
 * var acc = Account.NewAccount();
 *
 * var tx = new Transaction({
 *    chainID: 1,
 *    from: acc,
 *    to: "n1SAeQRVn33bamxN4ehWUT7JGdxipwn8b17",
 *    value: 10,
 *    nonce: 12,
 *    gasPrice: 1000000,
 *    gasLimit: 2000000
 * });
 */

/**
 * Represent of smart contract payload data.
 *
 * @typedef {Object} Contract
 * @property {String} source - Contract source code for deploy contract.
 * @property {String} sourceType - Contract source type for deploy contract. Currently support js and ts.
 * @property {String} args - The params of contract. The args content is JSON string of parameters array.
 * @property {String} function - The contract call function.
 * @property {Buffer} binary - Binary contract representation.
 *
 * @see [Create own smart contract in Nebulas.]{@link https://github.com/nebulasio/wiki/blob/master/tutorials/%5BEnglish%5D%20Nebulas%20101%20-%2003%20Smart%20Contracts%20JavaScript.md}
 * @see [More about transaction parameters.]{@link https://github.com/nebulasio/wiki/blob/c3f5ce8908c80e9104e3b512a7fdfd75f16ac38c/rpc.md#sendtransaction}
 *
 * @example
 * // It's example of possible fields values.
 * // For deploy, and execute smart contracts follow this link - https://github.com/nebulasio/wiki/blob/master/tutorials/%5BEnglish%5D%20Nebulas%20101%20-%2003%20Smart%20Contracts%20JavaScript.md
 * {
 *     'source': '"use strict";var DepositeContent=function(t){if(t){let n=JSON.parse(t);' +
 *               'this.balance=new BigNumber(n.balance),this.expiryHeight=new BigNumber(n.expiryHeight)' +
 *               '}else this.balance=new BigNumber(0),this.expiryHeight=new BigNumber(0)};' +
 *               'DepositeContent.prototype={toString:function(){return JSON.stringify(this)}};' +
 *               'var BankVaultContract=function(){LocalContractStorage.defineMapProperty(this,"bankVault",' +
 *               '{parse:function(t){return new DepositeContent(t)},stringify:function(t){return t.toString()}})};' +
 *               'BankVaultContract.prototype={init:function(){},save:function(t){var n=Blockchain.transaction.from,' +
 *               'e=Blockchain.transaction.value,a=new BigNumber(Blockchain.block.height),r=this.bankVault.get(n);' +
 *               'r&&(e=e.plus(r.balance));var i=new DepositeContent;i.balance=e,i.expiryHeight=a.plus(t),' +
 *               'this.bankVault.put(n,i)},takeout:function(t){var n=Blockchain.transaction.from,' +
 *               'e=new BigNumber(Blockchain.block.height),a=new BigNumber(t),r=this.bankVault.get(n);' +
 *               'if(!r)throw new Error("No deposit before.");if(e.lt(r.expiryHeight))throw new Error("Can't takeout before expiryHeight.");' +
 *               'if(a.gt(r.balance))throw new Error("Insufficient balance.");if(0!=Blockchain.transfer(n,a))throw new Error("transfer failed.");' +
 *               'Event.Trigger("BankVault",{Transfer:{from:Blockchain.transaction.to,to:n,value:a.toString()}}),' +
 *               'r.balance=r.balance.sub(a),this.bankVault.put(n,r)},balanceOf:function(){var t=Blockchain.transaction.from;' +
 *               'return this.bankVault.get(t)}},module.exports=BankVaultContract;',
 *     'sourceType': 'js',
 *     'args': '[0]',
 *     'function': 'save'
 * }
 */

/**
 * Represent Transaction parameters
 *
 * @typedef {Object} TransactionOptions
 * @property {Number} options.chainID - Transaction chain id.
 * @property {HexString} options.from - Hex string of the sender account addresss..
 * @property {HexString} options.to - Hex string of the receiver account addresss..
 * @property {Number} options.value - Value of transaction.
 * @property {Number} options.nonce - Transaction nonce.
 * @property {Number} options.gasPrice - Gas price. The unit is 10^-18 NAS.
 * @property {Number} options.gasLimit - Transaction gas limit.
 * @property {Contract} [options.contract]
 *
 * @example
 * {
*    chainID: 1,
*    from: "n1QZMXSZtW7BUerroSms4axNfyBGyFGkrh5",
*    to: "n1SAeQRVn33bamxN4ehWUT7JGdxipwn8b17",
*    value: 10,
*    nonce: 12,
*    gasPrice: 1000000,
*    gasLimit: 2000000
* }
 */

/**
 * Transaction constructor.
 * Class encapsulate main operation with transactions.
 * @see [For more information about parameters, follow this link]{@link https://github.com/nebulasio/wiki/blob/master/rpc.md#sendrawtransaction}
 * @constructor
 *
 * @param {TransactionOptions} options - Transaction options.
 *
 * @see [Transaction tutorial.]{@link https://github.com/nebulasio/wiki/blob/master/tutorials/%5BEnglish%5D%20Nebulas%20101%20-%2002%20Transaction.md}
 * @see [Create own smart contract in Nebulas.]{@link https://github.com/nebulasio/wiki/blob/master/tutorials/%5BEnglish%5D%20Nebulas%20101%20-%2003%20Smart%20Contracts%20JavaScript.md}
 * @see [More about transaction parameters.]{@link https://github.com/nebulasio/wiki/blob/c3f5ce8908c80e9104e3b512a7fdfd75f16ac38c/rpc.md#sendtransaction}
 *
 * @example
 * var acc = Account.NewAccount();
 *
 * var tx = new Transaction({
 *    chainID: 1,
 *    from: acc,
 *    to: "n1SAeQRVn33bamxN4ehWUT7JGdxipwn8b17",
 *    value: 10,
 *    nonce: 12,
 *    gasPrice: 1000000,
 *    gasLimit: 2000000,
 *    contract: {
 *        function: "save",
 *        args: "[0]"
 *    }
 * });
 *
 */
var Transaction = function (options) {
    options = utils.argumentsToObject(['chainID', 'from', 'to', 'value', 'nonce', 'gasPrice', 'gasLimit', 'contract'], arguments);

    this.chainID = options.chainID;
    this.from = account.fromAddress(options.from);
    this.to = account.fromAddress(options.to);
    this.value = utils.toBigNumber(options.value);
    this.nonce = options.nonce;
    this.timestamp = Math.floor(new Date().getTime() / 1000);
    this.contract = options.contract;
    this.gasPrice = utils.toBigNumber(options.gasPrice);
    this.gasLimit = utils.toBigNumber(options.gasLimit);

    this.data = parseContract(this.contract);
    if (this.gasPrice.lessThanOrEqualTo(0)) {
        this.gasPrice = new BigNumber(1000000);
    }

    if (this.gasLimit.lessThanOrEqualTo(0)) {
        this.gasLimit = new BigNumber(20000);
    }
    this.signErrorMessage = "You should sign transaction before this operation.";
};

var parseContract = function (obj) {
    /*jshint maxcomplexity:7 */

    var payloadType, payload;
    if (obj && utils.isString(obj.source) && obj.source.length > 0) {
        payloadType = TxPayloadDeployType;
        payload = {
            SourceType: obj.sourceType,
            Source: obj.source,
            Args: obj.args
        };
    } else if (obj && utils.isString(obj.function) && obj.function.length > 0) {
        payloadType = TxPayloadCallType;
        payload = {
            Function: obj.function,
            Args: obj.args
        };
    } else {
        payloadType = TxPayloadBinaryType;
        if (obj) {
            payload = {
                Data: cryptoUtils.toBuffer(obj.binary)
            };
        }
    }
    var payloadData = utils.isNull(payload) ? null : cryptoUtils.toBuffer(htmlescape(payload));

    return { type: payloadType, payload: payloadData };
};

Transaction.prototype = {
    /**
     * Convert transaction to hash by SHA3-256 algorithm.
     *
     * @return {Hash} hash of Transaction.
     *
     * @example
     * var acc = Account.NewAccount();
     *
     * var tx = new Transaction({
     *    chainID: 1,
     *    from: acc,
     *    to: "n1SAeQRVn33bamxN4ehWUT7JGdxipwn8b17",
     *    value: 10,
     *    nonce: 12,
     *    gasPrice: 1000000,
     *    gasLimit: 2000000
     * });
     * var txHash = tx.hashTransaction();
     * //Uint8Array(32) [211, 213, 102, 103, 23, 231, 246, 141, 20, 202, 210, 25, 92, 142, 162, 242, 232, 95, 44, 239, 45, 57, 241, 61, 34, 2, 213, 160, 17, 207, 75, 40]
     */
    hashTransaction: function () {
        var Data = root.lookup("corepb.Data");
        var err = Data.verify(this.data);
        if (err) {
            throw new Error(err);
        }
        var data = Data.create(this.data);
        var dataBuffer = Data.encode(data).finish();
        var hash = cryptoUtils.sha3(this.from.getAddress(), this.to.getAddress(), cryptoUtils.padToBigEndian(this.value, 128), cryptoUtils.padToBigEndian(this.nonce, 64), cryptoUtils.padToBigEndian(this.timestamp, 64), dataBuffer, cryptoUtils.padToBigEndian(this.chainID, 32), cryptoUtils.padToBigEndian(this.gasPrice, 128), cryptoUtils.padToBigEndian(this.gasLimit, 128));
        return hash;
    },
    /**
     * Sign transaction with the specified algorithm.
     *
     * @example
     * var acc = Account.NewAccount();
     *
     * var tx = new Transaction({
     *    chainID: 1,
     *    from: acc,
     *    to: "n1SAeQRVn33bamxN4ehWUT7JGdxipwn8b17",
     *    value: 10,
     *    nonce: 12,
     *    gasPrice: 1000000,
     *    gasLimit: 2000000
     * });
     * tx.signTransaction();
     */
    signTransaction: function () {
        if (this.from.getPrivateKey() !== null) {
            this.hash = this.hashTransaction();
            this.alg = SECP256K1;
            this.sign = cryptoUtils.sign(this.hash, this.from.getPrivateKey());
        } else {
            throw new Error("transaction from address's private key is invalid");
        }
    },
    /**
     * Conver transaction data to plain JavaScript object.
     *
     * @return {Object} Plain JavaScript object with Transaction fields.
     * @example
     * var acc = Account.NewAccount();
     * var tx = new Transaction({
     *    chainID: 1,
     *    from: acc,
     *    to: "n1SAeQRVn33bamxN4ehWUT7JGdxipwn8b17",
     *    value: 10,
     *    nonce: 12,
     *    gasPrice: 1000000,
     *    gasLimit: 2000000
     * });
     * txData = tx.toPlainObject();
     * // {chainID: 1001, from: "n1USdDKeZXQYubA44W2ZVUdW1cjiJuqswxp", to: "n1SAeQRVn33bamxN4ehWUT7JGdxipwn8b17", value: 1000000000000000000, nonce: 1, …}
     */
    toPlainObject: function () {
        return {
            chainID: this.chainID,
            from: this.from.getAddressString(),
            to: this.to.getAddressString(),
            value: utils.isBigNumber(this.value) ? this.value.toNumber() : this.value,
            nonce: this.nonce,
            gasPrice: utils.isBigNumber(this.gasPrice) ? this.gasPrice.toNumber() : this.gasPrice,
            gasLimit: utils.isBigNumber(this.gasLimit) ? this.gasLimit.toNumber() : this.gasLimit,
            contract: this.contract
        };
    },
    /**
     * Convert transaction to JSON string.
     * </br><b>Note:</b> Transaction should be [sign]{@link Transaction#signTransaction} before converting.
     *
     * @return {String} JSON stringify of transaction data.
     * @example
     * var acc = Account.NewAccount();
     *
     * var tx = new Transaction({
     *    chainID: 1,
     *    from: acc,
     *    to: "n1SAeQRVn33bamxN4ehWUT7JGdxipwn8b17",
     *    value: 10,
     *    nonce: 12,
     *    gasPrice: 1000000,
     *    gasLimit: 2000000
     * });
     * tx.signTransaction();
     * var txHash = tx.toString();
     * // "{"chainID":1001,"from":"n1QZMXSZtW7BUerroSms4axNfyBGyFGkrh5","to":"n1SAeQRVn33bamxN4ehWUT7JGdxipwn8b17","value":"1000000000000000000","nonce":1,"timestamp":1521905294,"data":{"payloadType":"binary","payload":null},"gasPrice":"1000000","gasLimit":"20000","hash":"f52668b853dd476fd309f21b22ade6bb468262f55402965c3460175b10cb2f20","alg":1,"sign":"cf30d5f61e67bbeb73bb9724ba5ba3744dcbc995521c62f9b5f43efabd9b82f10aaadf19a9cdb05f039d8bf074849ef4b508905bcdea76ae57e464e79c958fa900"}"
     */
    toString: function () {
        if (!this.sign) {
            throw new Error(this.signErrorMessage);
        }
        var payload = utils.isNull(this.data.payload) ? null : JSON.parse(this.data.payload.toString());
        var tx = {
            chainID: this.chainID,
            from: this.from.getAddressString(),
            to: this.to.getAddressString(),
            value: this.value.toString(10),
            nonce: this.nonce,
            timestamp: this.timestamp,
            data: { payloadType: this.data.type, payload: payload },
            gasPrice: this.gasPrice.toString(10),
            gasLimit: this.gasLimit.toString(10),
            hash: this.hash.toString("hex"),
            alg: this.alg,
            sign: this.sign.toString("hex")

        };
        return JSON.stringify(tx);
    },
    /**
     * Convert transaction to Protobuf format.
     * </br><b>Note:</b> Transaction should be [sign]{@link Transaction#signTransaction} before converting.
     *
     * @return {Buffer} Transaction data in Protobuf format
     *
     * @example
     * var acc = Account.NewAccount();
     *
     * var tx = new Transaction({
     *    chainID: 1,
     *    from: acc,
     *    to: "n1SAeQRVn33bamxN4ehWUT7JGdxipwn8b17",
     *    value: 10,
     *    nonce: 12,
     *    gasPrice: 1000000,
     *    gasLimit: 2000000
     * });
     * tx.signTransaction();
     * var txHash = tx.toProto();
     * // Uint8Array(127)
     */
    toProto: function () {
        if (!this.sign) {
            throw new Error(this.signErrorMessage);
        }
        var Data = root.lookup("corepb.Data");
        var err = Data.verify(this.data);
        if (err) {
            throw err;
        }
        var data = Data.create(this.data);

        var TransactionProto = root.lookup("corepb.Transaction");

        var txData = {
            hash: this.hash,
            from: this.from.getAddress(),
            to: this.to.getAddress(),
            value: cryptoUtils.padToBigEndian(this.value, 128),
            nonce: this.nonce,
            timestamp: this.timestamp,
            data: data,
            chainId: this.chainID,
            gasPrice: cryptoUtils.padToBigEndian(this.gasPrice, 128),
            gasLimit: cryptoUtils.padToBigEndian(this.gasLimit, 128),
            alg: this.alg,
            sign: this.sign
        };

        err = TransactionProto.verify(txData);
        if (err) {
            throw err;
        }
        var tx = TransactionProto.create(txData);

        var txBuffer = TransactionProto.encode(tx).finish();
        return txBuffer;
    },
    /**
     * Convert transaction to Protobuf hash string.
     * </br><b>Note:</b> Transaction should be [sign]{@link Transaction#signTransaction} before converting.
     *
     * @return {Base64} Transaction string.
     *
     * @example
     * var acc = Account.NewAccount();
     *
     * var tx = new Transaction({
     *    chainID: 1,
     *    from: acc,
     *    to: "n1SAeQRVn33bamxN4ehWUT7JGdxipwn8b17",
     *    value: 10,
     *    nonce: 12,
     *    gasPrice: 1000000,
     *    gasLimit: 2000000
     * });
     * tx.signTransaction();
     * var txHash = tx.toProtoString();
     * // "EhjZTY/gKLhWVVMZ+xoY9GiHOHJcxhc4uxkaGNlNj+AouFZVUxn7Ghj0aIc4clzGFzi7GSIQAAAAAAAAAAAN4Lazp2QAACgBMPCz6tUFOggKBmJpbmFyeUDpB0oQAAAAAAAAAAAAAAAAAA9CQFIQAAAAAAAAAAAAAAAAAABOIA=="
     */
    toProtoString: function () {
        var txBuffer = this.toProto();
        return protobuf.util.base64.encode(txBuffer, 0, txBuffer.length);
    },
    /**
     * Restore Transaction from Protobuf format.
     * @property {Buffer|String} data - Buffer or stringify Buffer.
     *
     * @return {Transaction} Restored transaction.
     *
     * @example
     * var acc = Account.NewAccount();
     *
     * var tx = new Transaction({
     *    chainID: 1,
     *    from: acc,
     *    to: "n1SAeQRVn33bamxN4ehWUT7JGdxipwn8b17",
     *    value: 10,
     *    nonce: 12,
     *    gasPrice: 1000000,
     *    gasLimit: 2000000
     * });
     * var tx = tx.fromProto("EhjZTY/gKLhWVVMZ+xoY9GiHOHJcxhc4uxkaGNlNj+AouFZVUxn7Ghj0aIc4clzGFzi7GSIQAAAAAAAAAAAN4Lazp2QAACgBMPCz6tUFOggKBmJpbmFyeUDpB0oQAAAAAAAAAAAAAAAAAA9CQFIQAAAAAAAAAAAAAAAAAABOIA==");
     */
    fromProto: function (data) {

        var txBuffer;
        if (utils.isString(data)) {
            txBuffer = new Array(protobuf.util.base64.length(data));
            protobuf.util.base64.decode(data, txBuffer, 0);
        } else {
            txBuffer = data;
        }

        var TransactionProto = root.lookup("corepb.Transaction");
        var txProto = TransactionProto.decode(txBuffer);

        this.hash = cryptoUtils.toBuffer(txProto.hash);
        this.from = account.fromAddress(txProto.from);
        this.to = account.fromAddress(txProto.to);
        this.value = utils.toBigNumber("0x" + cryptoUtils.toBuffer(txProto.value).toString("hex"));
        // long number is object, should convert to int
        this.nonce = parseInt(txProto.nonce.toString());
        this.timestamp = parseInt(txProto.timestamp.toString());
        this.data = txProto.data;
        if (this.data.payload.length === 0) {
            this.data.payload = null;
        }
        this.chainID = txProto.chainId;
        this.gasPrice = utils.toBigNumber("0x" + cryptoUtils.toBuffer(txProto.gasPrice).toString("hex"));
        this.gasLimit = utils.toBigNumber("0x" + cryptoUtils.toBuffer(txProto.gasLimit).toString("hex"));
        this.alg = txProto.alg;
        this.sign = cryptoUtils.toBuffer(txProto.sign);

        return this;
    }
};

module.exports = Transaction;

},{"./account.js":1,"./transaction.json":6,"./utils/crypto-utils.js":8,"./utils/utils.js":10,"bignumber.js":62,"htmlescape":148,"protobufjs":178}],8:[function(require,module,exports){

"use strict";

var Buffer = require('safe-buffer').Buffer;

var jsSHA = require('jssha');
var createKeccakHash = require('keccak');
var secp256k1 = require('secp256k1');
var crypto = require('crypto');
var scrypt = require('scryptsy');
var RIPEMD160 = require('ripemd160');

var uuid = require('uuid');

var utils = require('./utils.js');

var keccak = function (a, bits) {
    a = toBuffer(a);
    if (!bits) bits = 256;

    return createKeccakHash('keccak' + bits).update(a).digest();
};

var sha3 = function () {
    var shaObj = new jsSHA("SHA3-256", "HEX");
    for (var i = 0; i < arguments.length; i++) {
        var v = toBuffer(arguments[i]);
        shaObj.update(v.toString("hex"));
    }
    return Buffer.from(shaObj.getHash("HEX"), "hex");
};

var ripemd160 = function () {
    var ripemd160stream = new RIPEMD160();
    for (var i = 0; i < arguments.length; i++) {
        var v = toBuffer(arguments[i]);
        ripemd160stream.update(v);
    }
    return ripemd160stream.digest();
};

// check if hex string
var isHexPrefixed = function (str) {
    if (typeof str !== 'string') {
        throw new Error("[is-hex-prefixed] value must be type 'string', is currently type " + typeof str + ", while checking isHexPrefixed.");
    }

    return str.slice(0, 2) === '0x';
};

// returns hex string without 0x
var stripHexPrefix = function (str) {
    if (typeof str !== 'string') {
        return str;
    }
    return isHexPrefixed(str) ? str.slice(2) : str;
};

function isHexString(value, length) {
    if (typeof value !== 'string' || !value.match(/^0x[0-9A-Fa-f]*$/)) {
        return false;
    }

    if (length && value.length !== 2 + 2 * length) {
        return false;
    }

    return true;
}

// returns hex string from int
function intToHex(i) {
    var hex = i.toString(16); // eslint-disable-line

    return '0x' + padToEven(hex);
}

// returns buffer from int
function intToBuffer(i) {
    var hex = intToHex(i);

    return new Buffer(hex.slice(2), 'hex');
}

// returns a buffer filled with 0
var zeros = function (bytes) {
    return Buffer.allocUnsafe(bytes).fill(0);
};

var padToEven = function (value) {
    var a = value; // eslint-disable-line

    if (typeof a !== 'string') {
        throw new Error('padToEven only support string');
    }

    if (a.length % 2) {
        a = '0' + a;
    }

    return a;
};

// convert value to digit/8 buffer with BigEndian.
var padToBigEndian = function (value, digit) {
    value = toBuffer(value);
    var buff = Buffer.alloc(digit / 8);
    for (var i = 0; i < value.length; i++) {
        var start = buff.length - value.length + i;
        if (start >= 0) {
            buff[start] = value[i];
        }
    }
    return buff;
};

// attempts to turn a value to buffer, the input can be buffer, string,number
var toBuffer = function (v) {
    /*jshint maxcomplexity:13 */
    if (!Buffer.isBuffer(v)) {
        if (Array.isArray(v)) {
            v = Buffer.from(v);
        } else if (typeof v === 'string') {
            if (isHexString(v)) {
                v = Buffer.from(padToEven(stripHexPrefix(v)), 'hex');
            } else {
                v = Buffer.from(v);
            }
        } else if (typeof v === 'number') {
            v = intToBuffer(v);
        } else if (v === null || v === undefined) {
            v = Buffer.allocUnsafe(0);
        } else if (utils.isBigNumber(v)) {
            // TODO: neb number is a big int, not support if v is decimal, later fix it.
            v = Buffer.from(padToEven(v.toString(16)), 'hex');
        } else if (v.toArray) {
            v = Buffer.from(v.toArray());
        } else if (v.subarray) {
            v = Buffer.from(v);
        } else if (v === null || typeof v === "undefined") {
            v = Buffer.allocUnsafe(0);
        } else {
            throw new Error('invalid type');
        }
    }
    return v;
};

var bufferToHex = function (buf) {
    buf = toBuffer(buf);
    return '0x' + buf.toString('hex');
};

// convert secp256k1 private key to public key
var privateToPublic = function (privateKey) {
    privateKey = toBuffer(privateKey);
    // skip the type flag and use the X, Y points
    return secp256k1.publicKeyCreate(privateKey, false).slice(1);
};

var isValidPublic = function (publicKey, sanitize) {
    if (publicKey.length === 64) {
        // Convert to SEC1 for secp256k1
        return secp256k1.publicKeyVerify(Buffer.concat([Buffer.from([4]), publicKey]));
    }

    if (!sanitize) {
        return false;
    }

    return secp256k1.publicKeyVerify(publicKey);
};

// sign transaction hash
var sign = function (msgHash, privateKey) {

    var sig = secp256k1.sign(toBuffer(msgHash), toBuffer(privateKey));
    // var ret = {}
    // ret.r = sig.signature.slice(0, 32)
    // ret.s = sig.signature.slice(32, 64)
    // ret.v = sig.recovery
    return Buffer.concat([toBuffer(sig.signature), toBuffer(sig.recovery)]);
};

var verify = function (message, signature, publicKey) {
    return secp256k1.verify(toBuffer(message), toBuffer(signature), toBuffer(publicKey));
};

var recover = function (message, signature, recovery, compressed) {
    return secp256k1.recover(toBuffer(message), toBuffer(signature), recovery, compressed);
};

module.exports = {
    secp256k1: secp256k1,
    keccak: keccak,
    sha3: sha3,
    ripemd160: ripemd160,
    crypto: crypto,
    scrypt: scrypt,
    uuid: uuid,

    zeros: zeros,
    isHexPrefixed: isHexPrefixed,
    padToBigEndian: padToBigEndian,
    toBuffer: toBuffer,
    bufferToHex: bufferToHex,
    privateToPublic: privateToPublic,
    isValidPublic: isValidPublic,
    sign: sign,
    verify: verify,
    recover: recover
};

},{"./utils.js":10,"crypto":105,"jssha":154,"keccak":155,"ripemd160":233,"safe-buffer":234,"scryptsy":235,"secp256k1":236,"uuid":253}],9:[function(require,module,exports){

"use strict";

var BigNumber = require('bignumber.js');
var utils = require('./utils.js');

var unitMap = {
  'none': '0',
  'None': '0',
  'wei': '1',
  'Wei': '1',
  'kwei': '1000',
  'Kwei': '1000',
  'mwei': '1000000',
  'Mwei': '1000000',
  'gwei': '1000000000',
  'Gwei': '1000000000',
  'nas': '1000000000000000000',
  'NAS': '1000000000000000000'
};

var unitValue = function (unit) {
  unit = unit ? unit.toLowerCase() : 'nas';
  var unitValue = unitMap[unit];
  if (unitValue === undefined) {
    throw new Error('The unit undefined, please use the following units:' + JSON.stringify(unitMap, null, 2));
  }
  return new BigNumber(unitValue, 10);
};

var toBasic = function (number, unit) {
  return utils.toBigNumber(number).times(unitValue(unit));
};

var fromBasic = function (number, unit) {
  return utils.toBigNumber(number).dividedBy(unitValue(unit));
};

var nasToBasic = function (number) {
  return utils.toBigNumber(number).times(unitValue("nas"));
};

module.exports = {
  toBasic: toBasic,
  fromBasic: fromBasic,
  nasToBasic: nasToBasic
};

},{"./utils.js":10,"bignumber.js":62}],10:[function(require,module,exports){

"use strict";

var BigNumber = require('bignumber.js');

var isNull = function (v) {
	return v === null || typeof v === "undefined";
};

var isBrowser = function () {
	return typeof window !== "undefined";
};

var isBigNumber = function (obj) {
	return obj instanceof BigNumber || obj && obj.constructor && obj.constructor.name === 'BigNumber';
};

var isString = function (obj) {
	return typeof obj === 'string' && obj.constructor === String;
};

var isObject = function (obj) {
	return obj !== null && typeof obj === 'object';
};

var isFunction = function (object) {
	return typeof object === 'function';
};

var isNumber = function (object) {
	return typeof object === 'number';
};

var toBigNumber = function (number) {
	number = number || 0;
	if (isBigNumber(number)) {
		return number;
	}
	if (isString(number) && number.indexOf('0x') === 0) {
		return new BigNumber(number.replace('0x', ''), 16);
	}
	return new BigNumber(number.toString(10), 10);
};

var toString = function (obj) {
	if (isString(obj)) {
		return obj;
	} else if (isBigNumber(obj)) {
		return obj.toString(10);
	} else if (isObject(obj)) {
		return JSON.stringify(obj);
	} else {
		return obj + "";
	}
};

// Transform Array-like arguments object to common array.
var argumentsToArray = function (args) {
	var len = args.length,
	    resultArray = new Array(len);

	for (var i = 0; i < len; i += 1) {
		resultArray[i] = args[i];
	}
	return resultArray;
};

// Create object based on provided arrays
var zipArraysToObject = function (keysArr, valuesArr) {
	var resultObject = {};

	for (var i = 0; i < keysArr.length; i += 1) {
		resultObject[keysArr[i]] = valuesArr[i];
	}
	return resultObject;
};

// Function what make overall view for arguments.
// If arguments was provided separated by commas like "func(arg1 ,arg2)" we create
// ArgumentsObject and write keys from argsNames and value from args.
// in case wheare we provide args in object like "func({arg1: value})"
// we just return that object
var argumentsToObject = function (keys, args) {
	var ArgumentsObject = {};

	args = argumentsToArray(args);
	if (isObject(args[0])) {
		ArgumentsObject = args[0];
	} else {
		ArgumentsObject = zipArraysToObject(keys, args);
	}

	return ArgumentsObject;
};

module.exports = {
	isNull: isNull,
	isBrowser: isBrowser,
	isBigNumber: isBigNumber,
	isString: isString,
	isObject: isObject,
	isFunction: isFunction,
	isNumber: isNumber,
	toBigNumber: toBigNumber,
	toString: toString,
	argumentsToObject: argumentsToObject,
	zipArraysToObject: zipArraysToObject
};

},{"bignumber.js":62}],11:[function(require,module,exports){
<<<<<<< HEAD
"use strict";
module.exports = asPromise;

/**
 * Callback as used by {@link util.asPromise}.
 * @typedef asPromiseCallback
 * @type {function}
 * @param {Error|null} error Error, if any
 * @param {...*} params Additional arguments
 * @returns {undefined}
 */

/**
 * Returns a promise from a node-style callback function.
 * @memberof util
 * @param {asPromiseCallback} fn Function to call
 * @param {*} ctx Function context
 * @param {...*} params Function arguments
 * @returns {Promise<*>} Promisified function
 */
function asPromise(fn, ctx/*, varargs */) {
    var params  = new Array(arguments.length - 1),
        offset  = 0,
        index   = 2,
        pending = true;
    while (index < arguments.length)
        params[offset++] = arguments[index++];
    return new Promise(function executor(resolve, reject) {
        params[offset] = function callback(err/*, varargs */) {
            if (pending) {
                pending = false;
                if (err)
                    reject(err);
                else {
                    var params = new Array(arguments.length - 1),
                        offset = 0;
                    while (offset < params.length)
                        params[offset++] = arguments[offset];
                    resolve.apply(null, params);
                }
            }
        };
        try {
            fn.apply(ctx || null, params);
        } catch (err) {
            if (pending) {
                pending = false;
                reject(err);
            }
        }
    });
}

},{}],12:[function(require,module,exports){
"use strict";

/**
 * A minimal base64 implementation for number arrays.
 * @memberof util
 * @namespace
 */
var base64 = exports;

/**
 * Calculates the byte length of a base64 encoded string.
 * @param {string} string Base64 encoded string
 * @returns {number} Byte length
 */
base64.length = function length(string) {
    var p = string.length;
    if (!p)
        return 0;
    var n = 0;
    while (--p % 4 > 1 && string.charAt(p) === "=")
        ++n;
    return Math.ceil(string.length * 3) / 4 - n;
};

// Base64 encoding table
var b64 = new Array(64);

// Base64 decoding table
var s64 = new Array(123);

// 65..90, 97..122, 48..57, 43, 47
for (var i = 0; i < 64;)
    s64[b64[i] = i < 26 ? i + 65 : i < 52 ? i + 71 : i < 62 ? i - 4 : i - 59 | 43] = i++;

/**
 * Encodes a buffer to a base64 encoded string.
 * @param {Uint8Array} buffer Source buffer
 * @param {number} start Source start
 * @param {number} end Source end
 * @returns {string} Base64 encoded string
 */
base64.encode = function encode(buffer, start, end) {
    var parts = null,
        chunk = [];
    var i = 0, // output index
        j = 0, // goto index
        t;     // temporary
    while (start < end) {
        var b = buffer[start++];
        switch (j) {
            case 0:
                chunk[i++] = b64[b >> 2];
                t = (b & 3) << 4;
                j = 1;
                break;
            case 1:
                chunk[i++] = b64[t | b >> 4];
                t = (b & 15) << 2;
                j = 2;
                break;
            case 2:
                chunk[i++] = b64[t | b >> 6];
                chunk[i++] = b64[b & 63];
                j = 0;
                break;
        }
        if (i > 8191) {
            (parts || (parts = [])).push(String.fromCharCode.apply(String, chunk));
            i = 0;
        }
    }
    if (j) {
        chunk[i++] = b64[t];
        chunk[i++] = 61;
        if (j === 1)
            chunk[i++] = 61;
    }
    if (parts) {
        if (i)
            parts.push(String.fromCharCode.apply(String, chunk.slice(0, i)));
        return parts.join("");
    }
    return String.fromCharCode.apply(String, chunk.slice(0, i));
};

var invalidEncoding = "invalid encoding";

/**
 * Decodes a base64 encoded string to a buffer.
 * @param {string} string Source string
 * @param {Uint8Array} buffer Destination buffer
 * @param {number} offset Destination offset
 * @returns {number} Number of bytes written
 * @throws {Error} If encoding is invalid
 */
base64.decode = function decode(string, buffer, offset) {
    var start = offset;
    var j = 0, // goto index
        t;     // temporary
    for (var i = 0; i < string.length;) {
        var c = string.charCodeAt(i++);
        if (c === 61 && j > 1)
            break;
        if ((c = s64[c]) === undefined)
            throw Error(invalidEncoding);
        switch (j) {
            case 0:
                t = c;
                j = 1;
                break;
            case 1:
                buffer[offset++] = t << 2 | (c & 48) >> 4;
                t = c;
                j = 2;
                break;
            case 2:
                buffer[offset++] = (t & 15) << 4 | (c & 60) >> 2;
                t = c;
                j = 3;
                break;
            case 3:
                buffer[offset++] = (t & 3) << 6 | c;
                j = 0;
                break;
        }
    }
    if (j === 1)
        throw Error(invalidEncoding);
    return offset - start;
};

/**
 * Tests if the specified string appears to be base64 encoded.
 * @param {string} string String to test
 * @returns {boolean} `true` if probably base64 encoded, otherwise false
 */
base64.test = function test(string) {
    return /^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/.test(string);
};

},{}],13:[function(require,module,exports){
"use strict";
module.exports = codegen;

/**
 * Begins generating a function.
 * @memberof util
 * @param {string[]} functionParams Function parameter names
 * @param {string} [functionName] Function name if not anonymous
 * @returns {Codegen} Appender that appends code to the function's body
 */
function codegen(functionParams, functionName) {

    /* istanbul ignore if */
    if (typeof functionParams === "string") {
        functionName = functionParams;
        functionParams = undefined;
    }

    var body = [];

    /**
     * Appends code to the function's body or finishes generation.
     * @typedef Codegen
     * @type {function}
     * @param {string|Object.<string,*>} [formatStringOrScope] Format string or, to finish the function, an object of additional scope variables, if any
     * @param {...*} [formatParams] Format parameters
     * @returns {Codegen|Function} Itself or the generated function if finished
     * @throws {Error} If format parameter counts do not match
     */

    function Codegen(formatStringOrScope) {
        // note that explicit array handling below makes this ~50% faster

        // finish the function
        if (typeof formatStringOrScope !== "string") {
            var source = toString();
            if (codegen.verbose)
                console.log("codegen: " + source); // eslint-disable-line no-console
            source = "return " + source;
            if (formatStringOrScope) {
                var scopeKeys   = Object.keys(formatStringOrScope),
                    scopeParams = new Array(scopeKeys.length + 1),
                    scopeValues = new Array(scopeKeys.length),
                    scopeOffset = 0;
                while (scopeOffset < scopeKeys.length) {
                    scopeParams[scopeOffset] = scopeKeys[scopeOffset];
                    scopeValues[scopeOffset] = formatStringOrScope[scopeKeys[scopeOffset++]];
                }
                scopeParams[scopeOffset] = source;
                return Function.apply(null, scopeParams).apply(null, scopeValues); // eslint-disable-line no-new-func
            }
            return Function(source)(); // eslint-disable-line no-new-func
        }

        // otherwise append to body
        var formatParams = new Array(arguments.length - 1),
            formatOffset = 0;
        while (formatOffset < formatParams.length)
            formatParams[formatOffset] = arguments[++formatOffset];
        formatOffset = 0;
        formatStringOrScope = formatStringOrScope.replace(/%([%dfijs])/g, function replace($0, $1) {
            var value = formatParams[formatOffset++];
            switch ($1) {
                case "d": case "f": return String(Number(value));
                case "i": return String(Math.floor(value));
                case "j": return JSON.stringify(value);
                case "s": return String(value);
            }
            return "%";
        });
        if (formatOffset !== formatParams.length)
            throw Error("parameter count mismatch");
        body.push(formatStringOrScope);
        return Codegen;
    }

    function toString(functionNameOverride) {
        return "function " + (functionNameOverride || functionName || "") + "(" + (functionParams && functionParams.join(",") || "") + "){\n  " + body.join("\n  ") + "\n}";
    }

    Codegen.toString = toString;
    return Codegen;
}

/**
 * Begins generating a function.
 * @memberof util
 * @function codegen
 * @param {string} [functionName] Function name if not anonymous
 * @returns {Codegen} Appender that appends code to the function's body
 * @variation 2
 */

/**
 * When set to `true`, codegen will log generated code to console. Useful for debugging.
 * @name util.codegen.verbose
 * @type {boolean}
 */
codegen.verbose = false;

},{}],14:[function(require,module,exports){
"use strict";
module.exports = EventEmitter;

/**
 * Constructs a new event emitter instance.
 * @classdesc A minimal event emitter.
 * @memberof util
 * @constructor
 */
function EventEmitter() {

    /**
     * Registered listeners.
     * @type {Object.<string,*>}
     * @private
     */
    this._listeners = {};
}

/**
 * Registers an event listener.
 * @param {string} evt Event name
 * @param {function} fn Listener
 * @param {*} [ctx] Listener context
 * @returns {util.EventEmitter} `this`
 */
EventEmitter.prototype.on = function on(evt, fn, ctx) {
    (this._listeners[evt] || (this._listeners[evt] = [])).push({
        fn  : fn,
        ctx : ctx || this
    });
    return this;
};

/**
 * Removes an event listener or any matching listeners if arguments are omitted.
 * @param {string} [evt] Event name. Removes all listeners if omitted.
 * @param {function} [fn] Listener to remove. Removes all listeners of `evt` if omitted.
 * @returns {util.EventEmitter} `this`
 */
EventEmitter.prototype.off = function off(evt, fn) {
    if (evt === undefined)
        this._listeners = {};
    else {
        if (fn === undefined)
            this._listeners[evt] = [];
        else {
            var listeners = this._listeners[evt];
            for (var i = 0; i < listeners.length;)
                if (listeners[i].fn === fn)
                    listeners.splice(i, 1);
                else
                    ++i;
        }
    }
    return this;
};

/**
 * Emits an event by calling its listeners with the specified arguments.
 * @param {string} evt Event name
 * @param {...*} args Arguments
 * @returns {util.EventEmitter} `this`
 */
EventEmitter.prototype.emit = function emit(evt) {
    var listeners = this._listeners[evt];
    if (listeners) {
        var args = [],
            i = 1;
        for (; i < arguments.length;)
            args.push(arguments[i++]);
        for (i = 0; i < listeners.length;)
            listeners[i].fn.apply(listeners[i++].ctx, args);
    }
    return this;
};

},{}],15:[function(require,module,exports){
"use strict";
module.exports = fetch;

var asPromise = require("@protobufjs/aspromise"),
    inquire   = require("@protobufjs/inquire");

var fs = inquire("fs");

/**
 * Node-style callback as used by {@link util.fetch}.
 * @typedef FetchCallback
 * @type {function}
 * @param {?Error} error Error, if any, otherwise `null`
 * @param {string} [contents] File contents, if there hasn't been an error
 * @returns {undefined}
 */

/**
 * Options as used by {@link util.fetch}.
 * @typedef FetchOptions
 * @type {Object}
 * @property {boolean} [binary=false] Whether expecting a binary response
 * @property {boolean} [xhr=false] If `true`, forces the use of XMLHttpRequest
 */

/**
 * Fetches the contents of a file.
 * @memberof util
 * @param {string} filename File path or url
 * @param {FetchOptions} options Fetch options
 * @param {FetchCallback} callback Callback function
 * @returns {undefined}
 */
function fetch(filename, options, callback) {
    if (typeof options === "function") {
        callback = options;
        options = {};
    } else if (!options)
        options = {};

    if (!callback)
        return asPromise(fetch, this, filename, options); // eslint-disable-line no-invalid-this

    // if a node-like filesystem is present, try it first but fall back to XHR if nothing is found.
    if (!options.xhr && fs && fs.readFile)
        return fs.readFile(filename, function fetchReadFileCallback(err, contents) {
            return err && typeof XMLHttpRequest !== "undefined"
                ? fetch.xhr(filename, options, callback)
                : err
                ? callback(err)
                : callback(null, options.binary ? contents : contents.toString("utf8"));
        });

    // use the XHR version otherwise.
    return fetch.xhr(filename, options, callback);
}

/**
 * Fetches the contents of a file.
 * @name util.fetch
 * @function
 * @param {string} path File path or url
 * @param {FetchCallback} callback Callback function
 * @returns {undefined}
 * @variation 2
 */

/**
 * Fetches the contents of a file.
 * @name util.fetch
 * @function
 * @param {string} path File path or url
 * @param {FetchOptions} [options] Fetch options
 * @returns {Promise<string|Uint8Array>} Promise
 * @variation 3
 */

/**/
fetch.xhr = function fetch_xhr(filename, options, callback) {
    var xhr = new XMLHttpRequest();
    xhr.onreadystatechange /* works everywhere */ = function fetchOnReadyStateChange() {

        if (xhr.readyState !== 4)
            return undefined;

        // local cors security errors return status 0 / empty string, too. afaik this cannot be
        // reliably distinguished from an actually empty file for security reasons. feel free
        // to send a pull request if you are aware of a solution.
        if (xhr.status !== 0 && xhr.status !== 200)
            return callback(Error("status " + xhr.status));

        // if binary data is expected, make sure that some sort of array is returned, even if
        // ArrayBuffers are not supported. the binary string fallback, however, is unsafe.
        if (options.binary) {
            var buffer = xhr.response;
            if (!buffer) {
                buffer = [];
                for (var i = 0; i < xhr.responseText.length; ++i)
                    buffer.push(xhr.responseText.charCodeAt(i) & 255);
            }
            return callback(null, typeof Uint8Array !== "undefined" ? new Uint8Array(buffer) : buffer);
        }
        return callback(null, xhr.responseText);
    };

    if (options.binary) {
        // ref: https://developer.mozilla.org/en-US/docs/Web/API/XMLHttpRequest/Sending_and_Receiving_Binary_Data#Receiving_binary_data_in_older_browsers
        if ("overrideMimeType" in xhr)
            xhr.overrideMimeType("text/plain; charset=x-user-defined");
        xhr.responseType = "arraybuffer";
    }

    xhr.open("GET", filename);
    xhr.send();
};

},{"@protobufjs/aspromise":11,"@protobufjs/inquire":17}],16:[function(require,module,exports){
"use strict";

module.exports = factory(factory);

/**
 * Reads / writes floats / doubles from / to buffers.
 * @name util.float
 * @namespace
 */

/**
 * Writes a 32 bit float to a buffer using little endian byte order.
 * @name util.float.writeFloatLE
 * @function
 * @param {number} val Value to write
 * @param {Uint8Array} buf Target buffer
 * @param {number} pos Target buffer offset
 * @returns {undefined}
 */

/**
 * Writes a 32 bit float to a buffer using big endian byte order.
 * @name util.float.writeFloatBE
 * @function
 * @param {number} val Value to write
 * @param {Uint8Array} buf Target buffer
 * @param {number} pos Target buffer offset
 * @returns {undefined}
 */

/**
 * Reads a 32 bit float from a buffer using little endian byte order.
 * @name util.float.readFloatLE
 * @function
 * @param {Uint8Array} buf Source buffer
 * @param {number} pos Source buffer offset
 * @returns {number} Value read
 */

/**
 * Reads a 32 bit float from a buffer using big endian byte order.
 * @name util.float.readFloatBE
 * @function
 * @param {Uint8Array} buf Source buffer
 * @param {number} pos Source buffer offset
 * @returns {number} Value read
 */

/**
 * Writes a 64 bit double to a buffer using little endian byte order.
 * @name util.float.writeDoubleLE
 * @function
 * @param {number} val Value to write
 * @param {Uint8Array} buf Target buffer
 * @param {number} pos Target buffer offset
 * @returns {undefined}
 */

/**
 * Writes a 64 bit double to a buffer using big endian byte order.
 * @name util.float.writeDoubleBE
 * @function
 * @param {number} val Value to write
 * @param {Uint8Array} buf Target buffer
 * @param {number} pos Target buffer offset
 * @returns {undefined}
 */

/**
 * Reads a 64 bit double from a buffer using little endian byte order.
 * @name util.float.readDoubleLE
 * @function
 * @param {Uint8Array} buf Source buffer
 * @param {number} pos Source buffer offset
 * @returns {number} Value read
 */

/**
 * Reads a 64 bit double from a buffer using big endian byte order.
 * @name util.float.readDoubleBE
 * @function
 * @param {Uint8Array} buf Source buffer
 * @param {number} pos Source buffer offset
 * @returns {number} Value read
 */

// Factory function for the purpose of node-based testing in modified global environments
function factory(exports) {

    // float: typed array
    if (typeof Float32Array !== "undefined") (function() {

        var f32 = new Float32Array([ -0 ]),
            f8b = new Uint8Array(f32.buffer),
            le  = f8b[3] === 128;

        function writeFloat_f32_cpy(val, buf, pos) {
            f32[0] = val;
            buf[pos    ] = f8b[0];
            buf[pos + 1] = f8b[1];
            buf[pos + 2] = f8b[2];
            buf[pos + 3] = f8b[3];
        }

        function writeFloat_f32_rev(val, buf, pos) {
            f32[0] = val;
            buf[pos    ] = f8b[3];
            buf[pos + 1] = f8b[2];
            buf[pos + 2] = f8b[1];
            buf[pos + 3] = f8b[0];
        }

        /* istanbul ignore next */
        exports.writeFloatLE = le ? writeFloat_f32_cpy : writeFloat_f32_rev;
        /* istanbul ignore next */
        exports.writeFloatBE = le ? writeFloat_f32_rev : writeFloat_f32_cpy;

        function readFloat_f32_cpy(buf, pos) {
            f8b[0] = buf[pos    ];
            f8b[1] = buf[pos + 1];
            f8b[2] = buf[pos + 2];
            f8b[3] = buf[pos + 3];
            return f32[0];
        }

        function readFloat_f32_rev(buf, pos) {
            f8b[3] = buf[pos    ];
            f8b[2] = buf[pos + 1];
            f8b[1] = buf[pos + 2];
            f8b[0] = buf[pos + 3];
            return f32[0];
        }

        /* istanbul ignore next */
        exports.readFloatLE = le ? readFloat_f32_cpy : readFloat_f32_rev;
        /* istanbul ignore next */
        exports.readFloatBE = le ? readFloat_f32_rev : readFloat_f32_cpy;

    // float: ieee754
    })(); else (function() {

        function writeFloat_ieee754(writeUint, val, buf, pos) {
            var sign = val < 0 ? 1 : 0;
            if (sign)
                val = -val;
            if (val === 0)
                writeUint(1 / val > 0 ? /* positive */ 0 : /* negative 0 */ 2147483648, buf, pos);
            else if (isNaN(val))
                writeUint(2143289344, buf, pos);
            else if (val > 3.4028234663852886e+38) // +-Infinity
                writeUint((sign << 31 | 2139095040) >>> 0, buf, pos);
            else if (val < 1.1754943508222875e-38) // denormal
                writeUint((sign << 31 | Math.round(val / 1.401298464324817e-45)) >>> 0, buf, pos);
            else {
                var exponent = Math.floor(Math.log(val) / Math.LN2),
                    mantissa = Math.round(val * Math.pow(2, -exponent) * 8388608) & 8388607;
                writeUint((sign << 31 | exponent + 127 << 23 | mantissa) >>> 0, buf, pos);
            }
        }

        exports.writeFloatLE = writeFloat_ieee754.bind(null, writeUintLE);
        exports.writeFloatBE = writeFloat_ieee754.bind(null, writeUintBE);

        function readFloat_ieee754(readUint, buf, pos) {
            var uint = readUint(buf, pos),
                sign = (uint >> 31) * 2 + 1,
                exponent = uint >>> 23 & 255,
                mantissa = uint & 8388607;
            return exponent === 255
                ? mantissa
                ? NaN
                : sign * Infinity
                : exponent === 0 // denormal
                ? sign * 1.401298464324817e-45 * mantissa
                : sign * Math.pow(2, exponent - 150) * (mantissa + 8388608);
        }

        exports.readFloatLE = readFloat_ieee754.bind(null, readUintLE);
        exports.readFloatBE = readFloat_ieee754.bind(null, readUintBE);

    })();

    // double: typed array
    if (typeof Float64Array !== "undefined") (function() {

        var f64 = new Float64Array([-0]),
            f8b = new Uint8Array(f64.buffer),
            le  = f8b[7] === 128;

        function writeDouble_f64_cpy(val, buf, pos) {
            f64[0] = val;
            buf[pos    ] = f8b[0];
            buf[pos + 1] = f8b[1];
            buf[pos + 2] = f8b[2];
            buf[pos + 3] = f8b[3];
            buf[pos + 4] = f8b[4];
            buf[pos + 5] = f8b[5];
            buf[pos + 6] = f8b[6];
            buf[pos + 7] = f8b[7];
        }

        function writeDouble_f64_rev(val, buf, pos) {
            f64[0] = val;
            buf[pos    ] = f8b[7];
            buf[pos + 1] = f8b[6];
            buf[pos + 2] = f8b[5];
            buf[pos + 3] = f8b[4];
            buf[pos + 4] = f8b[3];
            buf[pos + 5] = f8b[2];
            buf[pos + 6] = f8b[1];
            buf[pos + 7] = f8b[0];
        }

        /* istanbul ignore next */
        exports.writeDoubleLE = le ? writeDouble_f64_cpy : writeDouble_f64_rev;
        /* istanbul ignore next */
        exports.writeDoubleBE = le ? writeDouble_f64_rev : writeDouble_f64_cpy;

        function readDouble_f64_cpy(buf, pos) {
            f8b[0] = buf[pos    ];
            f8b[1] = buf[pos + 1];
            f8b[2] = buf[pos + 2];
            f8b[3] = buf[pos + 3];
            f8b[4] = buf[pos + 4];
            f8b[5] = buf[pos + 5];
            f8b[6] = buf[pos + 6];
            f8b[7] = buf[pos + 7];
            return f64[0];
        }

        function readDouble_f64_rev(buf, pos) {
            f8b[7] = buf[pos    ];
            f8b[6] = buf[pos + 1];
            f8b[5] = buf[pos + 2];
            f8b[4] = buf[pos + 3];
            f8b[3] = buf[pos + 4];
            f8b[2] = buf[pos + 5];
            f8b[1] = buf[pos + 6];
            f8b[0] = buf[pos + 7];
            return f64[0];
        }

        /* istanbul ignore next */
        exports.readDoubleLE = le ? readDouble_f64_cpy : readDouble_f64_rev;
        /* istanbul ignore next */
        exports.readDoubleBE = le ? readDouble_f64_rev : readDouble_f64_cpy;

    // double: ieee754
    })(); else (function() {

        function writeDouble_ieee754(writeUint, off0, off1, val, buf, pos) {
            var sign = val < 0 ? 1 : 0;
            if (sign)
                val = -val;
            if (val === 0) {
                writeUint(0, buf, pos + off0);
                writeUint(1 / val > 0 ? /* positive */ 0 : /* negative 0 */ 2147483648, buf, pos + off1);
            } else if (isNaN(val)) {
                writeUint(0, buf, pos + off0);
                writeUint(2146959360, buf, pos + off1);
            } else if (val > 1.7976931348623157e+308) { // +-Infinity
                writeUint(0, buf, pos + off0);
                writeUint((sign << 31 | 2146435072) >>> 0, buf, pos + off1);
            } else {
                var mantissa;
                if (val < 2.2250738585072014e-308) { // denormal
                    mantissa = val / 5e-324;
                    writeUint(mantissa >>> 0, buf, pos + off0);
                    writeUint((sign << 31 | mantissa / 4294967296) >>> 0, buf, pos + off1);
                } else {
                    var exponent = Math.floor(Math.log(val) / Math.LN2);
                    if (exponent === 1024)
                        exponent = 1023;
                    mantissa = val * Math.pow(2, -exponent);
                    writeUint(mantissa * 4503599627370496 >>> 0, buf, pos + off0);
                    writeUint((sign << 31 | exponent + 1023 << 20 | mantissa * 1048576 & 1048575) >>> 0, buf, pos + off1);
                }
            }
        }

        exports.writeDoubleLE = writeDouble_ieee754.bind(null, writeUintLE, 0, 4);
        exports.writeDoubleBE = writeDouble_ieee754.bind(null, writeUintBE, 4, 0);

        function readDouble_ieee754(readUint, off0, off1, buf, pos) {
            var lo = readUint(buf, pos + off0),
                hi = readUint(buf, pos + off1);
            var sign = (hi >> 31) * 2 + 1,
                exponent = hi >>> 20 & 2047,
                mantissa = 4294967296 * (hi & 1048575) + lo;
            return exponent === 2047
                ? mantissa
                ? NaN
                : sign * Infinity
                : exponent === 0 // denormal
                ? sign * 5e-324 * mantissa
                : sign * Math.pow(2, exponent - 1075) * (mantissa + 4503599627370496);
        }

        exports.readDoubleLE = readDouble_ieee754.bind(null, readUintLE, 0, 4);
        exports.readDoubleBE = readDouble_ieee754.bind(null, readUintBE, 4, 0);

    })();

    return exports;
}

// uint helpers

function writeUintLE(val, buf, pos) {
    buf[pos    ] =  val        & 255;
    buf[pos + 1] =  val >>> 8  & 255;
    buf[pos + 2] =  val >>> 16 & 255;
    buf[pos + 3] =  val >>> 24;
}

function writeUintBE(val, buf, pos) {
    buf[pos    ] =  val >>> 24;
    buf[pos + 1] =  val >>> 16 & 255;
    buf[pos + 2] =  val >>> 8  & 255;
    buf[pos + 3] =  val        & 255;
}

function readUintLE(buf, pos) {
    return (buf[pos    ]
          | buf[pos + 1] << 8
          | buf[pos + 2] << 16
          | buf[pos + 3] << 24) >>> 0;
}

function readUintBE(buf, pos) {
    return (buf[pos    ] << 24
          | buf[pos + 1] << 16
          | buf[pos + 2] << 8
          | buf[pos + 3]) >>> 0;
}

},{}],17:[function(require,module,exports){
"use strict";
module.exports = inquire;

/**
 * Requires a module only if available.
 * @memberof util
 * @param {string} moduleName Module to require
 * @returns {?Object} Required module if available and not empty, otherwise `null`
 */
function inquire(moduleName) {
    try {
        var mod = eval("quire".replace(/^/,"re"))(moduleName); // eslint-disable-line no-eval
        if (mod && (mod.length || Object.keys(mod).length))
            return mod;
    } catch (e) {} // eslint-disable-line no-empty
    return null;
}

},{}],18:[function(require,module,exports){
"use strict";

/**
 * A minimal path module to resolve Unix, Windows and URL paths alike.
 * @memberof util
 * @namespace
 */
var path = exports;

var isAbsolute =
/**
 * Tests if the specified path is absolute.
 * @param {string} path Path to test
 * @returns {boolean} `true` if path is absolute
 */
path.isAbsolute = function isAbsolute(path) {
    return /^(?:\/|\w+:)/.test(path);
};

var normalize =
/**
 * Normalizes the specified path.
 * @param {string} path Path to normalize
 * @returns {string} Normalized path
 */
path.normalize = function normalize(path) {
    path = path.replace(/\\/g, "/")
               .replace(/\/{2,}/g, "/");
    var parts    = path.split("/"),
        absolute = isAbsolute(path),
        prefix   = "";
    if (absolute)
        prefix = parts.shift() + "/";
    for (var i = 0; i < parts.length;) {
        if (parts[i] === "..") {
            if (i > 0 && parts[i - 1] !== "..")
                parts.splice(--i, 2);
            else if (absolute)
                parts.splice(i, 1);
            else
                ++i;
        } else if (parts[i] === ".")
            parts.splice(i, 1);
        else
            ++i;
    }
    return prefix + parts.join("/");
};

/**
 * Resolves the specified include path against the specified origin path.
 * @param {string} originPath Path to the origin file
 * @param {string} includePath Include path relative to origin path
 * @param {boolean} [alreadyNormalized=false] `true` if both paths are already known to be normalized
 * @returns {string} Path to the include file
 */
path.resolve = function resolve(originPath, includePath, alreadyNormalized) {
    if (!alreadyNormalized)
        includePath = normalize(includePath);
    if (isAbsolute(includePath))
        return includePath;
    if (!alreadyNormalized)
        originPath = normalize(originPath);
    return (originPath = originPath.replace(/(?:\/|^)[^/]+$/, "")).length ? normalize(originPath + "/" + includePath) : includePath;
};

},{}],19:[function(require,module,exports){
"use strict";
module.exports = pool;

/**
 * An allocator as used by {@link util.pool}.
 * @typedef PoolAllocator
 * @type {function}
 * @param {number} size Buffer size
 * @returns {Uint8Array} Buffer
 */

/**
 * A slicer as used by {@link util.pool}.
 * @typedef PoolSlicer
 * @type {function}
 * @param {number} start Start offset
 * @param {number} end End offset
 * @returns {Uint8Array} Buffer slice
 * @this {Uint8Array}
 */

/**
 * A general purpose buffer pool.
 * @memberof util
 * @function
 * @param {PoolAllocator} alloc Allocator
 * @param {PoolSlicer} slice Slicer
 * @param {number} [size=8192] Slab size
 * @returns {PoolAllocator} Pooled allocator
 */
function pool(alloc, slice, size) {
    var SIZE   = size || 8192;
    var MAX    = SIZE >>> 1;
    var slab   = null;
    var offset = SIZE;
    return function pool_alloc(size) {
        if (size < 1 || size > MAX)
            return alloc(size);
        if (offset + size > SIZE) {
            slab = alloc(SIZE);
            offset = 0;
        }
        var buf = slice.call(slab, offset, offset += size);
        if (offset & 7) // align to 32 bit
            offset = (offset | 7) + 1;
        return buf;
    };
}

},{}],20:[function(require,module,exports){
"use strict";

/**
 * A minimal UTF8 implementation for number arrays.
 * @memberof util
 * @namespace
 */
var utf8 = exports;

/**
 * Calculates the UTF8 byte length of a string.
 * @param {string} string String
 * @returns {number} Byte length
 */
utf8.length = function utf8_length(string) {
    var len = 0,
        c = 0;
    for (var i = 0; i < string.length; ++i) {
        c = string.charCodeAt(i);
        if (c < 128)
            len += 1;
        else if (c < 2048)
            len += 2;
        else if ((c & 0xFC00) === 0xD800 && (string.charCodeAt(i + 1) & 0xFC00) === 0xDC00) {
            ++i;
            len += 4;
        } else
            len += 3;
    }
    return len;
};

/**
 * Reads UTF8 bytes as a string.
 * @param {Uint8Array} buffer Source buffer
 * @param {number} start Source start
 * @param {number} end Source end
 * @returns {string} String read
 */
utf8.read = function utf8_read(buffer, start, end) {
    var len = end - start;
    if (len < 1)
        return "";
    var parts = null,
        chunk = [],
        i = 0, // char offset
        t;     // temporary
    while (start < end) {
        t = buffer[start++];
        if (t < 128)
            chunk[i++] = t;
        else if (t > 191 && t < 224)
            chunk[i++] = (t & 31) << 6 | buffer[start++] & 63;
        else if (t > 239 && t < 365) {
            t = ((t & 7) << 18 | (buffer[start++] & 63) << 12 | (buffer[start++] & 63) << 6 | buffer[start++] & 63) - 0x10000;
            chunk[i++] = 0xD800 + (t >> 10);
            chunk[i++] = 0xDC00 + (t & 1023);
        } else
            chunk[i++] = (t & 15) << 12 | (buffer[start++] & 63) << 6 | buffer[start++] & 63;
        if (i > 8191) {
            (parts || (parts = [])).push(String.fromCharCode.apply(String, chunk));
            i = 0;
        }
    }
    if (parts) {
        if (i)
            parts.push(String.fromCharCode.apply(String, chunk.slice(0, i)));
        return parts.join("");
    }
    return String.fromCharCode.apply(String, chunk.slice(0, i));
};

/**
 * Writes a string as UTF8 bytes.
 * @param {string} string Source string
 * @param {Uint8Array} buffer Destination buffer
 * @param {number} offset Destination offset
 * @returns {number} Bytes written
 */
utf8.write = function utf8_write(string, buffer, offset) {
    var start = offset,
        c1, // character 1
        c2; // character 2
    for (var i = 0; i < string.length; ++i) {
        c1 = string.charCodeAt(i);
        if (c1 < 128) {
            buffer[offset++] = c1;
        } else if (c1 < 2048) {
            buffer[offset++] = c1 >> 6       | 192;
            buffer[offset++] = c1       & 63 | 128;
        } else if ((c1 & 0xFC00) === 0xD800 && ((c2 = string.charCodeAt(i + 1)) & 0xFC00) === 0xDC00) {
            c1 = 0x10000 + ((c1 & 0x03FF) << 10) + (c2 & 0x03FF);
            ++i;
            buffer[offset++] = c1 >> 18      | 240;
            buffer[offset++] = c1 >> 12 & 63 | 128;
            buffer[offset++] = c1 >> 6  & 63 | 128;
            buffer[offset++] = c1       & 63 | 128;
        } else {
            buffer[offset++] = c1 >> 12      | 224;
            buffer[offset++] = c1 >> 6  & 63 | 128;
            buffer[offset++] = c1       & 63 | 128;
        }
    }
    return offset - start;
};

},{}],21:[function(require,module,exports){
var asn1 = exports;

asn1.bignum = require('bn.js');

asn1.define = require('./asn1/api').define;
asn1.base = require('./asn1/base');
asn1.constants = require('./asn1/constants');
asn1.decoders = require('./asn1/decoders');
asn1.encoders = require('./asn1/encoders');

},{"./asn1/api":22,"./asn1/base":24,"./asn1/constants":28,"./asn1/decoders":30,"./asn1/encoders":33,"bn.js":64}],22:[function(require,module,exports){
var asn1 = require('../asn1');
var inherits = require('inherits');

var api = exports;

api.define = function define(name, body) {
  return new Entity(name, body);
};

function Entity(name, body) {
  this.name = name;
  this.body = body;

  this.decoders = {};
  this.encoders = {};
};

Entity.prototype._createNamed = function createNamed(base) {
  var named;
  try {
    named = require('vm').runInThisContext(
      '(function ' + this.name + '(entity) {\n' +
      '  this._initNamed(entity);\n' +
      '})'
    );
  } catch (e) {
    named = function (entity) {
      this._initNamed(entity);
    };
  }
  inherits(named, base);
  named.prototype._initNamed = function initnamed(entity) {
    base.call(this, entity);
  };

  return new named(this);
};

Entity.prototype._getDecoder = function _getDecoder(enc) {
  enc = enc || 'der';
  // Lazily create decoder
  if (!this.decoders.hasOwnProperty(enc))
    this.decoders[enc] = this._createNamed(asn1.decoders[enc]);
  return this.decoders[enc];
};

Entity.prototype.decode = function decode(data, enc, options) {
  return this._getDecoder(enc).decode(data, options);
};

Entity.prototype._getEncoder = function _getEncoder(enc) {
  enc = enc || 'der';
  // Lazily create encoder
  if (!this.encoders.hasOwnProperty(enc))
    this.encoders[enc] = this._createNamed(asn1.encoders[enc]);
  return this.encoders[enc];
};

Entity.prototype.encode = function encode(data, enc, /* internal */ reporter) {
  return this._getEncoder(enc).encode(data, reporter);
};

},{"../asn1":21,"inherits":151,"vm":258}],23:[function(require,module,exports){
var inherits = require('inherits');
var Reporter = require('../base').Reporter;
var Buffer = require('buffer').Buffer;

function DecoderBuffer(base, options) {
  Reporter.call(this, options);
  if (!Buffer.isBuffer(base)) {
    this.error('Input not Buffer');
    return;
  }

  this.base = base;
  this.offset = 0;
  this.length = base.length;
}
inherits(DecoderBuffer, Reporter);
exports.DecoderBuffer = DecoderBuffer;

DecoderBuffer.prototype.save = function save() {
  return { offset: this.offset, reporter: Reporter.prototype.save.call(this) };
};

DecoderBuffer.prototype.restore = function restore(save) {
  // Return skipped data
  var res = new DecoderBuffer(this.base);
  res.offset = save.offset;
  res.length = this.offset;

  this.offset = save.offset;
  Reporter.prototype.restore.call(this, save.reporter);

  return res;
};

DecoderBuffer.prototype.isEmpty = function isEmpty() {
  return this.offset === this.length;
};

DecoderBuffer.prototype.readUInt8 = function readUInt8(fail) {
  if (this.offset + 1 <= this.length)
    return this.base.readUInt8(this.offset++, true);
  else
    return this.error(fail || 'DecoderBuffer overrun');
}

DecoderBuffer.prototype.skip = function skip(bytes, fail) {
  if (!(this.offset + bytes <= this.length))
    return this.error(fail || 'DecoderBuffer overrun');

  var res = new DecoderBuffer(this.base);

  // Share reporter state
  res._reporterState = this._reporterState;

  res.offset = this.offset;
  res.length = this.offset + bytes;
  this.offset += bytes;
  return res;
}

DecoderBuffer.prototype.raw = function raw(save) {
  return this.base.slice(save ? save.offset : this.offset, this.length);
}

function EncoderBuffer(value, reporter) {
  if (Array.isArray(value)) {
    this.length = 0;
    this.value = value.map(function(item) {
      if (!(item instanceof EncoderBuffer))
        item = new EncoderBuffer(item, reporter);
      this.length += item.length;
      return item;
    }, this);
  } else if (typeof value === 'number') {
    if (!(0 <= value && value <= 0xff))
      return reporter.error('non-byte EncoderBuffer value');
    this.value = value;
    this.length = 1;
  } else if (typeof value === 'string') {
    this.value = value;
    this.length = Buffer.byteLength(value);
  } else if (Buffer.isBuffer(value)) {
    this.value = value;
    this.length = value.length;
  } else {
    return reporter.error('Unsupported type: ' + typeof value);
  }
}
exports.EncoderBuffer = EncoderBuffer;

EncoderBuffer.prototype.join = function join(out, offset) {
  if (!out)
    out = new Buffer(this.length);
  if (!offset)
    offset = 0;

  if (this.length === 0)
    return out;

  if (Array.isArray(this.value)) {
    this.value.forEach(function(item) {
      item.join(out, offset);
      offset += item.length;
    });
  } else {
    if (typeof this.value === 'number')
      out[offset] = this.value;
    else if (typeof this.value === 'string')
      out.write(this.value, offset);
    else if (Buffer.isBuffer(this.value))
      this.value.copy(out, offset);
    offset += this.length;
  }

  return out;
};

},{"../base":24,"buffer":96,"inherits":151}],24:[function(require,module,exports){
var base = exports;

base.Reporter = require('./reporter').Reporter;
base.DecoderBuffer = require('./buffer').DecoderBuffer;
base.EncoderBuffer = require('./buffer').EncoderBuffer;
base.Node = require('./node');

},{"./buffer":23,"./node":25,"./reporter":26}],25:[function(require,module,exports){
var Reporter = require('../base').Reporter;
var EncoderBuffer = require('../base').EncoderBuffer;
var DecoderBuffer = require('../base').DecoderBuffer;
var assert = require('minimalistic-assert');

// Supported tags
var tags = [
  'seq', 'seqof', 'set', 'setof', 'objid', 'bool',
  'gentime', 'utctime', 'null_', 'enum', 'int', 'objDesc',
  'bitstr', 'bmpstr', 'charstr', 'genstr', 'graphstr', 'ia5str', 'iso646str',
  'numstr', 'octstr', 'printstr', 't61str', 'unistr', 'utf8str', 'videostr'
];

// Public methods list
var methods = [
  'key', 'obj', 'use', 'optional', 'explicit', 'implicit', 'def', 'choice',
  'any', 'contains'
].concat(tags);

// Overrided methods list
var overrided = [
  '_peekTag', '_decodeTag', '_use',
  '_decodeStr', '_decodeObjid', '_decodeTime',
  '_decodeNull', '_decodeInt', '_decodeBool', '_decodeList',

  '_encodeComposite', '_encodeStr', '_encodeObjid', '_encodeTime',
  '_encodeNull', '_encodeInt', '_encodeBool'
];

function Node(enc, parent) {
  var state = {};
  this._baseState = state;

  state.enc = enc;

  state.parent = parent || null;
  state.children = null;

  // State
  state.tag = null;
  state.args = null;
  state.reverseArgs = null;
  state.choice = null;
  state.optional = false;
  state.any = false;
  state.obj = false;
  state.use = null;
  state.useDecoder = null;
  state.key = null;
  state['default'] = null;
  state.explicit = null;
  state.implicit = null;
  state.contains = null;

  // Should create new instance on each method
  if (!state.parent) {
    state.children = [];
    this._wrap();
  }
}
module.exports = Node;

var stateProps = [
  'enc', 'parent', 'children', 'tag', 'args', 'reverseArgs', 'choice',
  'optional', 'any', 'obj', 'use', 'alteredUse', 'key', 'default', 'explicit',
  'implicit', 'contains'
];

Node.prototype.clone = function clone() {
  var state = this._baseState;
  var cstate = {};
  stateProps.forEach(function(prop) {
    cstate[prop] = state[prop];
  });
  var res = new this.constructor(cstate.parent);
  res._baseState = cstate;
  return res;
};

Node.prototype._wrap = function wrap() {
  var state = this._baseState;
  methods.forEach(function(method) {
    this[method] = function _wrappedMethod() {
      var clone = new this.constructor(this);
      state.children.push(clone);
      return clone[method].apply(clone, arguments);
    };
  }, this);
};

Node.prototype._init = function init(body) {
  var state = this._baseState;

  assert(state.parent === null);
  body.call(this);

  // Filter children
  state.children = state.children.filter(function(child) {
    return child._baseState.parent === this;
  }, this);
  assert.equal(state.children.length, 1, 'Root node can have only one child');
};

Node.prototype._useArgs = function useArgs(args) {
  var state = this._baseState;

  // Filter children and args
  var children = args.filter(function(arg) {
    return arg instanceof this.constructor;
  }, this);
  args = args.filter(function(arg) {
    return !(arg instanceof this.constructor);
  }, this);

  if (children.length !== 0) {
    assert(state.children === null);
    state.children = children;

    // Replace parent to maintain backward link
    children.forEach(function(child) {
      child._baseState.parent = this;
    }, this);
  }
  if (args.length !== 0) {
    assert(state.args === null);
    state.args = args;
    state.reverseArgs = args.map(function(arg) {
      if (typeof arg !== 'object' || arg.constructor !== Object)
        return arg;

      var res = {};
      Object.keys(arg).forEach(function(key) {
        if (key == (key | 0))
          key |= 0;
        var value = arg[key];
        res[value] = key;
      });
      return res;
    });
  }
};

//
// Overrided methods
//

overrided.forEach(function(method) {
  Node.prototype[method] = function _overrided() {
    var state = this._baseState;
    throw new Error(method + ' not implemented for encoding: ' + state.enc);
  };
});

//
// Public methods
//

tags.forEach(function(tag) {
  Node.prototype[tag] = function _tagMethod() {
    var state = this._baseState;
    var args = Array.prototype.slice.call(arguments);

    assert(state.tag === null);
    state.tag = tag;

    this._useArgs(args);

    return this;
  };
});

Node.prototype.use = function use(item) {
  assert(item);
  var state = this._baseState;

  assert(state.use === null);
  state.use = item;

  return this;
};

Node.prototype.optional = function optional() {
  var state = this._baseState;

  state.optional = true;

  return this;
};

Node.prototype.def = function def(val) {
  var state = this._baseState;

  assert(state['default'] === null);
  state['default'] = val;
  state.optional = true;

  return this;
};

Node.prototype.explicit = function explicit(num) {
  var state = this._baseState;

  assert(state.explicit === null && state.implicit === null);
  state.explicit = num;

  return this;
};

Node.prototype.implicit = function implicit(num) {
  var state = this._baseState;

  assert(state.explicit === null && state.implicit === null);
  state.implicit = num;

  return this;
};

Node.prototype.obj = function obj() {
  var state = this._baseState;
  var args = Array.prototype.slice.call(arguments);

  state.obj = true;

  if (args.length !== 0)
    this._useArgs(args);

  return this;
};

Node.prototype.key = function key(newKey) {
  var state = this._baseState;

  assert(state.key === null);
  state.key = newKey;

  return this;
};

Node.prototype.any = function any() {
  var state = this._baseState;

  state.any = true;

  return this;
};

Node.prototype.choice = function choice(obj) {
  var state = this._baseState;

  assert(state.choice === null);
  state.choice = obj;
  this._useArgs(Object.keys(obj).map(function(key) {
    return obj[key];
  }));

  return this;
};

Node.prototype.contains = function contains(item) {
  var state = this._baseState;

  assert(state.use === null);
  state.contains = item;

  return this;
};

//
// Decoding
//

Node.prototype._decode = function decode(input, options) {
  var state = this._baseState;

  // Decode root node
  if (state.parent === null)
    return input.wrapResult(state.children[0]._decode(input, options));

  var result = state['default'];
  var present = true;

  var prevKey = null;
  if (state.key !== null)
    prevKey = input.enterKey(state.key);

  // Check if tag is there
  if (state.optional) {
    var tag = null;
    if (state.explicit !== null)
      tag = state.explicit;
    else if (state.implicit !== null)
      tag = state.implicit;
    else if (state.tag !== null)
      tag = state.tag;

    if (tag === null && !state.any) {
      // Trial and Error
      var save = input.save();
      try {
        if (state.choice === null)
          this._decodeGeneric(state.tag, input, options);
        else
          this._decodeChoice(input, options);
        present = true;
      } catch (e) {
        present = false;
      }
      input.restore(save);
    } else {
      present = this._peekTag(input, tag, state.any);

      if (input.isError(present))
        return present;
    }
  }

  // Push object on stack
  var prevObj;
  if (state.obj && present)
    prevObj = input.enterObject();

  if (present) {
    // Unwrap explicit values
    if (state.explicit !== null) {
      var explicit = this._decodeTag(input, state.explicit);
      if (input.isError(explicit))
        return explicit;
      input = explicit;
    }

    var start = input.offset;

    // Unwrap implicit and normal values
    if (state.use === null && state.choice === null) {
      if (state.any)
        var save = input.save();
      var body = this._decodeTag(
        input,
        state.implicit !== null ? state.implicit : state.tag,
        state.any
      );
      if (input.isError(body))
        return body;

      if (state.any)
        result = input.raw(save);
      else
        input = body;
    }

    if (options && options.track && state.tag !== null)
      options.track(input.path(), start, input.length, 'tagged');

    if (options && options.track && state.tag !== null)
      options.track(input.path(), input.offset, input.length, 'content');

    // Select proper method for tag
    if (state.any)
      result = result;
    else if (state.choice === null)
      result = this._decodeGeneric(state.tag, input, options);
    else
      result = this._decodeChoice(input, options);

    if (input.isError(result))
      return result;

    // Decode children
    if (!state.any && state.choice === null && state.children !== null) {
      state.children.forEach(function decodeChildren(child) {
        // NOTE: We are ignoring errors here, to let parser continue with other
        // parts of encoded data
        child._decode(input, options);
      });
    }

    // Decode contained/encoded by schema, only in bit or octet strings
    if (state.contains && (state.tag === 'octstr' || state.tag === 'bitstr')) {
      var data = new DecoderBuffer(result);
      result = this._getUse(state.contains, input._reporterState.obj)
          ._decode(data, options);
    }
  }

  // Pop object
  if (state.obj && present)
    result = input.leaveObject(prevObj);

  // Set key
  if (state.key !== null && (result !== null || present === true))
    input.leaveKey(prevKey, state.key, result);
  else if (prevKey !== null)
    input.exitKey(prevKey);

  return result;
};

Node.prototype._decodeGeneric = function decodeGeneric(tag, input, options) {
  var state = this._baseState;

  if (tag === 'seq' || tag === 'set')
    return null;
  if (tag === 'seqof' || tag === 'setof')
    return this._decodeList(input, tag, state.args[0], options);
  else if (/str$/.test(tag))
    return this._decodeStr(input, tag, options);
  else if (tag === 'objid' && state.args)
    return this._decodeObjid(input, state.args[0], state.args[1], options);
  else if (tag === 'objid')
    return this._decodeObjid(input, null, null, options);
  else if (tag === 'gentime' || tag === 'utctime')
    return this._decodeTime(input, tag, options);
  else if (tag === 'null_')
    return this._decodeNull(input, options);
  else if (tag === 'bool')
    return this._decodeBool(input, options);
  else if (tag === 'objDesc')
    return this._decodeStr(input, tag, options);
  else if (tag === 'int' || tag === 'enum')
    return this._decodeInt(input, state.args && state.args[0], options);

  if (state.use !== null) {
    return this._getUse(state.use, input._reporterState.obj)
        ._decode(input, options);
  } else {
    return input.error('unknown tag: ' + tag);
  }
};

Node.prototype._getUse = function _getUse(entity, obj) {

  var state = this._baseState;
  // Create altered use decoder if implicit is set
  state.useDecoder = this._use(entity, obj);
  assert(state.useDecoder._baseState.parent === null);
  state.useDecoder = state.useDecoder._baseState.children[0];
  if (state.implicit !== state.useDecoder._baseState.implicit) {
    state.useDecoder = state.useDecoder.clone();
    state.useDecoder._baseState.implicit = state.implicit;
  }
  return state.useDecoder;
};

Node.prototype._decodeChoice = function decodeChoice(input, options) {
  var state = this._baseState;
  var result = null;
  var match = false;

  Object.keys(state.choice).some(function(key) {
    var save = input.save();
    var node = state.choice[key];
    try {
      var value = node._decode(input, options);
      if (input.isError(value))
        return false;

      result = { type: key, value: value };
      match = true;
    } catch (e) {
      input.restore(save);
      return false;
    }
    return true;
  }, this);

  if (!match)
    return input.error('Choice not matched');

  return result;
};

//
// Encoding
//

Node.prototype._createEncoderBuffer = function createEncoderBuffer(data) {
  return new EncoderBuffer(data, this.reporter);
};

Node.prototype._encode = function encode(data, reporter, parent) {
  var state = this._baseState;
  if (state['default'] !== null && state['default'] === data)
    return;

  var result = this._encodeValue(data, reporter, parent);
  if (result === undefined)
    return;

  if (this._skipDefault(result, reporter, parent))
    return;

  return result;
};

Node.prototype._encodeValue = function encode(data, reporter, parent) {
  var state = this._baseState;

  // Decode root node
  if (state.parent === null)
    return state.children[0]._encode(data, reporter || new Reporter());

  var result = null;

  // Set reporter to share it with a child class
  this.reporter = reporter;

  // Check if data is there
  if (state.optional && data === undefined) {
    if (state['default'] !== null)
      data = state['default']
    else
      return;
  }

  // Encode children first
  var content = null;
  var primitive = false;
  if (state.any) {
    // Anything that was given is translated to buffer
    result = this._createEncoderBuffer(data);
  } else if (state.choice) {
    result = this._encodeChoice(data, reporter);
  } else if (state.contains) {
    content = this._getUse(state.contains, parent)._encode(data, reporter);
    primitive = true;
  } else if (state.children) {
    content = state.children.map(function(child) {
      if (child._baseState.tag === 'null_')
        return child._encode(null, reporter, data);

      if (child._baseState.key === null)
        return reporter.error('Child should have a key');
      var prevKey = reporter.enterKey(child._baseState.key);

      if (typeof data !== 'object')
        return reporter.error('Child expected, but input is not object');

      var res = child._encode(data[child._baseState.key], reporter, data);
      reporter.leaveKey(prevKey);

      return res;
    }, this).filter(function(child) {
      return child;
    });
    content = this._createEncoderBuffer(content);
  } else {
    if (state.tag === 'seqof' || state.tag === 'setof') {
      // TODO(indutny): this should be thrown on DSL level
      if (!(state.args && state.args.length === 1))
        return reporter.error('Too many args for : ' + state.tag);

      if (!Array.isArray(data))
        return reporter.error('seqof/setof, but data is not Array');

      var child = this.clone();
      child._baseState.implicit = null;
      content = this._createEncoderBuffer(data.map(function(item) {
        var state = this._baseState;

        return this._getUse(state.args[0], data)._encode(item, reporter);
      }, child));
    } else if (state.use !== null) {
      result = this._getUse(state.use, parent)._encode(data, reporter);
    } else {
      content = this._encodePrimitive(state.tag, data);
      primitive = true;
    }
  }

  // Encode data itself
  var result;
  if (!state.any && state.choice === null) {
    var tag = state.implicit !== null ? state.implicit : state.tag;
    var cls = state.implicit === null ? 'universal' : 'context';

    if (tag === null) {
      if (state.use === null)
        reporter.error('Tag could be omitted only for .use()');
    } else {
      if (state.use === null)
        result = this._encodeComposite(tag, primitive, cls, content);
    }
  }

  // Wrap in explicit
  if (state.explicit !== null)
    result = this._encodeComposite(state.explicit, false, 'context', result);
=======
"use strict";
module.exports = asPromise;

/**
 * Callback as used by {@link util.asPromise}.
 * @typedef asPromiseCallback
 * @type {function}
 * @param {Error|null} error Error, if any
 * @param {...*} params Additional arguments
 * @returns {undefined}
 */

/**
 * Returns a promise from a node-style callback function.
 * @memberof util
 * @param {asPromiseCallback} fn Function to call
 * @param {*} ctx Function context
 * @param {...*} params Function arguments
 * @returns {Promise<*>} Promisified function
 */
function asPromise(fn, ctx/*, varargs */) {
    var params  = new Array(arguments.length - 1),
        offset  = 0,
        index   = 2,
        pending = true;
    while (index < arguments.length)
        params[offset++] = arguments[index++];
    return new Promise(function executor(resolve, reject) {
        params[offset] = function callback(err/*, varargs */) {
            if (pending) {
                pending = false;
                if (err)
                    reject(err);
                else {
                    var params = new Array(arguments.length - 1),
                        offset = 0;
                    while (offset < params.length)
                        params[offset++] = arguments[offset];
                    resolve.apply(null, params);
                }
            }
        };
        try {
            fn.apply(ctx || null, params);
        } catch (err) {
            if (pending) {
                pending = false;
                reject(err);
            }
        }
    });
}

},{}],12:[function(require,module,exports){
"use strict";

/**
 * A minimal base64 implementation for number arrays.
 * @memberof util
 * @namespace
 */
var base64 = exports;

/**
 * Calculates the byte length of a base64 encoded string.
 * @param {string} string Base64 encoded string
 * @returns {number} Byte length
 */
base64.length = function length(string) {
    var p = string.length;
    if (!p)
        return 0;
    var n = 0;
    while (--p % 4 > 1 && string.charAt(p) === "=")
        ++n;
    return Math.ceil(string.length * 3) / 4 - n;
};

// Base64 encoding table
var b64 = new Array(64);

// Base64 decoding table
var s64 = new Array(123);

// 65..90, 97..122, 48..57, 43, 47
for (var i = 0; i < 64;)
    s64[b64[i] = i < 26 ? i + 65 : i < 52 ? i + 71 : i < 62 ? i - 4 : i - 59 | 43] = i++;

/**
 * Encodes a buffer to a base64 encoded string.
 * @param {Uint8Array} buffer Source buffer
 * @param {number} start Source start
 * @param {number} end Source end
 * @returns {string} Base64 encoded string
 */
base64.encode = function encode(buffer, start, end) {
    var parts = null,
        chunk = [];
    var i = 0, // output index
        j = 0, // goto index
        t;     // temporary
    while (start < end) {
        var b = buffer[start++];
        switch (j) {
            case 0:
                chunk[i++] = b64[b >> 2];
                t = (b & 3) << 4;
                j = 1;
                break;
            case 1:
                chunk[i++] = b64[t | b >> 4];
                t = (b & 15) << 2;
                j = 2;
                break;
            case 2:
                chunk[i++] = b64[t | b >> 6];
                chunk[i++] = b64[b & 63];
                j = 0;
                break;
        }
        if (i > 8191) {
            (parts || (parts = [])).push(String.fromCharCode.apply(String, chunk));
            i = 0;
        }
    }
    if (j) {
        chunk[i++] = b64[t];
        chunk[i++] = 61;
        if (j === 1)
            chunk[i++] = 61;
    }
    if (parts) {
        if (i)
            parts.push(String.fromCharCode.apply(String, chunk.slice(0, i)));
        return parts.join("");
    }
    return String.fromCharCode.apply(String, chunk.slice(0, i));
};

var invalidEncoding = "invalid encoding";

/**
 * Decodes a base64 encoded string to a buffer.
 * @param {string} string Source string
 * @param {Uint8Array} buffer Destination buffer
 * @param {number} offset Destination offset
 * @returns {number} Number of bytes written
 * @throws {Error} If encoding is invalid
 */
base64.decode = function decode(string, buffer, offset) {
    var start = offset;
    var j = 0, // goto index
        t;     // temporary
    for (var i = 0; i < string.length;) {
        var c = string.charCodeAt(i++);
        if (c === 61 && j > 1)
            break;
        if ((c = s64[c]) === undefined)
            throw Error(invalidEncoding);
        switch (j) {
            case 0:
                t = c;
                j = 1;
                break;
            case 1:
                buffer[offset++] = t << 2 | (c & 48) >> 4;
                t = c;
                j = 2;
                break;
            case 2:
                buffer[offset++] = (t & 15) << 4 | (c & 60) >> 2;
                t = c;
                j = 3;
                break;
            case 3:
                buffer[offset++] = (t & 3) << 6 | c;
                j = 0;
                break;
        }
    }
    if (j === 1)
        throw Error(invalidEncoding);
    return offset - start;
};

/**
 * Tests if the specified string appears to be base64 encoded.
 * @param {string} string String to test
 * @returns {boolean} `true` if probably base64 encoded, otherwise false
 */
base64.test = function test(string) {
    return /^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/.test(string);
};

},{}],13:[function(require,module,exports){
"use strict";
module.exports = codegen;

/**
 * Begins generating a function.
 * @memberof util
 * @param {string[]} functionParams Function parameter names
 * @param {string} [functionName] Function name if not anonymous
 * @returns {Codegen} Appender that appends code to the function's body
 */
function codegen(functionParams, functionName) {

    /* istanbul ignore if */
    if (typeof functionParams === "string") {
        functionName = functionParams;
        functionParams = undefined;
    }

    var body = [];

    /**
     * Appends code to the function's body or finishes generation.
     * @typedef Codegen
     * @type {function}
     * @param {string|Object.<string,*>} [formatStringOrScope] Format string or, to finish the function, an object of additional scope variables, if any
     * @param {...*} [formatParams] Format parameters
     * @returns {Codegen|Function} Itself or the generated function if finished
     * @throws {Error} If format parameter counts do not match
     */

    function Codegen(formatStringOrScope) {
        // note that explicit array handling below makes this ~50% faster

        // finish the function
        if (typeof formatStringOrScope !== "string") {
            var source = toString();
            if (codegen.verbose)
                console.log("codegen: " + source); // eslint-disable-line no-console
            source = "return " + source;
            if (formatStringOrScope) {
                var scopeKeys   = Object.keys(formatStringOrScope),
                    scopeParams = new Array(scopeKeys.length + 1),
                    scopeValues = new Array(scopeKeys.length),
                    scopeOffset = 0;
                while (scopeOffset < scopeKeys.length) {
                    scopeParams[scopeOffset] = scopeKeys[scopeOffset];
                    scopeValues[scopeOffset] = formatStringOrScope[scopeKeys[scopeOffset++]];
                }
                scopeParams[scopeOffset] = source;
                return Function.apply(null, scopeParams).apply(null, scopeValues); // eslint-disable-line no-new-func
            }
            return Function(source)(); // eslint-disable-line no-new-func
        }

        // otherwise append to body
        var formatParams = new Array(arguments.length - 1),
            formatOffset = 0;
        while (formatOffset < formatParams.length)
            formatParams[formatOffset] = arguments[++formatOffset];
        formatOffset = 0;
        formatStringOrScope = formatStringOrScope.replace(/%([%dfijs])/g, function replace($0, $1) {
            var value = formatParams[formatOffset++];
            switch ($1) {
                case "d": case "f": return String(Number(value));
                case "i": return String(Math.floor(value));
                case "j": return JSON.stringify(value);
                case "s": return String(value);
            }
            return "%";
        });
        if (formatOffset !== formatParams.length)
            throw Error("parameter count mismatch");
        body.push(formatStringOrScope);
        return Codegen;
    }

    function toString(functionNameOverride) {
        return "function " + (functionNameOverride || functionName || "") + "(" + (functionParams && functionParams.join(",") || "") + "){\n  " + body.join("\n  ") + "\n}";
    }

    Codegen.toString = toString;
    return Codegen;
}

/**
 * Begins generating a function.
 * @memberof util
 * @function codegen
 * @param {string} [functionName] Function name if not anonymous
 * @returns {Codegen} Appender that appends code to the function's body
 * @variation 2
 */

/**
 * When set to `true`, codegen will log generated code to console. Useful for debugging.
 * @name util.codegen.verbose
 * @type {boolean}
 */
codegen.verbose = false;

},{}],14:[function(require,module,exports){
"use strict";
module.exports = EventEmitter;

/**
 * Constructs a new event emitter instance.
 * @classdesc A minimal event emitter.
 * @memberof util
 * @constructor
 */
function EventEmitter() {

    /**
     * Registered listeners.
     * @type {Object.<string,*>}
     * @private
     */
    this._listeners = {};
}

/**
 * Registers an event listener.
 * @param {string} evt Event name
 * @param {function} fn Listener
 * @param {*} [ctx] Listener context
 * @returns {util.EventEmitter} `this`
 */
EventEmitter.prototype.on = function on(evt, fn, ctx) {
    (this._listeners[evt] || (this._listeners[evt] = [])).push({
        fn  : fn,
        ctx : ctx || this
    });
    return this;
};

/**
 * Removes an event listener or any matching listeners if arguments are omitted.
 * @param {string} [evt] Event name. Removes all listeners if omitted.
 * @param {function} [fn] Listener to remove. Removes all listeners of `evt` if omitted.
 * @returns {util.EventEmitter} `this`
 */
EventEmitter.prototype.off = function off(evt, fn) {
    if (evt === undefined)
        this._listeners = {};
    else {
        if (fn === undefined)
            this._listeners[evt] = [];
        else {
            var listeners = this._listeners[evt];
            for (var i = 0; i < listeners.length;)
                if (listeners[i].fn === fn)
                    listeners.splice(i, 1);
                else
                    ++i;
        }
    }
    return this;
};

/**
 * Emits an event by calling its listeners with the specified arguments.
 * @param {string} evt Event name
 * @param {...*} args Arguments
 * @returns {util.EventEmitter} `this`
 */
EventEmitter.prototype.emit = function emit(evt) {
    var listeners = this._listeners[evt];
    if (listeners) {
        var args = [],
            i = 1;
        for (; i < arguments.length;)
            args.push(arguments[i++]);
        for (i = 0; i < listeners.length;)
            listeners[i].fn.apply(listeners[i++].ctx, args);
    }
    return this;
};

},{}],15:[function(require,module,exports){
"use strict";
module.exports = fetch;

var asPromise = require("@protobufjs/aspromise"),
    inquire   = require("@protobufjs/inquire");

var fs = inquire("fs");

/**
 * Node-style callback as used by {@link util.fetch}.
 * @typedef FetchCallback
 * @type {function}
 * @param {?Error} error Error, if any, otherwise `null`
 * @param {string} [contents] File contents, if there hasn't been an error
 * @returns {undefined}
 */

/**
 * Options as used by {@link util.fetch}.
 * @typedef FetchOptions
 * @type {Object}
 * @property {boolean} [binary=false] Whether expecting a binary response
 * @property {boolean} [xhr=false] If `true`, forces the use of XMLHttpRequest
 */

/**
 * Fetches the contents of a file.
 * @memberof util
 * @param {string} filename File path or url
 * @param {FetchOptions} options Fetch options
 * @param {FetchCallback} callback Callback function
 * @returns {undefined}
 */
function fetch(filename, options, callback) {
    if (typeof options === "function") {
        callback = options;
        options = {};
    } else if (!options)
        options = {};

    if (!callback)
        return asPromise(fetch, this, filename, options); // eslint-disable-line no-invalid-this

    // if a node-like filesystem is present, try it first but fall back to XHR if nothing is found.
    if (!options.xhr && fs && fs.readFile)
        return fs.readFile(filename, function fetchReadFileCallback(err, contents) {
            return err && typeof XMLHttpRequest !== "undefined"
                ? fetch.xhr(filename, options, callback)
                : err
                ? callback(err)
                : callback(null, options.binary ? contents : contents.toString("utf8"));
        });

    // use the XHR version otherwise.
    return fetch.xhr(filename, options, callback);
}

/**
 * Fetches the contents of a file.
 * @name util.fetch
 * @function
 * @param {string} path File path or url
 * @param {FetchCallback} callback Callback function
 * @returns {undefined}
 * @variation 2
 */

/**
 * Fetches the contents of a file.
 * @name util.fetch
 * @function
 * @param {string} path File path or url
 * @param {FetchOptions} [options] Fetch options
 * @returns {Promise<string|Uint8Array>} Promise
 * @variation 3
 */

/**/
fetch.xhr = function fetch_xhr(filename, options, callback) {
    var xhr = new XMLHttpRequest();
    xhr.onreadystatechange /* works everywhere */ = function fetchOnReadyStateChange() {

        if (xhr.readyState !== 4)
            return undefined;

        // local cors security errors return status 0 / empty string, too. afaik this cannot be
        // reliably distinguished from an actually empty file for security reasons. feel free
        // to send a pull request if you are aware of a solution.
        if (xhr.status !== 0 && xhr.status !== 200)
            return callback(Error("status " + xhr.status));

        // if binary data is expected, make sure that some sort of array is returned, even if
        // ArrayBuffers are not supported. the binary string fallback, however, is unsafe.
        if (options.binary) {
            var buffer = xhr.response;
            if (!buffer) {
                buffer = [];
                for (var i = 0; i < xhr.responseText.length; ++i)
                    buffer.push(xhr.responseText.charCodeAt(i) & 255);
            }
            return callback(null, typeof Uint8Array !== "undefined" ? new Uint8Array(buffer) : buffer);
        }
        return callback(null, xhr.responseText);
    };

    if (options.binary) {
        // ref: https://developer.mozilla.org/en-US/docs/Web/API/XMLHttpRequest/Sending_and_Receiving_Binary_Data#Receiving_binary_data_in_older_browsers
        if ("overrideMimeType" in xhr)
            xhr.overrideMimeType("text/plain; charset=x-user-defined");
        xhr.responseType = "arraybuffer";
    }

    xhr.open("GET", filename);
    xhr.send();
};

},{"@protobufjs/aspromise":11,"@protobufjs/inquire":17}],16:[function(require,module,exports){
"use strict";

module.exports = factory(factory);

/**
 * Reads / writes floats / doubles from / to buffers.
 * @name util.float
 * @namespace
 */

/**
 * Writes a 32 bit float to a buffer using little endian byte order.
 * @name util.float.writeFloatLE
 * @function
 * @param {number} val Value to write
 * @param {Uint8Array} buf Target buffer
 * @param {number} pos Target buffer offset
 * @returns {undefined}
 */

/**
 * Writes a 32 bit float to a buffer using big endian byte order.
 * @name util.float.writeFloatBE
 * @function
 * @param {number} val Value to write
 * @param {Uint8Array} buf Target buffer
 * @param {number} pos Target buffer offset
 * @returns {undefined}
 */

/**
 * Reads a 32 bit float from a buffer using little endian byte order.
 * @name util.float.readFloatLE
 * @function
 * @param {Uint8Array} buf Source buffer
 * @param {number} pos Source buffer offset
 * @returns {number} Value read
 */

/**
 * Reads a 32 bit float from a buffer using big endian byte order.
 * @name util.float.readFloatBE
 * @function
 * @param {Uint8Array} buf Source buffer
 * @param {number} pos Source buffer offset
 * @returns {number} Value read
 */

/**
 * Writes a 64 bit double to a buffer using little endian byte order.
 * @name util.float.writeDoubleLE
 * @function
 * @param {number} val Value to write
 * @param {Uint8Array} buf Target buffer
 * @param {number} pos Target buffer offset
 * @returns {undefined}
 */

/**
 * Writes a 64 bit double to a buffer using big endian byte order.
 * @name util.float.writeDoubleBE
 * @function
 * @param {number} val Value to write
 * @param {Uint8Array} buf Target buffer
 * @param {number} pos Target buffer offset
 * @returns {undefined}
 */

/**
 * Reads a 64 bit double from a buffer using little endian byte order.
 * @name util.float.readDoubleLE
 * @function
 * @param {Uint8Array} buf Source buffer
 * @param {number} pos Source buffer offset
 * @returns {number} Value read
 */

/**
 * Reads a 64 bit double from a buffer using big endian byte order.
 * @name util.float.readDoubleBE
 * @function
 * @param {Uint8Array} buf Source buffer
 * @param {number} pos Source buffer offset
 * @returns {number} Value read
 */

// Factory function for the purpose of node-based testing in modified global environments
function factory(exports) {

    // float: typed array
    if (typeof Float32Array !== "undefined") (function() {

        var f32 = new Float32Array([ -0 ]),
            f8b = new Uint8Array(f32.buffer),
            le  = f8b[3] === 128;

        function writeFloat_f32_cpy(val, buf, pos) {
            f32[0] = val;
            buf[pos    ] = f8b[0];
            buf[pos + 1] = f8b[1];
            buf[pos + 2] = f8b[2];
            buf[pos + 3] = f8b[3];
        }

        function writeFloat_f32_rev(val, buf, pos) {
            f32[0] = val;
            buf[pos    ] = f8b[3];
            buf[pos + 1] = f8b[2];
            buf[pos + 2] = f8b[1];
            buf[pos + 3] = f8b[0];
        }

        /* istanbul ignore next */
        exports.writeFloatLE = le ? writeFloat_f32_cpy : writeFloat_f32_rev;
        /* istanbul ignore next */
        exports.writeFloatBE = le ? writeFloat_f32_rev : writeFloat_f32_cpy;

        function readFloat_f32_cpy(buf, pos) {
            f8b[0] = buf[pos    ];
            f8b[1] = buf[pos + 1];
            f8b[2] = buf[pos + 2];
            f8b[3] = buf[pos + 3];
            return f32[0];
        }

        function readFloat_f32_rev(buf, pos) {
            f8b[3] = buf[pos    ];
            f8b[2] = buf[pos + 1];
            f8b[1] = buf[pos + 2];
            f8b[0] = buf[pos + 3];
            return f32[0];
        }

        /* istanbul ignore next */
        exports.readFloatLE = le ? readFloat_f32_cpy : readFloat_f32_rev;
        /* istanbul ignore next */
        exports.readFloatBE = le ? readFloat_f32_rev : readFloat_f32_cpy;

    // float: ieee754
    })(); else (function() {

        function writeFloat_ieee754(writeUint, val, buf, pos) {
            var sign = val < 0 ? 1 : 0;
            if (sign)
                val = -val;
            if (val === 0)
                writeUint(1 / val > 0 ? /* positive */ 0 : /* negative 0 */ 2147483648, buf, pos);
            else if (isNaN(val))
                writeUint(2143289344, buf, pos);
            else if (val > 3.4028234663852886e+38) // +-Infinity
                writeUint((sign << 31 | 2139095040) >>> 0, buf, pos);
            else if (val < 1.1754943508222875e-38) // denormal
                writeUint((sign << 31 | Math.round(val / 1.401298464324817e-45)) >>> 0, buf, pos);
            else {
                var exponent = Math.floor(Math.log(val) / Math.LN2),
                    mantissa = Math.round(val * Math.pow(2, -exponent) * 8388608) & 8388607;
                writeUint((sign << 31 | exponent + 127 << 23 | mantissa) >>> 0, buf, pos);
            }
        }

        exports.writeFloatLE = writeFloat_ieee754.bind(null, writeUintLE);
        exports.writeFloatBE = writeFloat_ieee754.bind(null, writeUintBE);

        function readFloat_ieee754(readUint, buf, pos) {
            var uint = readUint(buf, pos),
                sign = (uint >> 31) * 2 + 1,
                exponent = uint >>> 23 & 255,
                mantissa = uint & 8388607;
            return exponent === 255
                ? mantissa
                ? NaN
                : sign * Infinity
                : exponent === 0 // denormal
                ? sign * 1.401298464324817e-45 * mantissa
                : sign * Math.pow(2, exponent - 150) * (mantissa + 8388608);
        }

        exports.readFloatLE = readFloat_ieee754.bind(null, readUintLE);
        exports.readFloatBE = readFloat_ieee754.bind(null, readUintBE);

    })();

    // double: typed array
    if (typeof Float64Array !== "undefined") (function() {

        var f64 = new Float64Array([-0]),
            f8b = new Uint8Array(f64.buffer),
            le  = f8b[7] === 128;

        function writeDouble_f64_cpy(val, buf, pos) {
            f64[0] = val;
            buf[pos    ] = f8b[0];
            buf[pos + 1] = f8b[1];
            buf[pos + 2] = f8b[2];
            buf[pos + 3] = f8b[3];
            buf[pos + 4] = f8b[4];
            buf[pos + 5] = f8b[5];
            buf[pos + 6] = f8b[6];
            buf[pos + 7] = f8b[7];
        }

        function writeDouble_f64_rev(val, buf, pos) {
            f64[0] = val;
            buf[pos    ] = f8b[7];
            buf[pos + 1] = f8b[6];
            buf[pos + 2] = f8b[5];
            buf[pos + 3] = f8b[4];
            buf[pos + 4] = f8b[3];
            buf[pos + 5] = f8b[2];
            buf[pos + 6] = f8b[1];
            buf[pos + 7] = f8b[0];
        }

        /* istanbul ignore next */
        exports.writeDoubleLE = le ? writeDouble_f64_cpy : writeDouble_f64_rev;
        /* istanbul ignore next */
        exports.writeDoubleBE = le ? writeDouble_f64_rev : writeDouble_f64_cpy;

        function readDouble_f64_cpy(buf, pos) {
            f8b[0] = buf[pos    ];
            f8b[1] = buf[pos + 1];
            f8b[2] = buf[pos + 2];
            f8b[3] = buf[pos + 3];
            f8b[4] = buf[pos + 4];
            f8b[5] = buf[pos + 5];
            f8b[6] = buf[pos + 6];
            f8b[7] = buf[pos + 7];
            return f64[0];
        }

        function readDouble_f64_rev(buf, pos) {
            f8b[7] = buf[pos    ];
            f8b[6] = buf[pos + 1];
            f8b[5] = buf[pos + 2];
            f8b[4] = buf[pos + 3];
            f8b[3] = buf[pos + 4];
            f8b[2] = buf[pos + 5];
            f8b[1] = buf[pos + 6];
            f8b[0] = buf[pos + 7];
            return f64[0];
        }

        /* istanbul ignore next */
        exports.readDoubleLE = le ? readDouble_f64_cpy : readDouble_f64_rev;
        /* istanbul ignore next */
        exports.readDoubleBE = le ? readDouble_f64_rev : readDouble_f64_cpy;

    // double: ieee754
    })(); else (function() {

        function writeDouble_ieee754(writeUint, off0, off1, val, buf, pos) {
            var sign = val < 0 ? 1 : 0;
            if (sign)
                val = -val;
            if (val === 0) {
                writeUint(0, buf, pos + off0);
                writeUint(1 / val > 0 ? /* positive */ 0 : /* negative 0 */ 2147483648, buf, pos + off1);
            } else if (isNaN(val)) {
                writeUint(0, buf, pos + off0);
                writeUint(2146959360, buf, pos + off1);
            } else if (val > 1.7976931348623157e+308) { // +-Infinity
                writeUint(0, buf, pos + off0);
                writeUint((sign << 31 | 2146435072) >>> 0, buf, pos + off1);
            } else {
                var mantissa;
                if (val < 2.2250738585072014e-308) { // denormal
                    mantissa = val / 5e-324;
                    writeUint(mantissa >>> 0, buf, pos + off0);
                    writeUint((sign << 31 | mantissa / 4294967296) >>> 0, buf, pos + off1);
                } else {
                    var exponent = Math.floor(Math.log(val) / Math.LN2);
                    if (exponent === 1024)
                        exponent = 1023;
                    mantissa = val * Math.pow(2, -exponent);
                    writeUint(mantissa * 4503599627370496 >>> 0, buf, pos + off0);
                    writeUint((sign << 31 | exponent + 1023 << 20 | mantissa * 1048576 & 1048575) >>> 0, buf,