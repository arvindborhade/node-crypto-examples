var crypto, ALGORITHM, KEY, HMAC_ALGORITHM, HMAC_KEY;


crypto = require('crypto');

ALGORITHM = 'AES-256-CBC'; // CBC because CTR isn't possible with the current version of the Node.JS crypto library
HMAC_ALGORITHM = 'SHA256';
KEY = crypto.randomBytes(32); // This key should be stored in an environment variable
HMAC_KEY = crypto.randomBytes(32); // This key should be stored in an environment variable

 

encrypt = function (plain_text) {

    var IV = "ajsksksldjfkslek"; // ensure that the IV (initialization vector) is random
    var cipher_text;
    var hmac;
    var encryptor;

    encryptor = crypto.createCipheriv(ALGORITHM, KEY, IV);
    encryptor.setEncoding('hex');
    encryptor.write(plain_text);
    encryptor.end();

    cipher_text = encryptor.read();

    hmac = crypto.createHmac(HMAC_ALGORITHM, HMAC_KEY);
    hmac.update(cipher_text);
    hmac.update(IV.toString('hex')); // ensure that both the IV and the cipher-text is protected by the HMAC

    // The IV isn't a secret so it can be stored along side everything else
    return cipher_text + "$" + IV.toString('hex') + "$" + hmac.digest('hex') 
    return cipher_text + "$" + IV.toString('hex') + "$" + hmac.digest('hex') 

};

decrypt = function (cipher_text) {
    var cipher_blob = cipher_text.split("$");
    var ct = cipher_blob[0];
    var IV = cipher_blob[1];
    var hmac = cipher_blob[2];
    var decryptor;
    var dec;

    chmac = crypto.createHmac(HMAC_ALGORITHM, HMAC_KEY);
    chmac.update(ct);
    chmac.update(IV.toString('hex'));

    if (!constant_time_compare(chmac.digest('hex'), hmac)) {
        console.log("Encrypted Blob has been tampered with...");
        return null;
    }

    var decipher = crypto.createDecipheriv(ALGORITHM, KEY, IV);
    var dec = decipher.update(ct,'hex','utf8')
    dec += decipher.final('utf8');
    return dec;

};



constant_time_compare = function (val1, val2) {
    var sentinel;

    if (val1.length !== val2.length) {
        return false;
    }


    for (var i = 0; i <= (val1.length - 1); i++) {
        sentinel |= val1.charCodeAt(i) ^ val2.charCodeAt(i);
    }

    return sentinel === 0
};


var cipherText = encrypt("1234567890");
console.log(cipherText);
var CleanText = decrypt(cipherText);
console.log(CleanText);
