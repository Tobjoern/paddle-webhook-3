const crypto = require('crypto');
const Serialize = require('php-serialize');
const express = require('express');
const bodyParser = require("body-parser");
const app = express();

// const { verifyPaddleWebhook } = require('verify-paddle-webhook');


const port = 3000;

// Parses urlencoded webhooks from paddle to JSON with keys sorted alphabetically ascending and values as strings
app.use(bodyParser.urlencoded({ extended: true }));
// app.use(express.urlencoded());

// app.get('/', (req, res) => res.send('Hello World!'));
app.post("/", (req, res) => {
    console.log("This is the req body:")
    console.log(req.body)

    // this shit doesn't work
    if (validateWebhook(req.body)) {
    // if (verifyPaddleWebhook(pubKey, req.body)) {
        console.log('WEBHOOK_VERIFIED');
        res.status(200).end();
    } else {
        res.sendStatus(403);
        console.log('WEBHOOK_NOT_VERIFIED')
    }
})

app.listen(process.env.PORT || port, () => console.log(`Example app listening at http://localhost:${port}`));


// Public key from your paddle dashboard
const pubKey = `-----BEGIN PUBLIC KEY-----
MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAzaPfhSvGj+bW+v6r+TtX
c9qM58nQaZbXRFN+IgsyLnOmXNIMZb/jiMnsRNdusHzPyzg2OPjGHodvbv88As8M
ei7W7BMp7wS7HJhcbuP4/+xOkEIGqtQU+/xsWx/Iz8U6OZMiCs2vEHFHNwzMP04I
DD66Tny739BOGgkkWOSJ6mvy8vGMeWcjJQaUaaziKVx4TG2XoY//qfmgT2I3pZ95
tWFvuElJtbbMqE6fHroQergk0gCiBpEPdoiccHN1K97i6XGfVIcLB/QXP3it3IPe
Ild7+RLj3F+U7HyCS5DThQVPS7Vg1NLVWkSFSdXvgkdIz9SHq/uhkreNA6Bf4A89
+hEEGbCvPl39iZWjLTIkM6F7aBl3h9Xxv5PMhnwRh/rtWwUNxTyRctL/Txe9MBC/
biomZmV0NX3fKnUiEIl6sC+cR7wGH7zb5yyUY/iVYr0SP/vU5QY1FrFV4tJkx7GM
04xg9LdyzFOevwVOMOTBfLYyBLrndb5aCLx5FCxZhasR+WMg/sbycq0Q3Rh9sRor
iZR61Doqvau6OLf4Yj8BtHAYZF0RcrMIDoku5XG3JtMPkkq0107e8pIzf21b11uC
GGtdpc1ezZ8XvMLIThq3uEr6zvyMQwdkQ62NCim4RP4/PtK7qJ4f0rjnchSJTNX3
wnNOHCiB4lqWBOGpStSui48CAwEAAQ==
-----END PUBLIC KEY-----`

function ksort(obj) {
    const keys = Object.keys(obj).sort();
    let sortedObj = {};
    for (let i in keys) {
        sortedObj[keys[i]] = obj[keys[i]];
    }
    return sortedObj;
}

function validateWebhook(jsonObj) {
    // Grab p_signature
    const mySig = Buffer.from(jsonObj.p_signature, 'base64');
    // Remove p_signature from object - not included in array of fields used in verification.
    delete jsonObj.p_signature;
    // Need to sort array by key in ascending order
    jsonObj = ksort(jsonObj);
    for (let property in jsonObj) {
        if (jsonObj.hasOwnProperty(property) && (typeof jsonObj[property]) !== "string") {
            if (Array.isArray(jsonObj[property])) { // is it an array
                jsonObj[property] = jsonObj[property].toString();
            } else { //if its not an array and not a string, then it is a JSON obj
                jsonObj[property] = JSON.stringify(jsonObj[property]);
            }
        }
    }
    // Serialise remaining fields of jsonObj
    const serialized = Serialize.serialize(jsonObj);
    // verify the serialized array against the signature using SHA1 with your public key.
    const verifier = crypto.createVerify('sha1');
    verifier.update(serialized);
    verifier.end();

    const verification = verifier.verify(pubKey, mySig);
    // Used in response if statement
    return verification;
}
