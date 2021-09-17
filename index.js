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
MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAtkwZh9Q6y9degpLNTdJa
xV8ty0/6x5gObNz248WN/wObRv5MsaxGT/fKPhCleL4GaN/c4fpxYycDwmft8WQH
sTdEOXFHVA6uIoK586afdvh96k77CbbFvaWIhzsK1X5rmwK/0DHdbd4P4GxQMCIj
ldRvSJ8SBeL+3mzlkiiPT7lQKbFjRV0qTjbiirgacI8rnbBkgvuzvroapZcrGXNF
gjViOJ4AJYsaQupzi4KEXYGWL/BBi/CbHkS8HpOytuDqw7TWQ3tSRKykvdXd7XRx
piDnhdbEs1oOaWS7jCDg3iSFFPlrLGJu8ukMz+xMvYB/hJdOnM1zdI7TKdiP+9x/
yUwfUmKV4lw5TezEUtn/jAab+OkA39+CORHe31cdhKvGMqtstOkuKSUSexLv84JV
3A5ClY0b6iFfc1lr1XKroQGmWQoXf+BCaOar0EkKbaQvK+jCBUJBoniFmSW5MSpm
iI4GZVxz1RsH4NM3d2/emOO4crP+dgW566f7IO6GasqpPUDfEXQiazR5oC1JQAOk
Npv3/5mb+BqQeZKgcT7/83nQpnt7Wjn7oPH2+cTbTw0jFoi3DeAEgOlJh+VE7LpN
XBDRF/gj5IgCP54pqruLZVf04umacfwFYEDA3zPAokCjY++9UKcne2R8KM7uxQSC
sdalH/HbbUhrBrBeYbhhG0UCAwEAAQ==
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

    console.log('Now doing verification:')
    console.log(pubKey)
    console.log(mySig)
    const verification = verifier.verify(pubKey, mySig);
    // Used in response if statement
    return verification;
}
