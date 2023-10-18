import { createServer } from 'http';
import jwt from 'jsonwebtoken';
import { readFileSync } from 'fs';
import { randomBytes } from 'crypto';
import { parse } from 'url';

const privateKey = readFileSync('signing.key');
const privateKeyKID = 'YOUR SIGNING KEY KID';

function generateRandomString(length) {
    return randomBytes(length).toString('hex');
}

function createClientAssertion(clientId,audience) {
    const currentTime = Math.floor(Date.now() / 1000);

    const jti = generateRandomString(10);

    const payload = {
        iss: clientId,
        sub: clientId,
        aud: audience,
        iat: currentTime,
        exp: currentTime + 500, // Token expiration time in seconds (e.g., 5 minutes from now)
        jti: jti
    };

    const header = {
        kid: privateKeyKID
    };

    const clientAssertion = jwt.sign(payload, privateKey, {
        algorithm: 'PS256',
        header
    });

    return clientAssertion;
}

function createPARRequestObject(clientId,audience,redirectUri) {
    const currentTime = Math.floor(Date.now() / 1000);

    const state = generateRandomString(10);

    const payload = {
        iss: clientId,
        response_type: "code id_token",
        code_challenge_method: "S256",
        nonce: "S05tH4J105",
        client_id: clientId,
        aud: audience,
        nbf: currentTime,
        scope: "openid payments",
        redirect_uri: redirectUri,
        state: state,
        exp: currentTime + 500,
        code_challenge: "KXbzltei9i53KWng8Xe0bsuBDFSVfrxn179CGlHEGho"
    }
    
    const header = {
        kid: privateKeyKID
    };

    const clientAssertion = jwt.sign(payload, privateKey, {
        algorithm: 'PS256',
        header
    });

    return clientAssertion;
}

const server = createServer((req, res) => {
    const { pathname, query } = parse(req.url, true);
    if (pathname === '/client_assertion' && req.method === 'GET') {
        res.writeHead(200, { 'Content-Type': 'text/plain' });
        res.end(createClientAssertion(query.client_id, query.audience));
    } else if (pathname === '/par_request' && req.method === 'GET') {
        res.writeHead(200, { 'Content-Type': 'text/plain' });
        res.end(createPARRequestObject(query.client_id, query.audience, query.redirect_uri));
    }
});

const port = 3000; // Specify the port number
server.listen(port, () => {
  console.log(`Server running at http://localhost:${port}`);
});