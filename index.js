const functions = require('@google-cloud/functions-framework');
const crypto = require('crypto');

// ─── JaaS Config ───────────────────────────────────────────────
const APP_ID  = 'vpaas-magic-cookie-b4744e36a70547ebb8b2a6f89f1eea5e';
const KEY_ID  = 'vpaas-magic-cookie-b4744e36a70547ebb8b2a6f89f1eea5e/a62f39';

// Private Key — JaaS Dashboard se download ki gayi
const PRIVATE_KEY = `-----BEGIN PRIVATE KEY-----
MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQCu51NaQm63BiLo
qBFlw2h73YjmMG15VaDQeDvg1oqN9F/y4QQKA4BnN0GuiZiRRGZlHkG39BYTxAqs
/cTkF9KhhK0u5iz0UJl9XeQBOVbMVpS/KOuY474Z5oR/NHO7YpwyXgYK3O3+LvGX
KRgEb3I2ZgVRp31RlpJH7BZddFP3sJ3zK5YEV164Re9fhswFLq0qqFZNE8PA8UFp
OeXL2sb+FRpVZ5iE0AD0+NYxxhukDzfFZOmvKyzX8cInnHbG1sxpCpbxA/1mrbYU
apRoRRHrJb0tbfWHGK/pAeOxeenos5WsBBcwH6i5cG5ZTo0IH+RyRhkl9v+6Lriu
U6MBGI49AgMBAAECggEASegL6674s7QPGjqyp0qsIvMYvxQlnkjVnGHCA58EizmB
NdNpboXOQ08xHPydkHzTu9TONloY3h9P14ugIDYE1iWHPLMcudw5D6WWDAJbsBrB
3gj/jOpnUPB8engCk2L2172tVffHRUo24gYGVRF2tI/lnXxl0w0KIQQc6z6VoKq5
KMMB2L0n6AluWEZN5wC7gsTRhHVc+dQO8BSdKz/M+UJQcLxX4qIrnKOcyetEsmzg
gToBGHXAjKurKRN1Fo/Enpkp0m3bm4RK/zgOaX5bmG6b0Gp2DEn63syHrciazRu8
A8Otj4KEJD6TczOwD3al5k1Tc5MQwRlVv5pLj0V/gQKBgQDXMYz3mXqSoVg2P7T7
fOyiq1TYp021nrlIdWp4XaH/86jpfI3tuW40YuS01HYzYercOVdnBV9WNq5fppx5
vEU+jzjCZl3msZX8HMf65h7KC8WXdFgwVUuMxPXoEuNzoRZ8wYXwQBfSv+F6dNGY
Mr3poXFetwG2mzfd25xg7BXnHQKBgQDQEewsEaDJfXsVBhPj/Q2AW0COVw0Qs6hU
LEmM6uhz1T9LYKP4lbDtY6utDuI6bHwFaJZXHAdE9KmZgAYKuPiieKfd60NVGjTx
USMbW1XQTPRgRDB9s7zbUxY/sON/dj7qiH0MjYrDzYygQMDaSr/9c2goQW9THyX5
VF/x7fP5oQKBgQCscERp1E7oWOn67qn0LHLjFy/yPH6E3x/R9GTQ9xbtpy7firOg
n0q0J9rlHKtrGTe+KSTkpOV0jHTGqRgSZM+IBfSRsr3kMsHhOJ73apeZiD1Z1B0m
/fKAZwQ2Z4xkB92hMuJFVtbARopEOoAJ2f9cy8WxBC0XSuJFocl50TTr8QKBgQCw
tXf5mWMPnIUqvsWnzCNqTpWODbpn49zi19YDWwHeVk5yCvpXRXJEunB0An75lWbj
BQchpgk6c/uSBRucgamP+p6+p27A2Qf7pqgFNNW1mZW2KFNyfnK3ZmIv51/ewaL/
drmVLqSaVHjJJRVkjzVs4FWmUqRkWMDcdt8hTbD14QKBgCXG95tlRPWPRQhdn0ai
l3WyNrZcTG8lK7vZv6v8iwshk5e+OILlgegI+86TzBgfvgLh/8TU14APc4s8Ti5T
m8E+4mriD54dtK/eyGafeQ33IsLs5hHF+/4jIwRHxcXo5lRhe/PXXFdIFHkWZx73
zh7lU9ejKMERgvaIgnapkEQ4
-----END PRIVATE KEY-----`;

// ─── JWT Builder (node crypto — no extra dependency) ───────────
function base64url(buf) {
    return buf.toString('base64')
        .replace(/\+/g, '-')
        .replace(/\//g, '_')
        .replace(/=+$/, '');
}

function generateJWT(userId, userName, roomId) {
    const now = Math.floor(Date.now() / 1000);

    const header = base64url(Buffer.from(JSON.stringify({
        alg: 'RS256',
        kid: KEY_ID,
        typ: 'JWT'
    })));

    const payload = base64url(Buffer.from(JSON.stringify({
        iss:     'chat',
        iat:     now,
        exp:     now + 7200,          // 2 ghante valid
        nbf:     now - 10,
        aud:     'jitsi',
        sub:     APP_ID,
        room:    roomId || '*',       // * = sab rooms access
        context: {
            user: {
                id:          userId   || 'anonymous',
                name:        userName || 'Guest',
                avatar:      '',
                email:       '',
                moderator:   'false'
            },
            features: {
                livestreaming: 'false',
                recording:     'false',
                transcription: 'false',
                'outbound-call': 'false'
            }
        }
    })));

    const sign = crypto.createSign('RSA-SHA256');
    sign.update(`${header}.${payload}`);
    const signature = base64url(sign.sign(PRIVATE_KEY));

    return `${header}.${payload}.${signature}`;
}

// ─── Cloud Function Entry Point ─────────────────────────────────
functions.http('generateJaaSToken', (req, res) => {
    // CORS — aapki domain se request allow karo
    res.set('Access-Control-Allow-Origin', '*');
    res.set('Access-Control-Allow-Methods', 'POST, OPTIONS');
    res.set('Access-Control-Allow-Headers', 'Content-Type');

    if (req.method === 'OPTIONS') {
        res.status(204).send('');
        return;
    }

    if (req.method !== 'POST') {
        res.status(405).json({ error: 'Only POST allowed' });
        return;
    }

    try {
        const { userId, userName, roomId } = req.body;

        if (!userId) {
            res.status(400).json({ error: 'userId required' });
            return;
        }

        const token = generateJWT(userId, userName, roomId);
        console.log(`[JaaS] Token generated for user: ${userId}, room: ${roomId}`);

        res.status(200).json({ token });

    } catch (err) {
        console.error('[JaaS] Token error:', err);
        res.status(500).json({ error: 'Token generation failed' });
    }
});
