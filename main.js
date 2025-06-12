const express = require('express');
const fs = require('fs');
const crypto = require('crypto');

const app = express();
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

const KEYS_FILE = 'keys.json';

const STORED_LOGIN_HASH = '8c6976e5b5410415bde908bd4dee15dfb167a9c873fc4bb8a81f6f2ab448a918';
const STORED_PASSWORD_HASH = '8825c1e5c216ced76e5b72ed6d38e0b70272cfbed02febf0782be0203e6e3861';

function readKeys() {
    if (!fs.existsSync(KEYS_FILE)) {
        fs.writeFileSync(KEYS_FILE, JSON.stringify({}));
    }
    const data = fs.readFileSync(KEYS_FILE);
    return JSON.parse(data);
}

function writeKeys(keys) {
    fs.writeFileSync(KEYS_FILE, JSON.stringify(keys, null, 2));
}

function hashString(str) {
    return crypto.createHash('sha256').update(str).digest('hex');
}

function authMiddleware(req, res, next) {
    if (req.path === '/activate') {
        return next();
    }
    const login = req.headers['x-login'];
    const password = req.headers['x-password'];
    if (!login || !password) {
        return res.status(401).json({ error: 'Authorization required' });
    }
    const loginHash = hashString(login);
    const passwordHash = hashString(password);
    if (loginHash !== STORED_LOGIN_HASH || passwordHash !== STORED_PASSWORD_HASH) {
        return res.status(403).json({ error: 'Invalid credentials' });
    }
    next();
}

app.use(authMiddleware);

const ALGORITHM = 'aes-256-cbc';
const SECRET_KEY = crypto.createHash('sha256').update('c322570df7925ad7daced4173df308a00a979a29eaf356889a750017c7407f13').digest();
const IV_LENGTH = 16;

function encryptDate(dateStr) {
    const iv = crypto.randomBytes(IV_LENGTH);
    const cipher = crypto.createCipheriv(ALGORITHM, SECRET_KEY, iv);
    let encrypted = cipher.update(dateStr, 'utf8', 'hex');
    encrypted += cipher.final('hex');
    return iv.toString('hex') + ':' + encrypted;
}

function decryptDate(encryptedStr) {
    const parts = encryptedStr.split(':');
    if (parts.length !== 2) throw new Error('Invalid encrypted data');
    const iv = Buffer.from(parts[0], 'hex');
    const encryptedText = parts[1];
    const decipher = crypto.createDecipheriv(ALGORITHM, SECRET_KEY, iv);
    let decrypted = decipher.update(encryptedText, 'hex', 'utf8');
    decrypted += decipher.final('utf8');
    return decrypted;
}

function isExpired(encryptedDate) {
    try {
        const decryptedDateStr = decryptDate(encryptedDate);
        return Date.now() > new Date(decryptedDateStr).getTime();
    } catch (e) {
        return true;
    }
}

app.post('/activate', (req, res) => {
    const { key, device } = req.body;
    if (!key || !device) {
        return res.status(400).json({ error: 'Key and device are required' });
    }
    const keysObj = readKeys();
    if (!(key in keysObj) || isExpired(key)) {
        return res.json(false);
    }
    const currentValue = keysObj[key];
    const deviceHash = hashString(device);
    if (!currentValue) {
        keysObj[key] = deviceHash;
        writeKeys(keysObj);
        return res.json(true);
    } else {
        return res.json(currentValue === deviceHash);
    }
});

app.post('/addKey', (req, res) => {
   const { date } = req.body;
   if (!date) {
       return res.status(400).json({ error: 'Date is required' });
   }
   const encryptedKey = encryptDate(date);
   const keysObj = readKeys();
   if (encryptedKey in keysObj) {
       return res.status(400).json({ error: 'Encrypted key already exists' });
   }
   keysObj[encryptedKey] = null;
   writeKeys(keysObj);
   res.json({ encryptedKey });
});

app.delete('/deleteKey/:key', (req, res) => {
   const key = req.params.key;
   if (!key) {
       return res.status(400).json({ error: 'Key is required' });
   }
   const keysObj = readKeys();
   if (key in keysObj) {
       delete keysObj[key];
       writeKeys(keysObj);
       return res.json({ success: true });
   } else {
       return res.status(404).json({ success: false });
   }
});

app.put('/clearExpired', (req, res) => {
   const keysObj = readKeys();
   const removedKeys = [];
   for (const key in {...keysObj}) { 
       try {
           if (isExpired(key)) {
               delete keysObj[key];
               removedKeys.push(key);
           }
       } catch(e) {}
   }
   writeKeys(keysObj);
   res.json({ removedKeys });
});

app.get('/getKeys', (req, res) => {
   try {
       const data = fs.readFileSync(KEYS_FILE);
       const jsonData = JSON.parse(data);
       res.json(jsonData);
   } catch(e) {
       res.status(500).json({ error: 'Failed to read keys file' });
   }
});

app.put('/updateKeys', (req, res) => {
   if (Array.isArray(req.body)) {
       res.status(400).json({ error: 'Expected an object' });
  } else {
       writeKeys(req.body);
       res.json({ success: true });
  }
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
   if (!fs.existsSync(KEYS_FILE)) {
       fs.writeFileSync(KEYS_FILE, JSON.stringify({}), 'utf8');
   }
   console.log(`Server running on port ${PORT}`);
});