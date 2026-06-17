const express = require('express');
const cors = require('cors');
const { v4: uuidv4 } = require('uuid');
const path = require('path');

const app = express();
app.set('trust proxy', true);
app.use(express.json());
app.use(cors());

const ROOT_TOKEN = process.env.ADMIN_ACCESS_KEY || "7c9e6b3a-5d2f-4c1a-8b9e-2f3a4b5c6d7e";
const tokenRegistry = {};
let activeSessions = [];

function authenticateRootRequest(req, res, next) {
    const inboundRootToken = req.headers['x-admin-key'] || req.query.AdminPanel;
    if (!inboundRootToken || inboundRootToken !== ROOT_TOKEN) {
        return res.status(403).json({ error: 'ACCESS_DENIED' });
    }
    next();
}

app.post('/admin/key', authenticateRootRequest, (req, res) => {
    const generatedToken = uuidv4();
    tokenRegistry[generatedToken] = { ip: null, status: 'Active' };
    res.json({ key: generatedToken, data: tokenRegistry[generatedToken] });
});

app.get('/admin/keys', authenticateRootRequest, (req, res) => {
    res.json(tokenRegistry);
});

app.delete('/admin/key/:key', authenticateRootRequest, (req, res) => {
    delete tokenRegistry[req.params.key];
    res.json({ success: true });
});

app.post('/api/update', (req, res) => {
    const { apiKey, username, sheckles, equippedPets, unequippedPets } = req.body;
    const clientIp = req.ip || req.headers['x-forwarded-for'] || req.socket.remoteAddress;

    if (!tokenRegistry[apiKey]) return res.status(401).json({ error: 'INVALID_TOKEN' });

    if (!tokenRegistry[apiKey].ip) {
        tokenRegistry[apiKey].ip = clientIp;
    } else if (tokenRegistry[apiKey].ip !== clientIp) {
        return res.status(403).json({ error: 'IP_MUTATION_BLOCKED' });
    }

    const timestamp = Date.now();
    const sessionIndex = activeSessions.findIndex(session => session.username === username && session.apiKey === apiKey);
    const payload = { apiKey, username, sheckles, equippedPets, unequippedPets, lastUpdated: timestamp };

    if (sessionIndex > -1) {
        activeSessions[sessionIndex] = payload;
    } else {
        activeSessions.push(payload);
    }

    res.json({ success: true });
});

app.get('/api/dashboard/:key', (req, res) => {
    const targetToken = req.params.key;
    if (!tokenRegistry[targetToken]) return res.status(401).json({ error: 'INVALID_TOKEN' });

    const currentTimestamp = Date.now();
    const TTL_EXPIRATION = 24 * 60 * 60 * 1000;

    activeSessions = activeSessions.filter(session => currentTimestamp - session.lastUpdated < TTL_EXPIRATION);
    
    const operationalData = activeSessions.filter(session => session.apiKey === targetToken);
    res.json(operationalData);
});

app.get('/', (req, res) => {
    if (req.query.AdminPanel === ROOT_TOKEN) {
        return res.sendFile(path.join(__dirname, 'admin.html'));
    }
    res.sendFile(path.join(__dirname, 'index.html'));
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
    console.log(`Server initialized on port ${PORT}`);
});
