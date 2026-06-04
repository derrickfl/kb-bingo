/**
 * KB BINGO - Professional Backend Server
 * =======================================
 * Run: node kb-bingo-backend.js
 * Requires: npm install express ws bcryptjs jsonwebtoken uuid
 *
 * Architecture:
 *  - Express REST API  → Auth, wallet, history
 *  - WebSocket Server  → Real-time multiplayer game rooms
 *  - In-memory DB      → Replace with MongoDB/PostgreSQL for production
 */

const express    = require('express');
const http       = require('http');
const WebSocket  = require('ws');
const bcrypt     = require('bcryptjs');
const jwt        = require('jsonwebtoken');
const { v4: uuidv4 } = require('uuid');
const path       = require('path');

const app    = express();
const server = http.createServer(app);
const wss    = new WebSocket.Server({ server });

const PORT       = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'kb-bingo-secret-change-in-prod';
const HOUSE_CUT  = 0.20; // 20% house edge

app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

// ══════════════════════════════════════════════
//  IN-MEMORY DATABASE  (swap for real DB later)
// ══════════════════════════════════════════════
const DB = {
  users:        new Map(),   // phone → user object
  sessions:     new Map(),   // token → userId
  transactions: new Map(),   // userId → tx[]
  rooms:        new Map(),   // roomId → room object
};

// ── Default admin seeded
const adminId = uuidv4();
DB.users.set('251900000000', {
  id: adminId, phone: '251900000000',
  passwordHash: bcrypt.hashSync('Admin@1234', 10),
  name: 'Admin', balance: 10000, role: 'admin',
  createdAt: new Date().toISOString(),
});
DB.transactions.set(adminId, []);

// ══════════════════════════════════════════════
//  HELPERS
// ══════════════════════════════════════════════
function generateToken(userId) {
  return jwt.sign({ userId }, JWT_SECRET, { expiresIn: '7d' });
}
function verifyToken(req) {
  const auth = req.headers.authorization || '';
  const token = auth.replace('Bearer ', '');
  if (!token) return null;
  try { return jwt.verify(token, JWT_SECRET); }
  catch { return null; }
}
function authMiddleware(req, res, next) {
  const payload = verifyToken(req);
  if (!payload) return res.status(401).json({ error: 'Unauthorized' });
  const user = [...DB.users.values()].find(u => u.id === payload.userId);
  if (!user) return res.status(401).json({ error: 'User not found' });
  req.user = user;
  next();
}
function sanitizeUser(u) {
  const { passwordHash, ...safe } = u;
  return safe;
}
function addTransaction(userId, type, amount, note, status = 'completed') {
  const txs = DB.transactions.get(userId) || [];
  txs.unshift({
    id: uuidv4(), type, amount, note, status,
    createdAt: new Date().toISOString(),
  });
  DB.transactions.set(userId, txs);
}
function validateEthiopianPhone(phone) {
  return /^251[79]\d{8}$/.test(phone);
}

// ══════════════════════════════════════════════
//  AUTH ROUTES
// ══════════════════════════════════════════════

// POST /api/auth/register
app.post('/api/auth/register', async (req, res) => {
  const { phone, password, name } = req.body;
  if (!phone || !password || !name)
    return res.status(400).json({ error: 'ስም፣ ስልክ እና ፓስወርድ ያስፈልጋል' });
  if (!validateEthiopianPhone(phone))
    return res.status(400).json({ error: 'ትክክለኛ የኢትዮጵያ ቁጥር ያስገቡ (251xx...)' });
  if (DB.users.has(phone))
    return res.status(400).json({ error: 'ይህ ስልክ ቁጥር አስቀድሞ ተመዝግቧል' });
  if (password.length < 6)
    return res.status(400).json({ error: 'ፓስወርድ ቢያንስ 6 ፊደል ሊኖረው ይገባል' });

  const passwordHash = await bcrypt.hash(password, 10);
  const userId = uuidv4();
  const user = {
    id: userId, phone, name,
    passwordHash, balance: 0, role: 'user',
    createdAt: new Date().toISOString(),
    bonus: 0, gamesPlayed: 0, totalWon: 0,
  };
  DB.users.set(phone, user);
  DB.transactions.set(userId, []);
  // Welcome bonus log slot
  addTransaction(userId, 'bonus', 0, 'ወደ KB BINGO እንኳን ደህና መጡ!', 'completed');
  const token = generateToken(userId);
  res.json({ token, user: sanitizeUser(user) });
});

// POST /api/auth/login
app.post('/api/auth/login', async (req, res) => {
  const { phone, password } = req.body;
  if (!phone || !password)
    return res.status(400).json({ error: 'ስልክ እና ፓስወርድ ያስፈልጋል' });
  const user = DB.users.get(phone);
  if (!user) return res.status(400).json({ error: 'ስልክ ቁጥሩ አልተገኘም' });
  const ok = await bcrypt.compare(password, user.passwordHash);
  if (!ok) return res.status(400).json({ error: 'ፓስወርዱ ትክክል አይደለም' });
  const token = generateToken(user.id);
  res.json({ token, user: sanitizeUser(user) });
});

// GET /api/auth/me
app.get('/api/auth/me', authMiddleware, (req, res) => {
  res.json({ user: sanitizeUser(req.user) });
});

// ══════════════════════════════════════════════
//  WALLET ROUTES
// ══════════════════════════════════════════════

// POST /api/wallet/deposit  (manual TeleBirr — admin confirms)
app.post('/api/wallet/deposit', authMiddleware, (req, res) => {
  const { amount, telebirrPhone, smsCode } = req.body;
  const amt = parseFloat(amount);
  if (!amt || amt < 50)
    return res.status(400).json({ error: 'ቢያንስ 50 ETB ማስገባት ይቻላል' });
  if (!telebirrPhone || !smsCode)
    return res.status(400).json({ error: 'TeleBirr ቁጥር እና SMS ኮድ ያስፈልጋሉ' });

  // In production: verify SMS code with TeleBirr API here
  // For demo: auto-approve
  req.user.balance += amt;
  const isFirst = (DB.transactions.get(req.user.id) || [])
    .filter(t => t.type === 'deposit').length === 0;
  if (isFirst) {
    const bonus = Math.floor(amt * 0.10);
    req.user.balance += bonus;
    addTransaction(req.user.id, 'bonus', bonus, '10% First Deposit Bonus', 'completed');
  }
  addTransaction(req.user.id, 'deposit', amt, `TeleBirr ${telebirrPhone}`, 'completed');
  res.json({ balance: req.user.balance, message: 'ተቀባይነት አግኝቷል!' });
});

// POST /api/wallet/withdraw
app.post('/api/wallet/withdraw', authMiddleware, (req, res) => {
  const { amount, telebirrPhone } = req.body;
  const amt = parseFloat(amount);
  if (!amt || amt < 50)
    return res.status(400).json({ error: 'ቢያንስ 50 ETB ማዉጣት ይቻላል' });
  if (amt > req.user.balance)
    return res.status(400).json({ error: 'በቂ ሂሳብ የለም' });
  req.user.balance -= amt;
  addTransaction(req.user.id, 'withdraw', -amt, `TeleBirr ${telebirrPhone}`, 'pending');
  res.json({ balance: req.user.balance, message: 'ጥያቄ ተልኳል! ከ 1-10 ደቂቃ ውስጥ ይደርሳል' });
});

// GET /api/wallet/transactions
app.get('/api/wallet/transactions', authMiddleware, (req, res) => {
  const txs = DB.transactions.get(req.user.id) || [];
  res.json({ transactions: txs });
});

// GET /api/wallet/balance
app.get('/api/wallet/balance', authMiddleware, (req, res) => {
  res.json({ balance: req.user.balance });
});

// ══════════════════════════════════════════════
//  ROOMS / GAME API
// ══════════════════════════════════════════════

// GET /api/rooms — list open rooms
app.get('/api/rooms', authMiddleware, (req, res) => {
  const list = [...DB.rooms.values()]
    .filter(r => r.status === 'waiting' || r.status === 'playing')
    .map(r => ({
      id: r.id, stake: r.stake, playerCount: r.players.length,
      maxPlayers: r.maxPlayers, status: r.status, prizePool: r.prizePool,
    }));
  res.json({ rooms: list });
});

// ══════════════════════════════════════════════
//  WEBSOCKET — REAL-TIME GAME ENGINE
// ══════════════════════════════════════════════
/*
  Message types (client → server):
    join_room   { roomId, stake, cardId }
    mark_cell   { roomId, number }
    claim_bingo { roomId }
    ping        {}

  Message types (server → client):
    room_state  { room, yourCard }
    number_called { number, callCount, calledNumbers }
    player_joined { player }
    player_left   { playerId }
    bingo_winner  { winner, prize, callCount }
    error         { message }
    pong          {}
*/

const clients = new Map(); // ws → { userId, roomId, cardId }

function send(ws, type, data) {
  if (ws.readyState === WebSocket.OPEN)
    ws.send(JSON.stringify({ type, ...data }));
}
function broadcast(roomId, type, data, excludeWs = null) {
  wss.clients.forEach(ws => {
    const meta = clients.get(ws);
    if (meta && meta.roomId === roomId && ws !== excludeWs)
      send(ws, type, data);
  });
}
function broadcastAll(roomId, type, data) {
  broadcast(roomId, type, data);
}

// ── BINGO CARD GENERATOR (seeded)
function generateCard(seed) {
  let s = seed;
  const rnd = () => { const x = Math.sin(s++) * 10000; return x - Math.floor(x); };
  const cols = [];
  for (let i = 0; i < 5; i++) {
    const pool = Array.from({ length: 15 }, (_, idx) => i * 15 + 1 + idx);
    for (let j = pool.length - 1; j > 0; j--) {
      const k = Math.floor(rnd() * (j + 1));
      [pool[j], pool[k]] = [pool[k], pool[j]];
    }
    cols.push(pool.slice(0, 5).sort((a, b) => a - b));
  }
  // Flatten row-major: [B0,I0,N0,G0,O0, B1,I1,...]
  const flat = [];
  for (let r = 0; r < 5; r++)
    for (let c = 0; c < 5; c++)
      flat.push(r === 2 && c === 2 ? 'FREE' : cols[c][r]);
  return flat;
}

// ── CHECK BINGO SERVER-SIDE
const BINGO_PATTERNS = [
  [0,1,2,3,4],[5,6,7,8,9],[10,11,12,13,14],[15,16,17,18,19],[20,21,22,23,24],
  [0,5,10,15,20],[1,6,11,16,21],[2,7,12,17,22],[3,8,13,18,23],[4,9,14,19,24],
  [0,6,12,18,24],[4,8,12,16,20],
];
function checkBingoServer(card, calledSet) {
  const marked = card.map((v, i) => v === 'FREE' || calledSet.has(v));
  return BINGO_PATTERNS.some(p => p.every(i => marked[i]));
}

// ── ROOM FACTORY
function createRoom(stake) {
  const id = uuidv4();
  const room = {
    id, stake, status: 'waiting',
    players: [], maxPlayers: 50,
    calledNumbers: [], calledSet: new Set(),
    prizePool: 0, callInterval: null,
    startTimeout: null, callCount: 0,
  };
  DB.rooms.set(id, room);
  return room;
}

// ── FIND OR CREATE ROOM for a stake
function findRoom(stake) {
  for (const room of DB.rooms.values()) {
    if (room.stake === stake && room.status === 'waiting' && room.players.length < room.maxPlayers)
      return room;
  }
  return createRoom(stake);
}

// ── START GAME
function startGame(room) {
  if (room.status !== 'waiting') return;
  room.status = 'playing';
  room.prizePool = Math.floor(room.players.length * room.stake * (1 - HOUSE_CUT));
  broadcastAll(room.id, 'game_start', {
    prizePool: room.prizePool,
    playerCount: room.players.length,
    countdown: 3,
  });

  // Auto-call every 3 seconds
  room.callInterval = setInterval(() => {
    if (room.calledNumbers.length >= 75) {
      clearInterval(room.callInterval);
      broadcastAll(room.id, 'game_over', { message: 'ጨዋታ ተጠናቋል — ወደ አዲስ ጨዋታ ይሂዱ' });
      room.status = 'finished';
      return;
    }
    let n;
    do { n = Math.floor(Math.random() * 75) + 1; } while (room.calledSet.has(n));
    room.calledNumbers.push(n);
    room.calledSet.add(n);
    room.callCount++;
    broadcastAll(room.id, 'number_called', {
      number: n,
      callCount: room.callCount,
      calledNumbers: room.calledNumbers,
    });
  }, 3000);
}

// ── WEBSOCKET HANDLER
wss.on('connection', (ws) => {
  clients.set(ws, { userId: null, roomId: null, cardId: null });

  ws.on('message', (raw) => {
    let msg;
    try { msg = JSON.parse(raw); } catch { return; }

    const meta = clients.get(ws);

    switch (msg.type) {

      // ── AUTHENTICATE
      case 'auth': {
        try {
          const payload = jwt.verify(msg.token, JWT_SECRET);
          const user = [...DB.users.values()].find(u => u.id === payload.userId);
          if (!user) { send(ws, 'error', { message: 'Invalid token' }); return; }
          meta.userId = user.id;
          send(ws, 'auth_ok', { user: sanitizeUser(user) });
        } catch { send(ws, 'error', { message: 'Token expired' }); }
        break;
      }

      // ── JOIN ROOM
      case 'join_room': {
        if (!meta.userId) { send(ws, 'error', { message: 'Login required' }); return; }
        const { stake, cardId } = msg;
        const user = [...DB.users.values()].find(u => u.id === meta.userId);
        if (!user) return;
        if (user.balance < stake) {
          send(ws, 'error', { message: 'በቂ ሂሳብ የለም። ያስቀምጡ።' }); return;
        }

        // Deduct stake
        user.balance -= stake;
        addTransaction(user.id, 'bet', -stake, `ጨዋታ ${stake} ETB`, 'completed');

        const room = findRoom(stake);
        const card = generateCard(cardId + room.id.charCodeAt(0));
        meta.roomId = room.id;
        meta.cardId = cardId;
        meta.card   = card;

        room.players.push({
          id: user.id, name: user.name,
          card, ws, marked: new Set([12]), // FREE center
        });

        send(ws, 'room_joined', {
          roomId: room.id,
          card,
          stake,
          playerCount: room.players.length,
          balance: user.balance,
          calledNumbers: room.calledNumbers, // in case joining mid-game
          prizePool: room.prizePool,
          status: room.status,
        });

        broadcast(room.id, 'player_joined', {
          player: { id: user.id, name: user.name },
          playerCount: room.players.length,
        }, ws);

        // Auto-start after 20s or if 50 players
        if (room.status === 'waiting') {
          if (room.players.length >= room.maxPlayers) {
            if (room.startTimeout) clearTimeout(room.startTimeout);
            startGame(room);
          } else if (!room.startTimeout) {
            room.startTimeout = setTimeout(() => startGame(room), 20000);
          }
        }
        break;
      }

      // ── CLAIM BINGO
      case 'claim_bingo': {
        if (!meta.userId || !meta.roomId) return;
        const room = DB.rooms.get(meta.roomId);
        if (!room || room.status !== 'playing') {
          send(ws, 'error', { message: 'ጨዋታ ገና አልጀመረም' }); return;
        }
        // Find this player
        const player = room.players.find(p => p.id === meta.userId);
        if (!player) return;

        // Server-side verify
        const won = checkBingoServer(player.card, room.calledSet);
        if (!won) {
          send(ws, 'false_bingo', { message: '⚠️ ቢንጎ ገና ነው!' }); return;
        }

        // Winner!
        clearInterval(room.callInterval);
        room.status = 'finished';
        const winner = [...DB.users.values()].find(u => u.id === meta.userId);
        if (winner) {
          winner.balance += room.prizePool;
          winner.totalWon = (winner.totalWon || 0) + room.prizePool;
          winner.gamesPlayed = (winner.gamesPlayed || 0) + 1;
          addTransaction(winner.id, 'win', room.prizePool, `BINGO WIN — ${room.callCount} calls`, 'completed');
        }
        broadcastAll(room.id, 'bingo_winner', {
          winner: { id: meta.userId, name: winner?.name || 'Player' },
          prize: room.prizePool,
          callCount: room.callCount,
          balance: winner?.balance,
        });
        break;
      }

      // ── PING
      case 'ping':
        send(ws, 'pong', { ts: Date.now() });
        break;
    }
  });

  ws.on('close', () => {
    const meta = clients.get(ws);
    if (meta?.roomId) {
      const room = DB.rooms.get(meta.roomId);
      if (room) {
        room.players = room.players.filter(p => p.id !== meta.userId);
        broadcast(meta.roomId, 'player_left', {
          playerId: meta.userId,
          playerCount: room.players.length,
        });
        if (room.players.length === 0 && room.status === 'waiting') {
          clearTimeout(room.startTimeout);
          DB.rooms.delete(meta.roomId);
        }
      }
    }
    clients.delete(ws);
  });
});

// ══════════════════════════════════════════════
//  ADMIN ROUTES
// ══════════════════════════════════════════════
app.get('/api/admin/users', authMiddleware, (req, res) => {
  if (req.user.role !== 'admin') return res.status(403).json({ error: 'Forbidden' });
  const users = [...DB.users.values()].map(sanitizeUser);
  res.json({ users });
});
app.get('/api/admin/rooms', authMiddleware, (req, res) => {
  if (req.user.role !== 'admin') return res.status(403).json({ error: 'Forbidden' });
  const rooms = [...DB.rooms.values()].map(r => ({
    ...r, players: r.players.map(p => ({ id: p.id, name: p.name })),
  }));
  res.json({ rooms });
});
// Manually confirm withdrawal
app.post('/api/admin/confirm-withdrawal', authMiddleware, (req, res) => {
  if (req.user.role !== 'admin') return res.status(403).json({ error: 'Forbidden' });
  const { userId, txId } = req.body;
  const txs = DB.transactions.get(userId) || [];
  const tx = txs.find(t => t.id === txId);
  if (!tx) return res.status(404).json({ error: 'TX not found' });
  tx.status = 'completed';
  res.json({ ok: true });
});

// ══════════════════════════════════════════════
//  START
// ══════════════════════════════════════════════
server.listen(PORT, () => {
  console.log(`\n🎰 KB BINGO Server running on http://localhost:${PORT}`);
  console.log(`📡 WebSocket ready on ws://localhost:${PORT}`);
  console.log(`\nAdmin: phone=251900000000 / password=Admin@1234\n`);
});

module.exports = { app, server };
