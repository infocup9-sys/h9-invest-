const express = require('express');
const cors = require('cors');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const mongoose = require('mongoose');

const app = express();
const PORT = process.env.PORT || 10000;
const JWT_SECRET = process.env.JWT_SECRET || 'chiave_segreta_molto_sicura';
const MONGO_URI = process.env.MONGO_URI;

app.use(cors());
app.use(express.json());

// Connessione al database MongoDB Reale
mongoose.connect(MONGO_URI)
  .then(() => console.log('Connesso al database MongoDB con successo'))
  .catch(err => console.error('Errore di connessione a MongoDB:', err));

// Schema Utente Reale
const userSchema = new mongoose.Schema({
  username: { type: String, required: true },
  email: { type: String, required: true, unique: true },
  password: { type: String, required: true },
  balances: {
    deposit: { type: Number, default: 0 },
    earnings: { type: Number, default: 0 }
  },
  investments: [{
    id: String,
    plan_name: String,
    duration_days: Number,
    principal: Number,
    earnings_credited: { type: Number, default: 0 },
    status: { type: String, default: 'active' },
    matures_at: String
  }],
  transactions: [{
    id: String,
    type: String, // 'deposit' o 'withdrawal'
    amount: Number,
    method: String,
    status: String,
    created_at: { type: String, default: () => new Date().toISOString() }
  }],
  status: { type: String, default: 'approved' }
});

const User = mongoose.model('User', userSchema);

const PLANS = [
  { id: 'plan-30', name: 'Piano 30 giorni', duration_days: 30, daily_rate_pct: 0.88, min_amount: 10 },
  { id: 'plan-60', name: 'Piano 60 giorni', duration_days: 60, daily_rate_pct: 1.23, min_amount: 10 },
  { id: 'plan-90', name: 'Piano 90 giorni', duration_days: 90, daily_rate_pct: 1.68, min_amount: 10 }
];

// Middleware di autenticazione Bearer Token
function authenticateToken(req, res, next) {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];
  if (!token) return res.status(401).json({ error: 'Token mancante' });

  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) return res.status(403).json({ error: 'Token non valido o scaduto' });
    req.user = user;
    next();
  });
}

// 1. Registrazione Reale
app.post('/api/auth/register', async (req, res) => {
  try {
    const { username, email, password } = req.body;
    if (!username || !email || !password) {
      return res.status(400).json({ error: 'Campi obbligatori mancanti' });
    }

    const existingUser = await User.findOne({ email });
    if (existingUser) {
      return res.status(400).json({ error: 'Email già registrata' });
    }

    const hashedPassword = await bcrypt.hash(password, 10);
    const newUser = new User({
      username,
      email,
      password: hashedPassword
    });

    await newUser.save();
    res.json({ requires_otp: false, message: 'Account registrato con successo' });
  } catch (err) {
    res.status(500).json({ error: 'Errore interno del server' });
  }
});

// 2. Login Reale
app.post('/api/auth/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    const user = await User.findOne({ email });
    if (!user) return res.status(400).json({ error: 'Credenziali non valide' });

    const validPassword = await bcrypt.compare(password, user.password);
    if (!validPassword) return res.status(400).json({ error: 'Credenziali non valide' });

    const access_token = jwt.sign({ id: user._id, email: user.email }, JWT_SECRET, { expiresIn: '7d' });
    res.json({ access_token, user: { username: user.username, email: user.email } });
  } catch (err) {
    res.status(500).json({ error: 'Errore interno del server' });
  }
});

// 3. Dati Conto Reale
app.get('/api/account', authenticateToken, async (req, res) => {
  try {
    const user = await User.findById(req.user.id);
    if (!user) return res.status(404).json({ error: 'Utente non trovato' });

    res.json({
      user: { username: user.username, email: user.email },
      balances: user.balances,
      investments: user.investments,
      transactions: user.transactions,
      updated_at: new Date().toISOString()
    });
  } catch (err) {
    res.status(500).json({ error: 'Errore interno del server' });
  }
});

// 4. Piani di investimento
app.get('/api/plans', (req, res) => {
  res.json({ plans: PLANS });
});

// 5. Creazione Investimento Reale
app.post('/api/investments', authenticateToken, async (req, res) => {
  try {
    const { plan_id, amount } = req.body;
    const user = await User.findById(req.user.id);
    const plan = PLANS.find(p => p.id === plan_id);

    if (!plan || !amount || amount <= 0) {
      return res.status(400).json({ error: 'Dati investimento non validi' });
    }

    if (user.balances.deposit < amount) {
      return res.status(400).json({ error: 'Saldo deposito insufficiente' });
    }

    user.balances.deposit -= amount;

    const investment = {
      id: Date.now().toString(),
      plan_name: plan.name,
      duration_days: plan.duration_days,
      principal: amount,
      earnings_credited: 0,
      status: 'active',
      matures_at: new Date(Date.now() + plan.duration_days * 86400000).toISOString()
    };

    user.investments.push(investment);
    await user.save();

    res.json({ message: 'Investimento avviato con successo', investment });
  } catch (err) {
    res.status(500).json({ error: 'Errore interno del server' });
  }
});

// 6. Deposito Reale
app.post('/api/deposit', authenticateToken, async (req, res) => {
  try {
    const { amount, method } = req.body;
    const user = await User.findById(req.user.id);

    if (!amount || amount <= 0) {
      return res.status(400).json({ error: 'Importo non valido' });
    }

    const tx = {
      id: Date.now().toString(),
      type: 'deposit',
      amount,
      method: method || 'Crypto',
      status: 'completed',
      created_at: new Date().toISOString()
    };

    user.transactions.push(tx);
    user.balances.deposit += Number(amount);
    await user.save();

    res.json({ message: 'Deposito registrato con successo', transaction: tx });
  } catch (err) {
    res.status(500).json({ error: 'Errore interno del server' });
  }
});

// 7. Prelievo Reale
app.post('/api/withdraw', authenticateToken, async (req, res) => {
  try {
    const { amount, address } = req.body;
    const user = await User.findById(req.user.id);

    if (!amount || amount <= 0) {
      return res.status(400).json({ error: 'Importo non valido' });
    }

    if (user.balances.deposit < amount) {
      return res.status(400).json({ error: 'Saldo disponibile insufficiente' });
    }

    user.balances.deposit -= Number(amount);

    const tx = {
      id: Date.now().toString(),
      type: 'withdrawal',
      amount,
      method: address || 'Crypto Wallet',
      status: 'completed',
      created_at: new Date().toISOString()
    };

    user.transactions.push(tx);
    await user.save();

    res.json({ message: 'Prelievo effettuato con successo', transaction: tx });
  } catch (err) {
    res.status(500).json({ error: 'Errore interno del server' });
  }
});

app.listen(PORT, () => {
  console.log(`Server reale avviato sulla porta ${PORT}`);
});


const express = require('express');
const cors = require('cors');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const mongoose = require('mongoose');

const app = express();
const PORT = process.env.PORT || 10000;
const JWT_SECRET = process.env.JWT_SECRET || 'chiave_segreta_molto_sicura';
const MONGO_URI = process.env.MONGO_URI;

app.use(cors());
app.use(express.json());

// Connessione al database MongoDB reale
mongoose.connect(MONGO_URI)
  .then(() => console.log('Database MongoDB connesso con successo'))
  .catch(err => console.error('Errore di connessione a MongoDB:', err));

// Schema e Modello Utente
const userSchema = new mongoose.Schema({
  username: { type: String, required: true },
  email: { type: String, required: true, unique: true },
  passwordHash: { type: String, required: true },
  role: { type: String, default: 'user' },
  status: { type: String, default: 'approved' },
  wallet: {
    deposit: { type: Number, default: 0 },
    earnings: { type: Number, default: 0 }
  },
  investments: { type: Array, default: [] },
  transactions: { type: Array, default: [] },
  depositRequests: { type: Array, default: [] },
  withdrawalRequests: { type: Array, default: [] },
  preferences: { type: Object, default: { language: 'it', theme: 'dark' } },
  withdrawalWallet: { type: Object, default: null },
  h9Points: { type: Number, default: 0 },
  bonusSpins: { type: Number, default: 0 },
  pointHistory: { type: Array, default: [] },
  referrals: { type: Array, default: [] },
  activeBonuses: { type: Array, default: [] },
  rewardRedemptions: { type: Array, default: [] },
  dailyPrizes: { type: Array, default: [] },
  referralCode: { type: String },
  lastDailyPrizeDate: { type: String, default: null },
  revision: { type: Number, default: 1 },
  createdAt: { type: Number, default: Date.now }
});

const User = mongoose.model('User', userSchema);

// Middleware di autenticazione Bearer Token
function authenticateToken(req, res, next) {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];
  if (!token) return res.status(401).json({ error: 'Token mancante' });

  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) return res.status(403).json({ error: 'Token non valido o scaduto' });
    req.user = user;
    next();
  });
}

// 1. Registrazione account reale
app.post('/api/auth/register', async (req, res) => {
  try {
    const { username, email, password } = req.body;
    if (!username || !email || !password) {
      return res.status(400).json({ error: 'Campi obbligatori mancanti' });
    }

    const existingUser = await User.findOne({ email });
    if (existingUser) {
      return res.status(400).json({ error: 'Email già registrata' });
    }

    const saltRounds = 10;
    const passwordHash = await bcrypt.hash(password, saltRounds);
    
    const count = await User.countDocuments();
    const role = count === 0 ? 'admin' : 'user';

    const newUser = new User({
      username,
      email,
      passwordHash,
      role,
      referralCode: Math.random().toString(36).substring(2, 9).toUpperCase()
    });

    await newUser.save();
    const token = jwt.sign({ id: newUser._id, email: newUser.email }, JWT_SECRET, { expiresIn: '7d' });

    res.json({ token, account: newUser });
  } catch (err) {
    res.status(500).json({ error: 'Errore interno del server' });
  }
});

// 2. Login reale
app.post('/api/auth/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    const user = await User.findOne({ email });
    if (!user) return res.status(400).json({ error: 'Credenziali non valide' });

    const validPassword = await bcrypt.compare(password, user.passwordHash);
    if (!validPassword) return res.status(400).json({ error: 'Credenziali non valide' });

    const token = jwt.sign({ id: user._id, email: user.email }, JWT_SECRET, { expiresIn: '7d' });
    res.json({ token, account: user });
  } catch (err) {
    res.status(500).json({ error: 'Errore interno del server' });
  }
});

// 3. Logout
app.post('/api/auth/logout', authenticateToken, (req, res) => {
  res.json({ ok: true });
});

// 4. Dati Conto Corrente
app.get('/api/account', authenticateToken, async (req, res) => {
  try {
    const user = await User.findById(req.user.id);
    if (!user) return res.status(404).json({ error: 'Account non trovato' });
    res.json({ account: user });
  } catch (err) {
    res.status(500).json({ error: 'Errore interno del server' });
  }
});

// 5. Aggiornamento Conto / Preferenze
app.put('/api/account', authenticateToken, async (req, res) => {
  try {
    const user = await User.findById(req.user.id);
    if (!user) return res.status(404).json({ error: 'Account non trovato' });

    Object.assign(user, req.body);
    user.revision = (user.revision || 1) + 1;
    await user.save();

    res.json({ account: user });
  } catch (err) {
    res.status(500).json({ error: 'Errore interno del server' });
  }
});

// 6. Gestione Admin - Elenco Account
app.get('/api/admin/accounts', authenticateToken, async (req, res) => {
  try {
    const admin = await User.findById(req.user.id);
    if (!admin || admin.role !== 'admin') return res.status(403).json({ error: 'Non autorizzato' });

    const accounts = await User.find({});
    res.json({ accounts });
  } catch (err) {
    res.status(500).json({ error: 'Errore interno del server' });
  }
});

// 7. Depositi Reali
app.post('/api/deposits', authenticateToken, async (req, res) => {
  try {
    const { amount, network, txHash } = req.body;
    const user = await User.findById(req.user.id);

    const depositReq = {
      id: Date.now().toString(),
      amount,
      network,
      txHash,
      status: 'pending',
      createdAt: Date.now()
    };

    user.depositRequests.unshift(depositReq);
    await user.save();
    res.json({ account: user });
  } catch (err) {
    res.status(500).json({ error: 'Errore interno del server' });
  }
});

// 8. Prelievi Reali
app.post('/api/withdrawals', authenticateToken, async (req, res) => {
  try {
    const { amount, network, address } = req.body;
    const user = await User.findById(req.user.id);

    if (user.wallet.earnings < amount) {
      return res.status(400).json({ error: 'Saldo guadagni insufficiente' });
    }

    user.wallet.earnings -= Number(amount);
    const withdrawalReq = {
      id: Date.now().toString(),
      amount,
      network,
      address,
      status: 'pending',
      createdAt: Date.now()
    };

    user.withdrawalRequests.unshift(withdrawalReq);
    await user.save();
    res.json({ account: user });
  } catch (err) {
    res.status(500).json({ error: 'Errore interno del server' });
  }
});

// 9. Creazione Investimento Reale
app.post('/api/investments', authenticateToken, async (req, res) => {
  try {
    const { amount, planId } = req.body;
    const user = await User.findById(req.user.id);

    if (user.wallet.deposit < amount) {
      return res.status(400).json({ error: 'Saldo deposito insufficiente' });
    }

    user.wallet.deposit -= Number(amount);
    const investment = {
      id: Date.now().toString(),
      planId,
      principal: amount,
      startedAt: Date.now(),
      status: 'active'
    };

    user.investments.unshift(investment);
    await user.save();
    res.json({ account: user });
  } catch (err) {
    res.status(500).json({ error: 'Errore interno del server' });
  }
});

app.listen(PORT, () => {
  console.log(`Server avviato sulla porta ${PORT}`);
});
