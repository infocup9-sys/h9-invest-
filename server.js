const express = require('express');
const cors = require('cors');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');

const app = express();
const PORT = process.env.PORT || 10000;
const JWT_SECRET = process.env.JWT_SECRET || 'chiave_segreta_molto_sicura';

app.use(cors());
app.use(express.json());

// Database in memoria (oppure collegabile a MongoDB / PostgreSQL)
let users = [];
let transactions = [];

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

// 1. Registrazione
app.post('/api/auth/register', async (req, res) => {
  const { username, email, password } = req.body;
  if (!username || !email || !password) {
    return res.status(400).json({ error: 'Campi obbligatori mancanti' });
  }

  const existingUser = users.find(u => u.email === email);
  if (existingUser) {
    return res.status(400).json({ error: 'Email già registrata' });
  }

  const hashedPassword = await bcrypt.hash(password, 10);
  const newUser = {
    id: Date.now().toString(),
    username,
    email,
    password: hashedPassword,
    balances: { deposit: 100, earnings: 0 }, // Bonus iniziale opzionale per test, o 0
    investments: [],
    transactions: [],
    status: 'approved'
  };

  users.push(newUser);
  res.json({ requires_otp: false, message: 'Account registrato con successo' });
});

// 2. Login
app.post('/api/auth/login', async (req, res) => {
  const { email, password } = req.body;
  const user = users.find(u => u.email === email);
  if (!user) return res.status(400).json({ error: 'Credenziali non valide' });

  const validPassword = await bcrypt.compare(password, user.password);
  if (!validPassword) return res.status(400).json({ error: 'Credenziali non valide' });

  const access_token = jwt.sign({ id: user.id, email: user.email }, JWT_SECRET, { expiresIn: '7d' });
  res.json({ access_token, user: { username: user.username, email: user.email, role: user.role || 'user' } });
});

// 3. Dati Conto
app.get('/api/account', authenticateToken, (req, res) => {
  const user = users.find(u => u.id === req.user.id);
  if (!user) return res.status(404).json({ error: 'Utente non trovato' });

  res.json({
    user: { username: user.username, email: user.email },
    balances: user.balances,
    investments: user.investments,
    transactions: user.transactions,
    updated_at: new Date().toISOString()
  });
});

// 4. Piani di investimento
app.get('/api/plans', (req, res) => {
  res.json({ plans: PLANS });
});

// 5. Creazione Investimento
app.post('/api/investments', authenticateToken, (req, res) => {
  const { plan_id, amount } = req.body;
  const user = users.find(u => u.id === req.user.id);
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
    progress_pct: 0,
    matures_at: new Date(Date.now() + plan.duration_days * 86400000).toISOString()
  };

  user.investments.push(investment);
  res.json({ message: 'Investimento creato con successo', investment });
});

app.listen(PORT, () => {
  console.log(`Server avviato sulla porta ${PORT}`);
});
