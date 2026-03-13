require('dotenv').config();
const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');

const app = express();
app.use(express.json({ limit: '5mb' }));
app.use(cors());

const userSchema = new mongoose.Schema({
  email:     { type: String, required: true, unique: true, lowercase: true, trim: true },
  password:  { type: String, required: true },
  createdAt: { type: Date, default: Date.now }
});
const User = mongoose.model('User', userSchema);

const EMAIL_TTL = parseInt(process.env.EMAIL_TTL_HOURS || '24') * 3600;

const emailSchema = new mongoose.Schema({
  to:         { type: String, required: true, lowercase: true, trim: true },
  from:       { type: String, required: true },
  subject:    { type: String, default: '(no subject)' },
  text:       { type: String, default: '' },
  html:       { type: String, default: '' },
  receivedAt: { type: Date, default: Date.now },
  createdAt:  { type: Date, default: Date.now, expires: EMAIL_TTL }
});
emailSchema.index({ to: 1, createdAt: -1 });
const Email = mongoose.model('Email', emailSchema);

mongoose.connect(process.env.MONGO_URI)
  .then(() => console.log('MongoDB connected'))
  .catch(err => { console.error('MongoDB error:', err); process.exit(1); });

function verifyWorker(req, res, next) {
  if (req.headers['x-worker-secret'] !== process.env.WORKER_SECRET)
    return res.status(401).json({ error: 'Unauthorized' });
  next();
}

function verifyAdmin(req, res, next) {
  if (req.headers['x-admin-key'] !== process.env.ADMIN_KEY)
    return res.status(401).json({ error: 'Unauthorized' });
  next();
}

function verifyToken(req, res, next) {
  const auth = req.headers['authorization'];
  if (!auth || !auth.startsWith('Bearer '))
    return res.status(401).json({ error: 'No token' });
  try {
    req.user = jwt.verify(auth.slice(7), process.env.JWT_SECRET);
    next();
  } catch {
    res.status(401).json({ error: 'Invalid token' });
  }
}

app.get('/', (req, res) => res.json({ status: 'online' }));

app.post('/webhook', verifyWorker, async (req, res) => {
  try {
    const { to, from, subject, text, html } = req.body;
    if (!to || !from) return res.status(400).json({ error: 'Missing fields' });
    const user = await User.findOne({ email: to.toLowerCase().trim() });
    if (!user) return res.json({ success: false, reason: 'No account for this address' });
    const email = new Email({ to: to.toLowerCase().trim(), from, subject, text, html });
    await email.save();
    res.json({ success: true, id: email._id });
  } catch (err) { res.status(500).json({ error: 'Server error' }); }
});

app.post('/admin/create', verifyAdmin, async (req, res) => {
  try {
    const { email, password } = req.body;
    if (!email || !password) return res.status(400).json({ error: 'email and password required' });
    const exists = await User.findOne({ email: email.toLowerCase() });
    if (exists) return res.status(409).json({ error: 'Account already exists' });
    const hash = await bcrypt.hash(password, 10);
    const user = new User({ email: email.toLowerCase().trim(), password: hash });
    await user.save();
    res.json({ success: true, email: user.email });
  } catch (err) { res.status(500).json({ error: 'Server error' }); }
});

app.get('/admin/accounts', verifyAdmin, async (req, res) => {
  try {
    const users = await User.find().select('email createdAt').sort({ createdAt: -1 });
    res.json({ count: users.length, accounts: users });
  } catch (err) { res.status(500).json({ error: 'Server error' }); }
});

app.delete('/admin/account/:email', verifyAdmin, async (req, res) => {
  try {
    await User.deleteOne({ email: req.params.email.toLowerCase() });
    await Email.deleteMany({ to: req.params.email.toLowerCase() });
    res.json({ success: true });
  } catch (err) { res.status(500).json({ error: 'Server error' }); }
});

app.post('/auth/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    if (!email || !password) return res.status(400).json({ error: 'email and password required' });
    const user = await User.findOne({ email: email.toLowerCase().trim() });
    if (!user) return res.status(401).json({ error: 'Invalid credentials' });
    const valid = await bcrypt.compare(password, user.password);
    if (!valid) return res.status(401).json({ error: 'Invalid credentials' });
    const token = jwt.sign({ email: user.email }, process.env.JWT_SECRET, { expiresIn: '7d' });
    res.json({ success: true, token, email: user.email });
  } catch (err) { res.status(500).json({ error: 'Server error' }); }
});

app.get('/api/inbox', verifyToken, async (req, res) => {
  try {
    const emails = await Email.find({ to: req.user.email })
      .sort({ createdAt: -1 }).limit(50).select('-__v');
    res.json({ address: req.user.email, count: emails.length, emails });
  } catch (err) { res.status(500).json({ error: 'Server error' }); }
});

app.get('/api/email/:id', verifyToken, async (req, res) => {
  try {
    const email = await Email.findById(req.params.id).select('-__v');
    if (!email) return res.status(404).json({ error: 'Not found' });
    if (email.to !== req.user.email) return res.status(403).json({ error: 'Forbidden' });
    res.json(email);
  } catch (err) { res.status(500).json({ error: 'Server error' }); }
});

app.delete('/api/inbox', verifyToken, async (req, res) => {
  try {
    const result = await Email.deleteMany({ to: req.user.email });
    res.json({ success: true, deleted: result.deletedCount });
  } catch (err) { res.status(500).json({ error: 'Server error' }); }
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log('Server running on port ' + PORT));

