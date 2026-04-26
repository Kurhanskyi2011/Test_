const express = require('express');
const bodyParser = require('body-parser');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const nodemailer = require('nodemailer');
const { Low } = require('lowdb');
const { JSONFile } = require('lowdb/node');
const path = require('path');

const app = express();
const PORT = 3000;
const SECRET_KEY = 'your-secret-key'; // Change this in production

// Initialize LowDB
const adapter = new JSONFile('db.json');
const db = new Low(adapter, { users: [], resetCodes: {} });

// Email transporter (using Gmail)
const transporter = nodemailer.createTransport({
  service: 'gmail',
  auth: {
    user: 'your-gmail@gmail.com', // Replace with your Gmail
    pass: 'your-app-password' // Replace with Gmail app password
  }
});

// Middleware
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));
app.use(express.static('public'));

// Routes
app.post('/register', async (req, res) => {
  const { email, password } = req.body;
  const users = db.data.users;

  if (users.find(u => u.email === email)) {
    return res.status(400).json({ message: 'User already exists' });
  }

  const hashedPassword = await bcrypt.hash(password, 10);
  users.push({ email, password: hashedPassword });
  await db.write();

  res.json({ message: 'User registered successfully' });
});

app.post('/login', async (req, res) => {
  const { email, password } = req.body;
  const user = db.data.users.find(u => u.email === email);

  if (!user || !(await bcrypt.compare(password, user.password))) {
    return res.status(401).json({ message: 'Invalid credentials' });
  }

  const token = jwt.sign({ email }, SECRET_KEY, { expiresIn: '1h' });
  res.json({ token });
});

app.post('/forgot-password', async (req, res) => {
  const { email } = req.body;
  const user = db.data.users.find(u => u.email === email);

  if (!user) {
    return res.status(404).json({ message: 'User not found' });
  }

  const code = Math.random().toString(36).substring(2, 8).toUpperCase();
  db.data.resetCodes[email] = code;
  await db.write();

  const mailOptions = {
    from: 'your-gmail@gmail.com',
    to: email,
    subject: 'Password Reset Code',
    text: `Your password reset code is: ${code}`
  };

  transporter.sendMail(mailOptions, (error, info) => {
    if (error) {
      console.log(error);
      res.status(500).json({ message: 'Error sending email' });
    } else {
      console.log('Email sent: ' + info.response);
      res.json({ message: 'Reset code sent to email' });
    }
  });
});

app.post('/reset-password', async (req, res) => {
  const { email, code, newPassword } = req.body;
  const storedCode = db.data.resetCodes[email];

  if (!storedCode || storedCode !== code) {
    return res.status(400).json({ message: 'Invalid code' });
  }

  const user = db.data.users.find(u => u.email === email);
  user.password = await bcrypt.hash(newPassword, 10);
  delete db.data.resetCodes[email];
  await db.write();

  res.json({ message: 'Password reset successfully' });
});

// Middleware to verify token
const verifyToken = (req, res, next) => {
  const token = req.headers['authorization'];
  if (!token) return res.status(403).json({ message: 'No token provided' });

  jwt.verify(token, SECRET_KEY, (err, decoded) => {
    if (err) return res.status(401).json({ message: 'Invalid token' });
    req.user = decoded;
    next();
  });
};

app.get('/profile', verifyToken, (req, res) => {
  res.json({ email: req.user.email });
});

app.listen(PORT, () => {
  console.log(`Server running on http://localhost:${PORT}`);
});