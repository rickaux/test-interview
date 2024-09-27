const express = require('express');
const router = express.Router();
const pool = require('./db');
const bcrypt = require('bcryptjs');
const { generateToken, verifyToken } = require('./auth');

// Create User (Admin only)
router.post('/users', verifyToken, async (req, res) => {
  if (req.user.role !== 'admin') return res.status(403).send('Access denied');
  
  const { name, email, password, role } = req.body;
  const hashedPassword = await bcrypt.hash(password, 10);
  
  try {
    const result = await pool.query('INSERT INTO users (name, email, password, role) VALUES ($1, $2, $3, $4) RETURNING *', [name, email, hashedPassword, role]);
    res.status(201).json(result.rows[0]);
  } catch (err) {
    res.status(400).send(err.message);
  }
});

// Login
router.post('/login', async (req, res) => {
  const { email, password } = req.body;
  
  try {
    const result = await pool.query('SELECT * FROM users WHERE email = $1', [email]);
    const user = result.rows[0];
    
    if (!user || !(await bcrypt.compare(password, user.password))) {
      return res.status(400).send('Invalid email or password');
    }
    
    const token = generateToken(user);
    res.json({ token });
  } catch (err) {
    res.status(400).send(err.message);
  }
});

module.exports = router;
