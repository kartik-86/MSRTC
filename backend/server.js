const express = require('express');
const mysql = require('mysql2');
const bodyParser = require('body-parser');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const cors = require('cors');

const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = 'KartikStrongSecretKey123!';

// Middleware
app.use(bodyParser.json());

app.use(cors({
  origin: [
    'https://msrtc.vercel.app',
    'http://127.0.0.1:3000',
    'http://localhost:8080',
    'http://127.0.0.1:8080',
    'http://127.0.0.1:5500',
    'http://localhost:5500'
  ],
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization'],
  credentials: true
}));

// ------------------------- MySQL POOL -------------------------
const pool = mysql.createPool({
  host: 'gateway01.ap-southeast-1.prod.aws.tidbcloud.com',
  port: 4000,
  user: 'Na3WQCguqJvPPa8.root',
  password: 'uv25a7EdgDlHnE9H',
  database: 'test',
  ssl: { rejectUnauthorized: true },
  waitForConnections: true,
  connectionLimit: 10,
  queueLimit: 0
});

// Create tables if they don't exist
function createTables() {
  const createUsersTable = `
    CREATE TABLE IF NOT EXISTS users (
      id INT AUTO_INCREMENT PRIMARY KEY,
      username VARCHAR(50) UNIQUE NOT NULL,
      email VARCHAR(100) UNIQUE NOT NULL,
      password VARCHAR(255) NOT NULL,
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )
  `;

  const createBusesTable = `
    CREATE TABLE IF NOT EXISTS buses (
      id INT AUTO_INCREMENT PRIMARY KEY,
      bus_number VARCHAR(20) NOT NULL,
      battery1 VARCHAR(255) DEFAULT 'Status',
      battery2 VARCHAR(255) DEFAULT 'Status',
      starter VARCHAR(255) DEFAULT 'Status',
      alternator VARCHAR(255) DEFAULT 'Status',
      etc1 VARCHAR(255) DEFAULT 'Status',
      etc2 VARCHAR(255) DEFAULT 'Status',
      date DATE NOT NULL,
      user_id INT NOT NULL,
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
      UNIQUE KEY unique_bus_user_date (bus_number, user_id, date)
    )
  `;

  pool.query(createUsersTable, (err) => {
    if (err) console.error('Error creating users table:', err);
    else console.log('Users table ready');
  });

  pool.query(createBusesTable, (err) => {
    if (err) console.error('Error creating buses table:', err);
    else console.log('Buses table ready');
  });
}

// Initialize tables
createTables();

// ------------------------- AUTH ROUTES -------------------------

app.post('/register', async (req, res) => {
  const { username, password, email } = req.body;
  if (!username || !password || !email) return res.status(400).json({ message: 'All fields are required' });
  if (password.length < 6) return res.status(400).json({ message: 'Password must be at least 6 characters long' });

  const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
  if (!emailRegex.test(email)) return res.status(400).json({ message: 'Invalid email' });

  try {
    const hashedPassword = await bcrypt.hash(password, 10);
    const query = 'INSERT INTO users (username, password, email) VALUES (?, ?, ?)';
    pool.query(query, [username, hashedPassword, email], (err) => {
      if (err) {
        if (err.code === 'ER_DUP_ENTRY') {
          if (err.message.includes('username')) return res.status(400).json({ message: 'Username already exists' });
          else return res.status(400).json({ message: 'Email already registered' });
        }
        console.error('Registration error:', err);
        return res.status(500).json({ message: 'Database error' });
      }
      res.json({ message: 'User registered successfully' });
    });
  } catch (err) {
    console.error('Server error:', err);
    res.status(500).json({ message: 'Server error' });
  }
});

app.post('/login', (req, res) => {
  const { username, password } = req.body;
  if (!username || !password) return res.status(400).json({ message: 'Username and password are required' });

  const query = 'SELECT * FROM users WHERE username = ?';
  pool.query(query, [username], async (err, results) => {
    if (err) { console.error('Login DB error:', err); return res.status(500).json({ message: 'Database error' }); }
    if (results.length === 0) return res.status(400).json({ message: 'Invalid username or password' });

    const user = results[0];
    try {
      const isMatch = await bcrypt.compare(password, user.password);
      if (!isMatch) return res.status(400).json({ message: 'Invalid username or password' });

      const token = jwt.sign({ id: user.id, username: user.username }, JWT_SECRET, { expiresIn: '24h' });
      res.json({ message: 'Login successful', token, username: user.username });
    } catch (err) {
      console.error('Password comparison error:', err);
      res.status(500).json({ message: 'Authentication error' });
    }
  });
});

// ------------------------- JWT Middleware -------------------------
function verifyToken(req, res, next) {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];
  if (!token) return res.status(401).json({ message: 'Access denied' });

  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) return res.status(403).json({ message: 'Invalid token' });
    req.user = user;
    next();
  });
}

// ------------------------- BUS ROUTES -------------------------
function normalizeBusNumber(busNumber) {
  return busNumber.replace(/[^a-zA-Z0-9]/g, '').toUpperCase();
}

app.get('/buses', verifyToken, (req, res) => {
  const month = req.query.month;
  if (!month || !/^\d{4}-\d{2}$/.test(month)) return res.status(400).json({ message: 'Invalid month' });

  const query = `SELECT * FROM buses WHERE DATE_FORMAT(date, '%Y-%m') = ? AND user_id = ? ORDER BY bus_number ASC`;
  pool.query(query, [month, req.user.id], (err, results) => {
    if (err) { console.error(err); return res.status(500).json({ message: 'DB error' }); }
    res.json(results);
  });
});

app.post('/buses', verifyToken, (req, res) => {
  const { busNumber, date } = req.body;
  if (!busNumber || !date) return res.status(400).json({ message: 'Bus number and date required' });
  if (!/^\d{4}-\d{2}-\d{2}$/.test(date)) return res.status(400).json({ message: 'Invalid date format' });

  const normalizedBusNumber = normalizeBusNumber(busNumber);

  const checkQuery = 'SELECT * FROM buses WHERE bus_number = ? AND date = ? AND user_id = ?';
  pool.query(checkQuery, [normalizedBusNumber, date, req.user.id], (err, results) => {
    if (err) { console.error(err); return res.status(500).json({ message: 'DB error' }); }
    if (results.length > 0) return res.status(400).json({ message: 'Bus already exists for this date' });

    const insertQuery = `
      INSERT INTO buses 
      (bus_number, battery1, battery2, starter, alternator, etc1, etc2, date, user_id) 
      VALUES (?, 'Status','Status','Status','Status','Status','Status',?,?)
    `;
    pool.query(insertQuery, [normalizedBusNumber, date, req.user.id], (err, result) => {
      if (err) { console.error(err); return res.status(500).json({ message: 'DB error' }); }
      res.json({ message: 'Bus added successfully', id: result.insertId });
    });
  });
});

app.put('/buses/:id', verifyToken, (req, res) => {
  const busId = req.params.id;
  const fields = req.body;
  if (!busId || isNaN(busId)) return res.status(400).json({ message: 'Valid bus ID required' });
  if (Object.keys(fields).length === 0) return res.status(400).json({ message: 'No fields to update' });

  const allowedFields = ['battery1','battery2','starter','alternator','etc1','etc2','date'];
  const updateFields = Object.keys(fields).filter(key => allowedFields.includes(key));
  if (updateFields.length === 0) return res.status(400).json({ message: 'No valid fields to update' });

  const setClause = updateFields.map(f => `${f}=?`).join(',');
  const values = updateFields.map(f => fields[f]);
  values.push(busId, req.user.id);

  const query = `UPDATE buses SET ${setClause} WHERE id=? AND user_id=?`;
  pool.query(query, values, (err, result) => {
    if (err) { console.error(err); return res.status(500).json({ message: 'DB error' }); }
    if (result.affectedRows === 0) return res.status(404).json({ message: 'Bus not found or unauthorized' });
    res.json({ message: 'Bus updated successfully' });
  });
});

app.delete('/buses/:id', verifyToken, (req, res) => {
  const busId = req.params.id;
  if (!busId || isNaN(busId)) return res.status(400).json({ message: 'Valid bus ID required' });

  const query = 'DELETE FROM buses WHERE id=? AND user_id=?';
  pool.query(query, [busId, req.user.id], (err, result) => {
    if (err) { console.error(err); return res.status(500).json({ message: 'DB error' }); }
    if (result.affectedRows === 0) return res.status(404).json({ message: 'Bus not found or unauthorized' });
    res.json({ message: 'Bus deleted successfully' });
  });
});

// Health check
app.get('/health', (req, res) => res.json({ status: 'OK', timestamp: new Date().toISOString() }));

// Error handling middleware
app.use((err, req, res, next) => {
  console.error('Unhandled error:', err);
  res.status(500).json({ message: 'Internal server error' });
});

// ------------------------- START SERVER -------------------------
app.listen(PORT, () => {
  console.log(`Server running at http://localhost:${PORT}`);
  console.log(`Health check at http://localhost:${PORT}/health`);
});
