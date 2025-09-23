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
    'http://localhost:3000',
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



// ------------------------- MySQL CONNECTION -------------------------
const db = mysql.createConnection({
  host: 'gateway01.ap-southeast-1.prod.aws.tidbcloud.com',
  port: 4000,
  user: 'Na3WQCguqJvPPa8.root',
  password: 'uv25a7EdgDlHnE9H',
  database: 'test',
  ssl: { rejectUnauthorized: true } // TiDB Cloud requires SSL
});


db.connect(err => {
  if (err) {
    console.error('DB connection error:', err);
    process.exit(1);
  } else {
    console.log('Connected to MySQL database');
    createTables();
  }
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
      battery1 VARCHAR(50) DEFAULT 'Status',
      battery2 VARCHAR(50) DEFAULT 'Status',
      starter VARCHAR(50) DEFAULT 'Status',
      alternator VARCHAR(50) DEFAULT 'Status',
      etc1 VARCHAR(50) DEFAULT 'Status',
      etc2 VARCHAR(50) DEFAULT 'Status',
      date DATE NOT NULL,
      user_id INT NOT NULL,
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
      UNIQUE KEY unique_bus_user_date (bus_number, user_id, date)
    )
  `;

  db.query(createUsersTable, (err) => {
    if (err) console.error('Error creating users table:', err);
    else console.log('Users table ready');
  });

  db.query(createBusesTable, (err) => {
    if (err) console.error('Error creating buses table:', err);
    else console.log('Buses table ready');
  });
}

// ------------------------- AUTH ROUTES -------------------------

// Register user
app.post('/register', async (req, res) => {
  const { username, password, email } = req.body;
  
  if (!username || !password || !email) {
    return res.status(400).json({ message: 'All fields are required' });
  }

  if (password.length < 6) {
    return res.status(400).json({ message: 'Password must be at least 6 characters long' });
  }

  // Validate email format
  const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
  if (!emailRegex.test(email)) {
    return res.status(400).json({ message: 'Please enter a valid email address' });
  }

  try {
    const hashedPassword = await bcrypt.hash(password, 10);
    const query = 'INSERT INTO users (username, password, email) VALUES (?, ?, ?)';
    
    db.query(query, [username, hashedPassword, email], (err) => {
      if (err) {
        if (err.code === 'ER_DUP_ENTRY') {
          if (err.message.includes('username')) {
            return res.status(400).json({ message: 'Username already exists' });
          } else {
            return res.status(400).json({ message: 'Email already registered' });
          }
        }
        console.error('Registration error:', err);
        return res.status(500).json({ message: 'Database error during registration' });
      }
      res.json({ message: 'User registered successfully' });
    });
  } catch (err) {
    console.error('Server error during registration:', err);
    res.status(500).json({ message: 'Server error during registration' });
  }
});

// Login user
app.post('/login', (req, res) => {
  const { username, password } = req.body;
  
  if (!username || !password) {
    return res.status(400).json({ message: 'Username and password are required' });
  }

  const query = 'SELECT * FROM users WHERE username = ?';
  db.query(query, [username], async (err, results) => {
    if (err) {
      console.error('Login database error:', err);
      return res.status(500).json({ message: 'Database error during login' });
    }
    
    if (results.length === 0) {
      return res.status(400).json({ message: 'Invalid username or password' });
    }

    const user = results[0];
    
    try {
      const isMatch = await bcrypt.compare(password, user.password);
      if (!isMatch) {
        return res.status(400).json({ message: 'Invalid username or password' });
      }

      const token = jwt.sign(
        { id: user.id, username: user.username }, 
        JWT_SECRET, 
        { expiresIn: '24h' }
      );
      
      res.json({ 
        message: 'Login successful', 
        token,
        username: user.username 
      });
    } catch (bcryptError) {
      console.error('Password comparison error:', bcryptError);
      res.status(500).json({ message: 'Authentication error' });
    }
  });
});

// ------------------------- JWT Middleware -------------------------
function verifyToken(req, res, next) {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];
  
  if (!token) {
    return res.status(401).json({ message: 'Access denied, token missing' });
  }

  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) {
      return res.status(403).json({ message: 'Invalid or expired token' });
    }
    req.user = user;
    next();
  });
}

// ------------------------- BUS ROUTES -------------------------

// Utility: normalize bus number
function normalizeBusNumber(busNumber) {
  return busNumber.replace(/[^a-zA-Z0-9]/g, '').toUpperCase();
}

// Get buses by month
app.get('/buses', verifyToken, (req, res) => {
  const month = req.query.month; // YYYY-MM format
  
  if (!month || !/^\d{4}-\d{2}$/.test(month)) {
    return res.status(400).json({ message: 'Valid month parameter required (YYYY-MM format)' });
  }

  const query = `
    SELECT * FROM buses 
    WHERE DATE_FORMAT(date, '%Y-%m') = ? AND user_id = ? 
    ORDER BY bus_number ASC
  `;
  
  db.query(query, [month, req.user.id], (err, results) => {
    if (err) {
      console.error('Error fetching buses:', err);
      return res.status(500).json({ message: 'Database error fetching buses' });
    }
    res.json(results);
  });
});

// Add bus
app.post('/buses', verifyToken, (req, res) => {
  const { busNumber, date } = req.body;
  
  if (!busNumber || !date) {
    return res.status(400).json({ message: 'Bus number and date are required' });
  }

  // Validate date format
  if (!/^\d{4}-\d{2}-\d{2}$/.test(date)) {
    return res.status(400).json({ message: 'Invalid date format. Use YYYY-MM-DD' });
  }

  // ✅ Normalize bus number
  const normalizedBusNumber = normalizeBusNumber(busNumber);
  const month = date.slice(0, 7);
  
  // Check if bus already exists for this user and date
  const checkQuery = `
    SELECT * FROM buses 
    WHERE bus_number = ? AND date = ? AND user_id = ?
  `;
  
  db.query(checkQuery, [normalizedBusNumber, date, req.user.id], (err, results) => {
    if (err) {
      console.error('Error checking existing bus:', err);
      return res.status(500).json({ message: 'Database error checking existing bus' });
    }
    
    if (results.length > 0) {
      return res.status(400).json({ 
        message: 'Bus already exists for this date' 
      });
    }

    // Insert new bus with normalized bus number
    const insertQuery = `
      INSERT INTO buses 
      (bus_number, battery1, battery2, starter, alternator, etc1, etc2, date, user_id) 
      VALUES (?, 'Status', 'Status', 'Status', 'Status', 'Status', 'Status', ?, ?)
    `;
    
    db.query(insertQuery, [normalizedBusNumber, date, req.user.id], (err, result) => {
      if (err) {
        console.error('Error inserting bus:', err);
        return res.status(500).json({ message: 'Database error adding bus' });
      }
      
      res.json({ 
        message: 'Bus added successfully', 
        id: result.insertId 
      });
    });
  });
});

// Update bus
app.put('/buses/:id', verifyToken, (req, res) => {
  const busId = req.params.id;
  const fields = req.body;
  
  if (!busId || isNaN(busId)) {
    return res.status(400).json({ message: 'Valid bus ID required' });
  }

  if (Object.keys(fields).length === 0) {
    return res.status(400).json({ message: 'No fields to update' });
  }

  // Validate allowed fields
  const allowedFields = ['battery1', 'battery2', 'starter', 'alternator', 'etc1', 'etc2', 'date'];
  const updateFields = Object.keys(fields).filter(key => allowedFields.includes(key));
  
  if (updateFields.length === 0) {
    return res.status(400).json({ message: 'No valid fields to update' });
  }

  const setClause = updateFields.map(field => `${field} = ?`).join(', ');
  const values = updateFields.map(field => fields[field]);
  values.push(busId, req.user.id);

  const query = `UPDATE buses SET ${setClause} WHERE id = ? AND user_id = ?`;
  
  db.query(query, values, (err, result) => {
    if (err) {
      console.error('Error updating bus:', err);
      return res.status(500).json({ message: 'Database error updating bus' });
    }
    
    if (result.affectedRows === 0) {
      return res.status(404).json({ 
        message: 'Bus not found or not authorized to update' 
      });
    }
    
    res.json({ message: 'Bus updated successfully' });
  });
});

// Delete bus
app.delete('/buses/:id', verifyToken, (req, res) => {
  const busId = req.params.id;
  
  if (!busId || isNaN(busId)) {
    return res.status(400).json({ message: 'Valid bus ID required' });
  }

  const query = 'DELETE FROM buses WHERE id = ? AND user_id = ?';
  
  db.query(query, [busId, req.user.id], (err, result) => {
    if (err) {
      console.error('Error deleting bus:', err);
      return res.status(500).json({ message: 'Database error deleting bus' });
    }
    
    if (result.affectedRows === 0) {
      return res.status(404).json({ 
        message: 'Bus not found or not authorized to delete' 
      });
    }
    
    res.json({ message: 'Bus deleted successfully' });
  });
});

// Health check endpoint
app.get('/health', (req, res) => {
  res.json({ status: 'OK', timestamp: new Date().toISOString() });
});

// Error handling middleware
app.use((err, req, res, next) => {
  console.error('Unhandled error:', err);
  res.status(500).json({ message: 'Internal server error' });
});

// Graceful shutdown
process.on('SIGINT', () => {
  console.log('Shutting down server...');
  db.end(() => {
    console.log('Database connection closed');
    process.exit(0);
  });
});

// ------------------------- START SERVER -------------------------
app.listen(PORT, () => {
  console.log(`Server running at http://localhost:${PORT}`);
  console.log(`Health check available at http://localhost:${PORT}/health`);
});
