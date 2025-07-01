const express = require('express');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { v4: uuidv4 } = require('uuid');

const app = express();
const PORT = process.env.PORT || 8080;
const JWT_SECRET = process.env.JWT_SECRET || 'your-secret-key';

// Middleware
app.use(express.json());

// In-memory storage (replace with database in production)
const users = new Map();
const resignations = new Map();
const exitResponses = new Map();

// Initialize admin user
const adminId = uuidv4();
users.set(adminId, {
  id: adminId,
  username: 'admin',
  password: bcrypt.hashSync('admin', 10),
  role: 'admin'
});

// Helper function to generate JWT token
const generateToken = (user) => {
  return jwt.sign(
    { userId: user.id, username: user.username, role: user.role },
    JWT_SECRET,
    { expiresIn: '24h' }
  );
};

// Middleware to authenticate user
// const authenticateToken = (req, res, next) => {
//   const authHeader = req.headers['authorization'];
//   const token = authHeader && authHeader.split(' ')[1];

//   if (!token) {
//     return res.status(401).json({ error: 'Access token required' });
//   }

//   jwt.verify(token, JWT_SECRET, (err, user) => {
//     if (err) {
//       return res.status(403).json({ error: 'Invalid or expired token' });
//     }
//     req.user = user;
//     next();
//   });
// };
// Middleware to authenticate user (compatible with Cypress)
const authenticateToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];

  if (!authHeader) {
    console.log("Missing auth header");
    return res.status(401).json({ error: 'Access token required' });
  }

  const token = authHeader.startsWith('Bearer ')
    ? authHeader.split(' ')[1]
    : authHeader;

  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) {
      console.log("JWT verification failed:", err.message);
      return res.status(403).json({ error: 'Invalid or expired token' });
    }
    req.user = user;
    console.log("Authenticated user:", user);
    next();
  });
};



// Middleware to check admin role
const requireAdmin = (req, res, next) => {
  if (req.user.role !== 'admin') {
    return res.status(403).json({ error: 'Admin access required' });
  }
  next();
};

// 1. User Registration Endpoint
app.post('/api/auth/register', async (req, res) => {
  try {
    const { username, password } = req.body;

    if (!username || !password) {
      return res.status(400).json({ error: 'Username and password are required' });
    }

    // Check if user already exists
    const existingUser = Array.from(users.values()).find(u => u.username === username);
    if (existingUser) {
      return res.status(409).json({ error: 'Username already exists' });
    }

    // Create new user
    const userId = uuidv4();
    const hashedPassword = await bcrypt.hash(password, 10);
    
    users.set(userId, {
      id: userId,
      username,
      password: hashedPassword,
      role: 'employee'
    });

    res.status(201).json({
      message: 'User registered successfully'
    });
  } catch (error) {
    res.status(500).json({ error: 'Internal server error' });
  }
});

// 2. User Login Endpoint (handles both employee and admin)
app.post('/api/auth/login', async (req, res) => {
  try {
    const { username, password } = req.body;

    if (!username || !password) {
      return res.status(400).json({ error: 'Username and password are required' });
    }

    // Find user
    const user = Array.from(users.values()).find(u => u.username === username);
    if (!user) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    // Verify password
    const isValidPassword = await bcrypt.compare(password, user.password);
    if (!isValidPassword) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    // Generate token
    const token = generateToken(user);

    res.status(200).json({
      token
    });
  } catch (error) {
    res.status(500).json({ error: 'Internal server error' });
  }
});

app.post('/api/user/resign', authenticateToken, (req, res) => {
  try {
    const { lwd } = req.body;

    if (!lwd) {
      return res.status(400).json({ error: 'Last working day (lwd) is required' });
    }

    // Validate date format
    const parsedDate = new Date(lwd);
    if (isNaN(parsedDate.getTime())) {
      return res.status(400).json({ error: 'Invalid date format. Use YYYY-MM-DD' });
    }

    // Check for existing resignation
    const existingResignation = Array.from(resignations.values()).find(
      r => r.employeeId === req.user.userId && r.status === 'pending'
    );

    if (existingResignation) {
      return res.status(409).json({ error: 'You already have a pending resignation' });
    }

    // Create resignation record
    const resignationId = uuidv4();
    const resignation = {
      _id: resignationId,
      employeeId: req.user.userId,
      lwd: parsedDate.toISOString().split('T')[0], // Store as YYYY-MM-DD
      status: 'pending',
      submittedAt: new Date().toISOString()
    };

    resignations.set(resignationId, resignation);

    res.status(200).json({
      data: {
        resignation: {
          _id: resignationId
        }
      }
    });

  } catch (error) {
    console.error('Resignation error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});


// 5. View All Resignations (Admin)
app.get('/api/admin/resignations', authenticateToken, requireAdmin, (req, res) => {
  try {
    const allResignations = Array.from(resignations.values()).map(resignation => ({
      _id: resignation._id,
      employeeId: resignation.employeeId,
      lwd: resignation.lwd,
      status: resignation.status
    }));

    res.status(200).json({
      data: allResignations
    });
  } catch (error) {
    res.status(500).json({ error: 'Internal server error' });
  }
});

// 6. Approve or Reject Employee Resignation (Admin)
app.put('/api/admin/conclude_resignation', authenticateToken, requireAdmin, (req, res) => {
  try {
    const { resignationId, approved, lwd } = req.body;

    if (!resignationId || typeof approved !== 'boolean' || !lwd) {
      return res.status(400).json({ 
        error: 'resignationId, approved (boolean), and lwd are required' 
      });
    }

    // Validate LWD format
    const parsedDate = new Date(lwd);
    if (isNaN(parsedDate.getTime())) {
      return res.status(400).json({ error: 'Invalid date format. Use YYYY-MM-DD' });
    }
    const formattedLwd = parsedDate.toISOString().split('T')[0]; // YYYY-MM-DD

    // Get resignation
    const resignation = resignations.get(resignationId);
    if (!resignation) {
      return res.status(404).json({ error: 'Resignation not found' });
    }

    if (resignation.status !== 'pending') {
      return res.status(400).json({ error: 'Resignation has already been processed' });
    }

    // Update resignation
    resignation.status = approved ? 'approved' : 'rejected';
    resignation.lwd = formattedLwd;
    resignation.processedAt = new Date().toISOString();
    resignation.processedBy = req.user.userId;

    resignations.set(resignationId, resignation);

    res.status(200).json({
      message: `Resignation ${approved ? 'approved' : 'rejected'} successfully`
    });
  } catch (error) {
    console.error('Error concluding resignation:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});


// 7. Employee Exit Questionnaire Submission
app.post('/api/user/responses', authenticateToken, (req, res) => {
  try {
    const { responses } = req.body;

    if (!responses || !Array.isArray(responses)) {
      return res.status(400).json({ error: 'Responses array is required' });
    }

    // Validate responses format
    for (const response of responses) {
      if (!response.questionText || !response.response) {
        return res.status(400).json({ 
          error: 'Each response must have questionText and response fields' 
        });
      }
    }

    // Check if user already submitted responses
    const existingResponse = exitResponses.get(req.user.userId);
    if (existingResponse) {
      return res.status(409).json({ error: 'Exit questionnaire already submitted' });
    }

    // Store responses
    exitResponses.set(req.user.userId, {
      employeeId: req.user.userId,
      responses,
      submittedAt: new Date().toISOString()
    });

    res.status(200).json({
      message: 'Exit questionnaire submitted successfully'
    });
  } catch (error) {
    res.status(500).json({ error: 'Internal server error' });
  }
});

// 8. View All Exit Questionnaire Responses (Admin)
app.get('/api/admin/exit_responses', authenticateToken, requireAdmin, (req, res) => {
  try {
    const allResponses = Array.from(exitResponses.values()).map(response => ({
      employeeId: response.employeeId,
      responses: response.responses
    }));

    res.status(200).json({
      data: allResponses
    });
  } catch (error) {
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Health check endpoint
app.get('/health', (req, res) => {
  res.status(200).json({ status: 'OK', timestamp: new Date().toISOString() });
});

// Error handling middleware
app.use((err, req, res, next) => {
  console.error(err.stack);
  res.status(500).json({ error: 'Something went wrong!' });
});

// 404 handler
app.use('*', (req, res) => {
  res.status(404).json({ error: 'Endpoint not found' });
});

// Start server
app.listen(PORT, () => {
  console.log(`Server is running on port ${PORT}`);
  console.log(`Admin credentials: username=admin, password=admin`);
});

module.exports = app;
