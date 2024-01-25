require('dotenv').config();
const express = require('express');
const jwt = require('jsonwebtoken');
const axios = require('axios');
const mysql = require('mysql');
const NodeCache = require('node-cache');
const rateLimit = require('express-rate-limit');
const cors = require('cors');
const helmet = require('helmet');
const uuid = require('uuid');

const app = express();
const privateKey = process.env.ACCESS_TOKEN_SECRET;

// Parse JSON and urlencoded data
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Database connection pooling
const pool = mysql.createPool({
  connectionLimit: 10,
  host: process.env.CLOUD_SQL_PUBLIC_IP,
  user: process.env.MYSQL_USER,
  password: process.env.MYSQL_PASSWORD,
  database: process.env.MYSQL_DATABASE,
  socketPath: process.env.SOCKET_PATH
});

// Caching setup
const userCache = new NodeCache({ stdTTL: 100, checkperiod: 120 });

// Security enhancements
app.use(cors());
app.use(helmet());

// Trust the first proxy (adjust according to your deployment)
app.set('trust proxy', 1);

// Apply rate limiting
app.use(rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 100
}));

// Middleware to verify JWT token
const verifyToken = (req, res, next) => {
  const token = req.headers.authorization;
  if (!token) {
    return res.status(401).json({ message: 'No token provided' });
  }

  jwt.verify(token, privateKey, (err, decoded) => {
    if (err) {
      return res.status(403).json({ message: 'Failed to authenticate token' });
    }
    req.sessionId = decoded;
    req.encryptedSessionId = token;
    next();
  });
};

// Middleware to check authentication
const checkAuth = async (req, res, next) => {
  try {
    const response = await axios.get(process.env.checkAuth_SERVICE_ENDPOINT, {
      headers: {
        Authorization: req.sessionId
      }
    });
    if (response.data.isAuthenticated) {
      req.userId = response.data.user_id;
      req.userRole = response.data.role; // Store user role
      req.username = response.data.username; // Store username
      next();
    } else {
      return res.status(401).json({ message: 'User not authenticated' });
    }
  } catch (error) {
    next(error);
  }
};


app.post('/register-referral', verifyToken, checkAuth, async (req, res) => {
  const { twitter_id, referral_id } = req.body;
  const referralPoints = parseFloat(process.env.REFERRAL_POINTS);

  // Check for required data
  if (!twitter_id || !referral_id) {
    return res.status(400).json({ message: 'Missing required fields' });
  }

  if (isNaN(referralPoints)) {
    return res.status(500).json({ message: 'Invalid referral points configuration' });
  }

  try {
    // Check if referral already exists for the given twitter_id
    const checkReferralSql = 'SELECT * FROM referrals WHERE twitter_id = ?';
    pool.query(checkReferralSql, [twitter_id], (error, results) => {
      if (error) {
        throw error;
      }
      
      if (results.length > 0) {
        // Referral already exists
        return res.status(409).json({ message: 'Referral already exists for this Twitter ID' });
      } else {
        // Transaction for inserting referral and updating user points
        pool.getConnection((err, connection) => {
          if (err) throw err;

          // Start transaction
          connection.beginTransaction(err => {
            if (err) {
              connection.release();
              throw err;
            }

            // Insert new referral
            const insertReferralSql = 'INSERT INTO referrals (user_id, twitter_id, referrer_user_id, referrer_twitter_id, earned_points) VALUES (?, ?, ?, ?, ?)';
            const userId = req.userId;
            const referrerUserId = "";  // Determine how to get this
            const referrerTwitterId = referral_id;

            connection.query(insertReferralSql, [userId, twitter_id, referrerUserId, referrerTwitterId, referralPoints], (error, results) => {
              if (error) {
                return connection.rollback(() => {
                  connection.release();
                  throw error;
                });
              }

              console.log("[]---->");
              console.log(referralPoints);
              console.log("/[]---->");

              // Update user points
              const updateUserPointsSql = 'UPDATE users SET points = points + ? WHERE twitter_id = ?';
              connection.query(updateUserPointsSql, [referralPoints, referral_id], (error, results) => {
                if (error) {
                  return connection.rollback(() => {
                    connection.release();
                    throw error;
                  });
                }

                // Commit transaction
                connection.commit(err => {
                  if (err) {
                    return connection.rollback(() => {
                      connection.release();
                      throw err;
                    });
                  }

                  connection.release();
                  res.status(201).json({ message: 'Referral registered successfully', referralId: results.insertId });
                });
              });
            });
          });
        });
      }
    });
  } catch (error) {
    res.status(500).json({ message: 'Internal server error', error: error.message });
  }
});


// Endpoint to get total referral earned points
app.get('/get-total-referral-earned-points', verifyToken, checkAuth, (req, res) => {
  const userId = req.userId;  // Obtained from the authenticated user session

  // SQL to get twitter_id from users table
  const getTwitterIdSql = 'SELECT twitter_id FROM users WHERE user_id = ?';

  pool.query(getTwitterIdSql, [userId], (error, results) => {
    if (error) {
      return res.status(500).json({ message: 'Internal server error', error: error.message });
    }


    // Get the twitter_id from the results
    const twitterId = results[0].twitter_id;

    // SQL to get total points from referrals table using twitter_id
    const getTotalPointsSql = 'SELECT SUM(earned_points) as totalPoints FROM referrals WHERE referrer_twitter_id = ?';

    pool.query(getTotalPointsSql, [twitterId], (error, results) => {
      if (error) {
        return res.status(500).json({ message: 'Internal server error', error: error.message });
      }

      // Handle case where there are no referrals yet
      const totalEarnedPoints = results[0].totalPoints || 0;

      res.json({ "totalEarnedPoints": totalEarnedPoints });
    });
  });
});



// Health Check Endpoint
app.get('/health', (req, res) => {
  pool.query('SELECT 1', (err, results) => {
    if (err) {
      return res.status(500).json({ message: 'Database connection failed', error: err });
    }
    res.json({ message: 'Micro-service active and database connection successful' });
  });
});

// Central error handler
app.use((err, req, res, next) => {
  console.error(err.stack);
  res.status(500).json({ message: 'Internal Server Error' });
});

// Starting the server
const PORT = process.env.APP_PORT || 8080;
app.listen(PORT, () => {
  console.log(`Micro-service listening on port ${PORT}`);
});
