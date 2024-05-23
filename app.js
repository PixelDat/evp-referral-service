require('dotenv').config();
const express = require('express');
const jwt = require('jsonwebtoken');
const axios = require('axios');
const mysql = require('mysql2');
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
const userCache = new NodeCache({ stdTTL: 300, checkperiod: 120 });

// Security enhancements
app.use(cors());
app.use(helmet());

// Trust the first proxy (adjust according to your deployment)
app.set('trust proxy', 1);

// Apply rate limiting
app.use(rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 500
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
    const sessionId = req.sessionId;

    if (!sessionId) {
      return res.status(401).json({ message: 'Session ID is missing' });
    }

    const query = 'SELECT user_id, role, username FROM users WHERE session_id = ?';

    // Check if the query result is already cached
    const cachedResult = userCache.get(sessionId);
    if (cachedResult) {
      const { user_id, role, username } = cachedResult;
      req.userId = user_id;
      req.userRole = role; // Store user role
      req.username = username;
      return next();
    }

    pool.query(query, [sessionId], (error, results) => {
      if (error) {
        return next(error); // Pass the error to the central error handler
      }

      if (results.length > 0) {
        const user = results[0];

        // Cache the query result with the sessionId as the key
        userCache.set(sessionId, user);

        req.userId = user.user_id;
        req.userRole = user.role; // Store user role
        req.username = user.username;
        next();
      } else {
        res.status(404).send('User not authenticated');
      }
    });
  } catch (error) {
    next(error);
  }
};

// Function to generate a 5-digit alphanumeric string
function generateRefID() {
  const characters = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
  let result = '';
  const charactersLength = characters.length;
  for (let i = 0; i < 5; i++) {
      result += characters.charAt(Math.floor(Math.random() * charactersLength));
  }
  return result;
}

// Function to check if the generated refID is unique
async function isRefIDUnique(refID) {
  const query = 'SELECT COUNT(*) AS count FROM users_refIDs WHERE refID = ?';
  const [results] = await pool.promise().query(query, [refID]);
  return results[0].count === 0;
}



// Create a new mining account
app.post('/create-referral-account', verifyToken, checkAuth, async (req, res) => {
  try {
    const userId = req.userId; // Assuming this is set by your authentication middleware

    // First, check if a referral account already exists for the user
    const existingRefQuery = 'SELECT refID FROM users_refIDs WHERE user_id = ?';
    const [existingRefs] = await pool.promise().query(existingRefQuery, [userId]);

    if (existingRefs.length > 0) {
      // User already has a referral account
      return res.status(400).json({ message: 'Referral account already exists for this user', refID: existingRefs[0].refID });
    }

    // If no existing referral account, generate a unique refID
    let unique = false;
    let refID;
    while (!unique) {
      refID = generateRefID();
      unique = await isRefIDUnique(refID);
    }

    // Once a unique refID is generated, proceed with account creation
    const insertQuery = `INSERT INTO users_refIDs (user_id, refID) VALUES (?, ?)`;
    pool.query(insertQuery, [userId, refID], (error, results) => {
      if (error) {
        console.error(error);
        return res.status(500).json({ message: 'Failed to create referral account', error: error.message });
      }
      res.json({ message: 'Referral account created successfully', refID: refID });
    });
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: 'Failed to create referral account', error: error.message });
  }
});




app.post('/reg-potential-referrals', async (req, res) => {
  const { _genID, _refID } = req.body;

  // Input validation
  if (!_genID || !_refID) {
    return res.status(400).json({ message: 'Missing required fields' });
  }

  // Assuming you have a function to sanitize input or using prepared statements
  const sanitizedGenID = _genID; // Implement actual sanitization
  const sanitizedRefID = _refID; // Implement actual sanitization

  // Prepare the insert query
  const insertQuery = `INSERT INTO potential_referrals (genID, refID, confirmed) VALUES (?, ?, false)`;

  // Execute the query
  pool.query(insertQuery, [sanitizedGenID, sanitizedRefID], (error, results) => {
    if (error) {
      console.error(error);
      return res.status(500).json({ message: 'Failed to register potential referral', error: error.message });
    }
    res.json({ message: 'Potential referral registered successfully', insertId: results.insertId });
  });
});

app.get('/reg-potential-referrals-redirect', async (req, res) => {
  const { _genID, _refID } = req.query;

  // Input validation
  if (!_genID || !_refID) {
    return res.status(400).json({ message: 'Missing required fields' });
  }

  // Assuming you have a function to sanitize input or using prepared statements
  const sanitizedGenID = _genID; // Implement actual sanitization
  const sanitizedRefID = _refID; // Implement actual sanitization

  // Prepare the insert query
  const insertQuery = `INSERT INTO potential_referrals (genID, refID, confirmed) VALUES (?, ?, false)`;

  // Execute the query
  pool.query(insertQuery, [sanitizedGenID, sanitizedRefID], (error, results) => {
    if (error) {
      console.error(error);
      return res.status(500).json({ message: 'Failed to register potential referral', error: error.message });
    }
    res.redirect('https://play.google.com/store/apps/details?id=com.everpumpstudio.pumpmilitia');
  });
});


app.post('/confirm-potential-referrals', verifyToken, checkAuth, async (req, res) => {
  const { _genID, _refID } = req.body;
  const _referee_user_id = req.userId; // Assuming checkAuth middleware sets `req.userId`

  // Input validation
  if (!_genID || !_refID) {
    return res.status(400).json({ message: 'Missing required fields' });
  }

  // First, find the referrer's user_id by _refID
  const getReferrerUserIdQuery = 'SELECT user_id FROM users_refIDs WHERE refID = ?';
  pool.query(getReferrerUserIdQuery, [_refID], (error, results) => {
    if (error) {
      return res.status(500).json({ message: 'Error fetching referrer user ID', error: error.message });
    }
    if (results.length === 0) {
      return res.status(404).json({ message: 'Referrer not found' });
    }
    const _referrer_user_id = results[0].user_id;

    // Then, confirm the potential referral
    const confirmReferralQuery = `UPDATE potential_referrals SET confirmed = true, referee_user_id = ?, referrer_user_id = ? WHERE genID = ? AND refID = ?`;
    pool.query(confirmReferralQuery, [_referee_user_id, _referrer_user_id, _genID, _refID], (error, results) => {
      if (error) {
        return res.status(500).json({ message: 'Failed to confirm potential referral', error: error.message });
      }
      if (results.affectedRows === 0) {
        return res.status(404).json({ message: 'Potential referral not found or already confirmed' });
      }
      res.json({ message: 'Potential referral confirmed successfully' });
    });
  });
});


app.get('/get-referrer-refID', verifyToken, checkAuth, async (req, res) => {
  const userId = req.userId;  // Set by checkAuth middleware

  // SQL query to find the refID of the user's referrer
  // Ensure that the referral is confirmed
  const query = `
    SELECT ur.refID FROM users_refIDs ur
    JOIN potential_referrals pr ON ur.user_id = pr.referrer_user_id
    WHERE pr.referee_user_id = ? AND pr.confirmed = true
  `;

  pool.query(query, [userId], (error, results) => {
    if (error) {
      console.error(error);
      return res.status(500).send('Error fetching referrer refID');
    }
    if (results.length === 0) {
      return res.status(404).send('Referrer not found or referral not confirmed');
    }
    
    // Assuming each user can be referred by only one referrer, so taking the first result
    const refID = results[0].refID;
    res.status(200).json({ referrerRefID: refID });
  });
});




app.post('/register-referral', verifyToken, checkAuth, (req, res) => {
  const { refID } = req.body;
  const referralPoints = parseFloat(process.env.REFERRAL_POINTS);
  const userId = req.userId; // Set by checkAuth middleware

  if (!refID || isNaN(referralPoints)) {
    return res.status(400).json({ message: 'Missing required fields or invalid referral points configuration' });
  }

  pool.getConnection((err, connection) => {
    if (err) {
      console.error('Error getting connection from pool:', err);
      return res.status(500).json({ message: 'Failed to connect to database' });
    }

    connection.beginTransaction(err => {
      if (err) {
        connection.release();
        console.error('Error starting transaction:', err);
        return res.status(500).json({ message: 'Failed to start transaction' });
      }

      // Retrieve the referrer's user_id
      connection.query('SELECT user_id FROM users_refIDs WHERE refID = ?', [refID], (err, referrer) => {
        if (err || referrer.length === 0) {
          connection.rollback(() => {
            connection.release();
            console.error('Error fetching referrer:', err);
            res.status(err ? 500 : 404).json({ message: err ? 'Failed to fetch referrer' : 'Referrer not found' });
          });
          return;
        }
        const referrerUserId = referrer[0].user_id;

        // Check if a referral already exists for this user
        connection.query('SELECT 1 FROM referrals WHERE user_id = ?', [userId], (err, existingReferral) => {
          if (err || existingReferral.length > 0) {
            connection.rollback(() => {
              connection.release();
              console.error('Error checking existing referral:', err);
              res.status(err ? 500 : 400).json({ message: err ? 'Failed to check existing referral' : 'Referral already exists for this user' });
            });
            return;
          }

          // Insert new referral and update user points
          const insertReferralSql = 'INSERT INTO referrals (user_id, referrer_user_id, earned_points) VALUES (?, ?, ?)';
          connection.query(insertReferralSql, [userId, referrerUserId, referralPoints], (err) => {
            if (err) {
              connection.rollback(() => {
                connection.release();
                console.error('Error inserting referral:', err);
                res.status(500).json({ message: 'Failed to insert referral' });
              });
              return;
            }

            const updateUserPointsSql = 'UPDATE users SET points = points + ? WHERE user_id = ?';
            connection.query(updateUserPointsSql, [referralPoints, referrerUserId], (err) => {
              if (err) {
                connection.rollback(() => {
                  connection.release();
                  console.error('Error updating user points:', err);
                  res.status(500).json({ message: 'Failed to update user points' });
                });
                return;
              }

              
              

              // Parse the mining rate boost from the environment variable
              const miningRateBoost = parseFloat(process.env.MINING_RATE_BOOST);
              if (isNaN(miningRateBoost)) {
                connection.rollback(() => {
                  connection.release();
                  console.error('Invalid mining rate boost configuration');
                  res.status(500).json({ message: 'Invalid mining rate boost configuration' });
                });
                return;
              }

              // Update the mining rate in the token_minne table
              const updateMiningRateSql = 'UPDATE token_minne SET mining_rate = mining_rate + ? WHERE user_id = ?';
              connection.query(updateMiningRateSql, [miningRateBoost, userId], (err) => {
                if (err) {
                  connection.rollback(() => {
                    connection.release();
                    console.error('Error updating mining rate:', err);
                    res.status(500).json({ message: 'Failed to update mining rate' });
                  });
                  return;
                }
              });




              connection.commit(err => {
                if (err) {
                  connection.rollback(() => {
                    connection.release();
                    console.error('Error committing transaction:', err);
                    res.status(500).json({ message: 'Transaction commit failed' });
                  });
                  return;
                }

                connection.release();
                res.status(201).json({ message: 'Referral registered successfully' });
              });
            });
          });
        });
      });
    });
  });
});




// Endpoint to get total referral earned points
app.get('/get-total-referral-earned-points', verifyToken, checkAuth, (req, res) => {
  const userId = req.userId;  // Obtained from the authenticated user session
 // SQL to get total points from referrals table using twitter_id
 const getTotalPointsSql = 'SELECT SUM(earned_points) as totalPoints FROM referrals WHERE referrer_user_id = ?';

 pool.query(getTotalPointsSql, [userId], (error, results) => {
   if (error) {
     return res.status(500).json({ message: 'Internal server error', error: error.message });
   }

   // Handle case where there are no referrals yet
   const totalEarnedPoints = results[0].totalPoints || 0;

   res.json({ "totalEarnedPoints": totalEarnedPoints });
 });
});


app.get('/get-refLink', verifyToken, checkAuth, async (req, res) => {
  const userId = req.userId;  // This is set in your checkAuth middleware
  const getUserDataSql = 'SELECT refID FROM users_refIDs WHERE user_id = ?';

  pool.query(getUserDataSql, [userId], (error, results) => {
    if (error) {
      console.error(error);
      return res.status(500).send('Error fetching user data');
    }
    if (results.length === 0) {
      return res.status(404).send('User not found');
    }
    
    const userData = results[0]; // Assuming user_id is unique, there should only be one result.
    const refLink = `https://everpump.io/GenRegRef?refID=${userData.refID}`; // Assuming twitter_id is a field in your users table.
    const refMessage = process.env.REF_MESSAGE;
    
    const inviteFriendsMsgCondtruct = `💰 I installed Pump Militia on Solana and earned 100,000 $PUMP tokens. I'm mining more daily. Join me \n\n 🎮 App: https://pumpmilitia.io/gameDownload \n 💁🏻‍♂️ Referral Code:${userData.refID}`;
    const userReferralCode = "Referral Code: "+userData.refID;

    return res.status(200).json({ refLink, refMessage, inviteFriendsMsgCondtruct, userReferralCode });
  });
});

// Endpoint to get the number of referees
app.get('/get-number-of-referees', verifyToken, checkAuth, (req, res) => {
  const userId = req.userId;  // This is set by the checkAuth middleware

  // SQL query to count the number of referrals by the referrer_user_id
  const countRefereesSql = 'SELECT COUNT(*) AS totalReferees FROM referrals WHERE referrer_user_id = ?';

  pool.query(countRefereesSql, [userId], (error, results) => {
    if (error) {
      console.error('Error fetching total number of referees:', error);
      return res.status(500).json({ message: 'Internal server error', error: error.message });
    }

    // Assuming successful query execution, return the total number of referees
    const totalReferees = results[0].totalReferees;
    res.json({ totalReferees });
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
