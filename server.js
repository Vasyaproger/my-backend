const express = require('express');
const mysql = require('mysql2/promise');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const multer = require('multer');
const path = require('path');
const cors = require('cors');
const helmet = require('helmet');
const { body, validationResult } = require('express-validator');
const winston = require('winston');
const { S3Client, PutObjectCommand, DeleteObjectCommand, GetObjectCommand, ListBucketsCommand } = require('@aws-sdk/client-s3');
const { Upload } = require('@aws-sdk/lib-storage');
const axios = require('axios');

const app = express();

// Configuration (using environment variables)
require('dotenv').config();
const JWT_SECRET = process.env.JWT_SECRET || 'your_jwt_secret';
const DB_HOST = process.env.DB_HOST || 'your_db_host';
const DB_USER = process.env.DB_USER || 'your_db_user';
const DB_PASSWORD = process.env.DB_PASSWORD || 'your_db_password';
const DB_NAME = process.env.DB_NAME || 'your_db_name';
const S3_ACCESS_KEY = process.env.S3_ACCESS_KEY || 'your_s3_access_key';
const S3_SECRET_KEY = process.env.S3_SECRET_KEY || 'your_s3_secret_key';
const PORT = process.env.PORT || 5000;
const BUCKET_NAME = process.env.BUCKET_NAME || 'your_bucket_name';
const TELEGRAM_BOT_TOKEN = process.env.TELEGRAM_BOT_TOKEN || 'your_telegram_bot_token';
const FRONTEND_URL = process.env.FRONTEND_URL || 'https://your-frontend.com';

// Check required environment variables
const requiredEnvVars = ['JWT_SECRET', 'DB_HOST', 'DB_USER', 'DB_PASSWORD', 'DB_NAME', 'S3_ACCESS_KEY', 'S3_SECRET_KEY', 'BUCKET_NAME', 'TELEGRAM_BOT_TOKEN', 'FRONTEND_URL'];
for (const envVar of requiredEnvVars) {
  if (!process.env[envVar]) {
    console.error(`Error: ${envVar} is not set in environment variables`);
    process.exit(1);
  }
}

// Logger setup
const logger = winston.createLogger({
  level: 'info',
  format: winston.format.combine(
    winston.format.timestamp(),
    winston.format.json()
  ),
  transports: [
    new winston.transports.File({ filename: 'error.log', level: 'error' }),
    new winston.transports.File({ filename: 'combined.log' }),
    new winston.transports.Console(),
  ],
});

// S3 Client setup
const s3Client = new S3Client({
  endpoint: 'https://s3.twcstorage.ru',
  credentials: {
    accessKeyId: S3_ACCESS_KEY,
    secretAccessKey: S3_SECRET_KEY,
  },
  region: 'ru-1',
  forcePathStyle: true,
});

// Check S3 connection
async function checkS3Connection() {
  try {
    await s3Client.send(new ListBucketsCommand({}));
    logger.info('S3 connection successful');
  } catch (err) {
    logger.error(`S3 connection error: ${err.message}, stack: ${err.stack}`);
    throw err;
  }
}

// Middleware
app.use(helmet());
app.use(cors({
  origin: '*',
  methods: ['GET', 'POST', 'PUT', 'DELETE'],
  allowedHeaders: ['Content-Type', 'Authorization'],
  exposedHeaders: ['Authorization'],
}));
app.use(express.json());

// MySQL connection pool
const db = mysql.createPool({
  host: DB_HOST,
  user: DB_USER,
  password: DB_PASSWORD,
  database: DB_NAME,
  port: 3306,
  connectionLimit: 10,
  connectTimeout: 30000,
});

// Multer setup for file uploads
const upload = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: 10 * 1024 * 1024 },
  fileFilter: (req, file, cb) => {
    if (file.fieldname === 'icon') {
      const validMimeTypes = ['image/png'];
      const validExtensions = /\.png$/i;
      const extname = validExtensions.test(path.extname(file.originalname).toLowerCase());
      const mimetype = validMimeTypes.includes(file.mimetype);
      if (extname && mimetype) {
        return cb(null, true);
      }
      logger.warn(`Invalid icon: name=${file.originalname}, MIME=${file.mimetype}`);
      cb(new Error('Only PNG files are allowed for icons!'));
    } else if (file.fieldname === 'apk') {
      const extname = file.originalname.toLowerCase().endsWith('.apk');
      const validMimeTypes = [
        'application/vnd.android.package-archive',
        'application/octet-stream',
        'application/x-apk',
        'application/zip',
      ];
      const mimetype = validMimeTypes.includes(file.mimetype);
      if (extname && mimetype) {
        return cb(null, true);
      }
      logger.warn(`Invalid APK: name=${file.originalname}, MIME=${file.mimetype}`);
      cb(new Error('Only APK files are allowed!'));
    } else if (file.fieldname === 'documents') {
      const validMimeTypes = ['application/pdf', 'image/jpeg', 'image/png', 'image/jpg'];
      const validExtensions = /\.(pdf|jpg|jpeg|png)$/i;
      const extname = validExtensions.test(path.extname(file.originalname).toLowerCase());
      const mimetype = validMimeTypes.includes(file.mimetype);
      if (extname && mimetype) {
        return cb(null, true);
      }
      logger.warn(`Invalid document: name=${file.originalname}, MIME=${file.mimetype}`);
      cb(new Error('Only PDF, JPG, JPEG, and PNG files are allowed for documents!'));
    } else {
      logger.warn(`Invalid field name: ${file.fieldname}`);
      cb(new Error('Invalid field name!'));
    }
  },
}).fields([
  { name: 'icon', maxCount: 1 },
  { name: 'apk', maxCount: 1 },
  { name: 'documents', maxCount: 3 },
]);

// Upload file to S3
async function uploadToS3(file, folder) {
  const sanitizedName = path.basename(file.originalname, path.extname(file.originalname)).replace(/[^a-zA-Z0-9]/g, '_');
  const key = `${folder}/${Date.now()}-${sanitizedName}${path.extname(file.originalname)}`;

  const params = {
    Bucket: BUCKET_NAME,
    Key: key,
    Body: file.buffer,
    ContentType: file.mimetype,
    ACL: 'public-read',
  };

  try {
    const upload = new Upload({
      client: s3Client,
      params,
    });
    await upload.done();
    const location = `https://s3.twcstorage.ru/${BUCKET_NAME}/${key}`;
    logger.info(`File uploaded to S3: ${key}, URL: ${location}`);
    return location;
  } catch (error) {
    logger.error(`S3 upload error for ${key}: ${error.message}, stack: ${error.stack}`);
    throw new Error(`S3 upload error: ${error.message}`);
  }
}

// Delete file from S3
async function deleteFromS3(key) {
  const params = {
    Bucket: BUCKET_NAME,
    Key: key,
  };

  try {
    await s3Client.send(new DeleteObjectCommand(params));
    logger.info(`File deleted from S3: ${key}`);
  } catch (err) {
    logger.error(`S3 delete error: ${err.message}, stack: ${err.stack}`);
    throw err;
  }
}

// Get file from S3
async function getFromS3(key) {
  const params = {
    Bucket: BUCKET_NAME,
    Key: key,
  };

  try {
    const command = new GetObjectCommand(params);
    const data = await s3Client.send(command);
    return data;
  } catch (err) {
    logger.error(`S3 get error: ${err.message}, stack: ${err.stack}`);
    throw err;
  }
}

// JWT authentication middleware
const authenticateToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];
  if (!token) {
    logger.warn(`No authorization token for route: ${req.originalUrl}`);
    return res.status(401).json({ message: 'Authorization token required' });
  }
  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    if (!decoded.id || !decoded.email) {
      logger.warn(`Token missing id or email: ${JSON.stringify(decoded)}`);
      return res.status(403).json({ message: 'Invalid token: missing required data' });
    }
    req.user = decoded;
    logger.info(`Token verified: id=${decoded.id}, email=${decoded.email}, route: ${req.originalUrl}`);
    next();
  } catch (error) {
    logger.error(`Token verification error for route ${req.originalUrl}: ${error.message}, stack: ${error.stack}`);
    return res.status(403).json({
      message: 'Invalid or expired token',
      error: error.message,
    });
  }
};

// Optional JWT authentication middleware
const optionalAuthenticateToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];
  if (token) {
    jwt.verify(token, JWT_SECRET, (err, user) => {
      if (!err) {
        req.user = user;
      }
      next();
    });
  } else {
    next();
  }
};

// Database initialization
async function initializeDatabase() {
  try {
    const connection = await db.getConnection();
    logger.info('MySQL connection established');

    // Create Users table
    await connection.query(`
      CREATE TABLE IF NOT EXISTS Users (
        id INT AUTO_INCREMENT PRIMARY KEY,
        email VARCHAR(255) NOT NULL UNIQUE,
        password VARCHAR(255) NOT NULL,
        accountType ENUM('individual', 'commercial') NOT NULL,
        name VARCHAR(255) NOT NULL,
        phone VARCHAR(20) NOT NULL,
        telegramUsername VARCHAR(255),
        addressStreet VARCHAR(255),
        addressCity VARCHAR(255),
        addressCountry VARCHAR(255),
        addressPostalCode VARCHAR(20),
        documents JSON,
        isVerified BOOLEAN DEFAULT FALSE,
        isBlocked BOOLEAN DEFAULT FALSE,
        jwtToken VARCHAR(500),
        resetPasswordToken VARCHAR(500),
        resetPasswordExpires DATETIME,
        verificationToken VARCHAR(500),
        verificationExpires DATETIME,
        createdAt TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        updatedAt TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
      )
    `);
    logger.info('Users table checked/created');

    // Create PreRegisters table
    await connection.query(`
      CREATE TABLE IF NOT EXISTS PreRegisters (
        id INT AUTO_INCREMENT PRIMARY KEY,
        email VARCHAR(255) NOT NULL UNIQUE,
        createdAt TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        updatedAt TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
      )
    `);
    logger.info('PreRegisters table checked/created');

    // Create Apps table
    await connection.query(`
      CREATE TABLE IF NOT EXISTS Apps (
        id INT AUTO_INCREMENT PRIMARY KEY,
        name VARCHAR(255) NOT NULL,
        description TEXT NOT NULL,
        category ENUM('games', 'productivity', 'education', 'entertainment') NOT NULL,
        iconPath VARCHAR(500) NOT NULL,
        apkPath VARCHAR(500) NOT NULL,
        userId INT NOT NULL,
        status ENUM('pending', 'approved', 'rejected') DEFAULT 'pending',
        createdAt TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        updatedAt TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
        FOREIGN KEY (userId) REFERENCES Users(id) ON DELETE CASCADE
      )
    `);
    logger.info('Apps table checked/created');

    // Create Advertisements table
    await connection.query(`
      CREATE TABLE IF NOT EXISTS Advertisements (
        id INT AUTO_INCREMENT PRIMARY KEY,
        name VARCHAR(255) NOT NULL,
        description TEXT NOT NULL,
        budget DECIMAL(10,2) NOT NULL,
        status ENUM('active', 'paused', 'completed') DEFAULT 'active',
        impressions INT DEFAULT 0,
        clicks INT DEFAULT 0,
        endDate DATE,
        userId INT NOT NULL,
        createdAt TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        updatedAt TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
        FOREIGN KEY (userId) REFERENCES Users(id) ON DELETE CASCADE
      )
    `);
    logger.info('Advertisements table checked/created');

    // Create default admin
    const [users] = await connection.query("SELECT * FROM Users WHERE email = ?", ['admin@24webstudio.ru']);
    if (users.length === 0) {
      const hashedPassword = await bcrypt.hash('admin123', 10);
      await connection.query(
        "INSERT INTO Users (email, password, accountType, name, phone, isVerified) VALUES (?, ?, ?, ?, ?, ?)",
        ['admin@24webstudio.ru', hashedPassword, 'commercial', 'Admin', '1234567890', true]
      );
      logger.info('Admin created: admin@24webstudio.ru / admin123');
    } else {
      logger.info('Admin already exists: admin@24webstudio.ru');
    }

    connection.release();
  } catch (err) {
    logger.error(`Database initialization error: ${err.message}, stack: ${err.stack}`);
    throw err;
  }
}

// Telegram Bot Setup
const TelegramBot = require('node-telegram-bot-api');
const bot = new TelegramBot(TELEGRAM_BOT_TOKEN, { polling: true });

// Function to resolve Telegram username to chat ID
async function resolveTelegramUsername(username) {
  try {
    const response = await axios.get(`https://api.telegram.org/bot${TELEGRAM_BOT_TOKEN}/getChat`, {
      params: { chat_id: username },
    });
    if (response.data.ok) {
      return response.data.result.id;
    }
    return null;
  } catch (error) {
    logger.error(`Error resolving chat_id for ${username}: ${error.message}`);
    return null;
  }
}

// Telegram Bot Commands
bot.onText(/\/start/, (msg) => {
  const chatId = msg.chat.id;
  bot.sendMessage(chatId, 'Welcome! Use the following commands to manage your account:\n' +
    '/status - Check verification status\n' +
    '/verify <code> - Verify your account\n' +
    '/delete - Request account deletion');
});

bot.onText(/\/status/, async (msg) => {
  const chatId = msg.chat.id;
  const username = `@${msg.from.username}`;
  try {
    const [user] = await db.query('SELECT email, isVerified, isBlocked FROM Users WHERE telegramUsername = ?', [username]);
    if (!user.length) {
      bot.sendMessage(chatId, 'Account not found. Please register with this Telegram username.');
      return;
    }
    const status = user[0].isVerified ? 'Verified' : 'Awaiting verification';
    const blockStatus = user[0].isBlocked ? 'Blocked' : 'Active';
    bot.sendMessage(chatId, `Your account (${user[0].email}):\nStatus: ${status}\nBlock status: ${blockStatus}`);
  } catch (error) {
    logger.error(`Error checking status for ${username}: ${error.message}`);
    bot.sendMessage(chatId, 'Server error. Please try again later.');
  }
});

bot.onText(/\/verify (.+)/, async (msg, match) => {
  const chatId = msg.chat.id;
  const username = `@${msg.from.username}`;
  const code = match[1];
  try {
    const [user] = await db.query('SELECT id, email, verificationToken FROM Users WHERE telegramUsername = ? AND verificationToken = ?', [username, code]);
    if (!user.length) {
      bot.sendMessage(chatId, 'Invalid verification code or account not found.');
      return;
    }
    await db.query('UPDATE Users SET isVerified = ?, verificationToken = NULL, verificationExpires = NULL WHERE id = ?', [true, user[0].id]);
    bot.sendMessage(chatId, `Account ${user[0].email} successfully verified!`);
    logger.info(`User ${user[0].email} verified via Telegram`);
  } catch (error) {
    logger.error(`Error verifying via Telegram for ${username}: ${error.message}`);
    bot.sendMessage(chatId, 'Server error. Please try again later.');
  }
});

bot.onText(/\/delete/, async (msg) => {
  const chatId = msg.chat.id;
  const username = `@${msg.from.username}`;
  try {
    const [user] = await db.query('SELECT id, email, documents FROM Users WHERE telegramUsername = ?', [username]);
    if (!user.length) {
      bot.sendMessage(chatId, 'Account not found.');
      return;
    }
    let documents = [];
    try {
      documents = user[0].documents ? JSON.parse(user[0].documents) : [];
      if (!Array.isArray(documents)) documents = [documents];
    } catch (parseError) {
      logger.error(`Error parsing documents for ${user[0].email}: ${parseError.message}`);
    }
    for (const doc of documents) {
      const docKey = doc.split('/').pop();
      if (docKey) await deleteFromS3(`documents/${docKey}`);
    }
    await db.query('DELETE FROM Users WHERE id = ?', [user[0].id]);
    bot.sendMessage(chatId, `Account ${user[0].email} successfully deleted.`);
    logger.info(`Account ${user[0].email} deleted via Telegram`);
  } catch (error) {
    logger.error(`Error deleting account for ${username}: ${error.message}`);
    bot.sendMessage(chatId, 'Server error. Please try again later.');
  }
});

// Server initialization
async function initializeServer() {
  try {
    await initializeDatabase();
    await checkS3Connection();
    app.listen(PORT, () => {
      logger.info(`Server started on port ${PORT}`);
    });
  } catch (err) {
    logger.error(`Server initialization error: ${err.message}, stack: ${err.stack}`);
    process.exit(1);
  }
}

// Public routes
// Get approved apps
app.get('/api/public/apps', async (req, res) => {
  try {
    const [apps] = await db.query(`
      SELECT id, name, description, category, iconPath, status, createdAt
      FROM Apps
      WHERE status = 'approved'
      ORDER BY createdAt DESC
    `);
    res.json(apps);
  } catch (err) {
    logger.error(`Error fetching apps: ${err.message}, stack: ${err.stack}`);
    res.status(500).json({ message: 'Server error', error: err.message });
  }
});

// Get app image
app.get('/api/public/app-image/:key', optionalAuthenticateToken, async (req, res) => {
  const { key } = req.params;
  try {
    const image = await getFromS3(`icons/${key}`);
    res.setHeader('Content-Type', image.ContentType || 'image/png');
    image.Body.pipe(res);
  } catch (err) {
    logger.error(`Error fetching image: ${err.message}, stack: ${err.stack}`);
    res.status(500).json({ message: 'Error fetching image', error: err.message });
  }
});

// User pre-registration
app.post(
  '/api/pre-register',
  [
    body('email').isEmail().normalizeEmail().withMessage('Valid email is required'),
    body('telegramUsername').optional().matches(/^@[\w\d_]{5,32}$/).withMessage('Invalid Telegram username'),
  ],
  async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      logger.warn(`Validation errors: ${JSON.stringify(errors.array())}`);
      return res.status(400).json({ message: 'Validation error', errors: errors.array() });
    }

    try {
      const { email, telegramUsername } = req.body;
      const [existing] = await db.query('SELECT email FROM PreRegisters WHERE email = ?', [email]);
      if (existing.length > 0) {
        return res.status(400).json({ message: 'Email already in waitlist' });
      }

      await db.query('INSERT INTO PreRegisters (email) VALUES (?)', [email]);
      logger.info(`Pre-registration: ${email}`);

      if (telegramUsername) {
        const chatId = await resolveTelegramUsername(telegramUsername);
        if (chatId) {
          try {
            await bot.sendMessage(chatId, `Thank you for pre-registering, ${email}!`);
            logger.info(`Telegram notification sent for ${telegramUsername}`);
          } catch (telegramErr) {
            logger.error(`Telegram notification error for ${telegramUsername}: ${telegramErr.message}`);
          }
        }
      }

      res.status(201).json({ message: `Thank you! Your email (${email}) has been added to the waitlist.` });
    } catch (error) {
      logger.error(`Pre-registration error: ${error.message}, stack: ${error.stack}`);
      res.status(500).json({ message: 'Server error', error: error.message });
    }
  }
);

// User registration
app.post(
  '/api/auth/register',
  upload,
  [
    body('email').isEmail().normalizeEmail().withMessage('Valid email is required'),
    body('password').isLength({ min: 8 }).withMessage('Password must be at least 8 characters'),
    body('accountType').isIn(['individual', 'commercial']).withMessage('Invalid account type'),
    body('name').notEmpty().trim().withMessage('Name is required'),
    body('phone').notEmpty().trim().withMessage('Phone number is required'),
    body('telegramUsername').optional().matches(/^@[\w\d_]{5,32}$/).withMessage('Invalid Telegram username'),
  ],
  async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      logger.warn(`Validation errors: ${JSON.stringify(errors.array())}`);
      return res.status(400).json({ message: 'Validation error', errors: errors.array() });
    }

    try {
      const { email, password, accountType, name, phone, telegramUsername, addressStreet, addressCity, addressCountry, addressPostalCode } = req.body;
      if (!req.files || !req.files.documents || req.files.documents.length === 0) {
        logger.warn('No documents uploaded');
        return res.status(400).json({ message: 'At least one document is required' });
      }

      const [existingUser] = await db.query('SELECT email FROM Users WHERE email = ?', [email]);
      if (existingUser.length > 0) {
        return res.status(400).json({ message: 'Email already registered' });
      }

      const documentUrls = await Promise.all(req.files.documents.map(file => uploadToS3(file, 'documents')));
      const salt = await bcrypt.genSalt(10);
      const hashedPassword = await bcrypt.hash(password, salt);
      const verificationToken = jwt.sign({ email, purpose: 'verify' }, JWT_SECRET, { expiresIn: '1h' });
      const verificationLink = `${FRONTEND_URL}/verify?token=${verificationToken}`;

      const [result] = await db.query(
        `INSERT INTO Users (
          email, password, accountType, name, phone, telegramUsername, addressStreet, addressCity, addressCountry, addressPostalCode,
          documents, isVerified, verificationToken, verificationExpires
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
        [
          email, hashedPassword, accountType, name, phone, telegramUsername || null, addressStreet || null, addressCity || null, addressCountry || null,
          addressPostalCode || null, JSON.stringify(documentUrls), false, verificationToken, new Date(Date.now() + 3600000),
        ]
      );

      const authToken = jwt.sign({ id: result.insertId, email }, JWT_SECRET, { expiresIn: '7d' });
      await db.query('UPDATE Users SET jwtToken = ? WHERE id = ?', [authToken, result.insertId]);

      if (telegramUsername) {
        const chatId = await resolveTelegramUsername(telegramUsername);
        if (chatId) {
          try {
            await bot.sendMessage(
              chatId,
              `Welcome, ${name}! You have registered with email: ${email}.\n` +
              `Please verify your account by clicking this link: ${verificationLink}`
            );
            logger.info(`Registration notification sent to Telegram for ${telegramUsername}`);
          } catch (telegramErr) {
            logger.error(`Telegram notification error for ${telegramUsername}: ${telegramErr.message}`);
          }
        }
      }

      try {
        await bot.sendMessage(
          '-1002311447135',
          `New documents for review from user ${email} (${telegramUsername || 'no Telegram'}). Count: ${documentUrls.length}`
        );
        logger.info(`Telegram notification sent for user ${email} documents`);
      } catch (telegramErr) {
        logger.error(`Telegram admin notification error: ${telegramErr.message}`);
      }

      logger.info(`User registered: ${email}, documents: ${JSON.stringify(documentUrls)}`);
      res.status(201).json({
        message: 'Registration successful. Check Telegram for verification link.',
        token: authToken,
        user: { id: result.insertId, email, accountType, name, phone, telegramUsername, isVerified: false },
      });
    } catch (error) {
      logger.error(`Registration error: ${error.message}, stack: ${error.stack}`);
      res.status(500).json({ message: 'Server error', error: error.message });
    }
  }
);

// Verify account via token
app.get('/api/auth/verify/:token', async (req, res) => {
  const { token } = req.params;
  try {
    let decoded;
    try {
      decoded = jwt.verify(token, JWT_SECRET);
      if (decoded.purpose !== 'verify') {
        return res.status(400).json({ message: 'Invalid verification token' });
      }
    } catch (error) {
      logger.warn(`Invalid verification token: ${error.message}`);
      return res.status(400).json({ message: 'Invalid or expired verification token' });
    }

    const [user] = await db.query(
      'SELECT id, email, telegramUsername FROM Users WHERE email = ? AND verificationToken = ? AND verificationExpires > NOW()',
      [decoded.email, token]
    );
    if (!user.length) {
      logger.warn(`Invalid or expired verification token for email: ${decoded.email}`);
      return res.status(400).json({ message: 'Invalid or expired verification token' });
    }

    await db.query('UPDATE Users SET isVerified = ?, verificationToken = NULL, verificationExpires = NULL WHERE id = ?', [true, user[0].id]);

    if (user[0].telegramUsername) {
      const chatId = await resolveTelegramUsername(user[0].telegramUsername);
      if (chatId) {
        try {
          await bot.sendMessage(chatId, `Your account ${user[0].email} has been successfully verified!`);
          logger.info(`Verification notification sent to Telegram for ${user[0].telegramUsername}`);
        } catch (telegramErr) {
          logger.error(`Telegram notification error for ${user[0].telegramUsername}: ${telegramErr.message}`);
        }
      }
    }

    logger.info(`User ${user[0].email} verified via link`);
    res.status(200).json({ message: 'Account successfully verified' });
  } catch (error) {
    logger.error(`Verification error: ${error.message}, stack: ${error.stack}`);
    res.status(500).json({ message: 'Server error', error: error.message });
  }
});

// User login
app.post(
  '/api/auth/login',
  [
    body('email').isEmail().normalizeEmail().withMessage('Valid email is required'),
    body('password').notEmpty().withMessage('Password is required'),
  ],
  async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      logger.warn(`Validation errors: ${JSON.stringify(errors.array())}`);
      return res.status(400).json({ message: 'Validation error', errors: errors.array() });
    }

    try {
      const { email, password } = req.body;
      const [user] = await db.query('SELECT * FROM Users WHERE email = ?', [email]);
      if (!user.length) {
        logger.warn(`Login attempt with non-existent email: ${email}`);
        return res.status(400).json({ message: 'Invalid email or password' });
      }

      const isMatch = await bcrypt.compare(password, user[0].password);
      if (!isMatch) {
        logger.warn(`Invalid password for email: ${email}`);
        return res.status(400).json({ message: 'Invalid email or password' });
      }

      const token = jwt.sign({ id: user[0].id, email: user[0].email }, JWT_SECRET, { expiresIn: '7d' });
      await db.query('UPDATE Users SET jwtToken = ? WHERE id = ?', [token, user[0].id]);

      if (user[0].telegramUsername) {
        const chatId = await resolveTelegramUsername(user[0].telegramUsername);
        if (chatId) {
          try {
            await bot.sendMessage(chatId, `You have successfully logged into ${email}`);
            logger.info(`Login notification sent to Telegram for ${user[0].telegramUsername}`);
          } catch (telegramErr) {
            logger.error(`Telegram notification error for ${user[0].telegramUsername}: ${telegramErr.message}`);
          }
        }
      }

      logger.info(`User logged in: ${user[0].email}`);
      res.status(200).json({
        token,
        user: {
          id: user[0].id,
          email: user[0].email,
          accountType: user[0].accountType,
          name: user[0].name,
          phone: user[0].phone,
          telegramUsername: user[0].telegramUsername,
          isVerified: user[0].isVerified,
        },
        message: user[0].isVerified ? 'Login successful' : 'Login successful, but account awaits verification',
      });
    } catch (error) {
      logger.error(`Login error: ${error.message}, stack: ${error.stack}`);
      res.status(500).json({ message: 'Server error', error: error.message });
    }
  }
);

// Forgot password
app.post(
  '/api/auth/forgot-password',
  [body('email').isEmail().normalizeEmail().withMessage('Valid email is required')],
  async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      logger.warn(`Validation errors: ${JSON.stringify(errors.array())}`);
      return res.status(400).json({ message: 'Validation error', errors: errors.array() });
    }

    try {
      const { email } = req.body;
      const [user] = await db.query('SELECT id, email, telegramUsername FROM Users WHERE email = ?', [email]);
      if (!user.length) {
        logger.warn(`Password reset attempt for non-existent email: ${email}`);
        return res.status(404).json({ message: 'User with this email not found' });
      }

      const resetToken = jwt.sign({ email }, JWT_SECRET, { expiresIn: '1h' });
      await db.query(
        'UPDATE Users SET resetPasswordToken = ?, resetPasswordExpires = ? WHERE email = ?',
        [resetToken, new Date(Date.now() + 3600000), email]
      );

      if (user[0].telegramUsername) {
        const chatId = await resolveTelegramUsername(user[0].telegramUsername);
        if (chatId) {
          try {
            await bot.sendMessage(
              chatId,
              `Password reset request for ${email}. Use this token to reset your password: ${resetToken}`
            );
            logger.info(`Password reset notification sent to Telegram for ${user[0].telegramUsername}`);
          } catch (telegramErr) {
            logger.error(`Telegram notification error for ${user[0].telegramUsername}: ${telegramErr.message}`);
          }
        }
      }

      logger.info(`Password reset requested for ${user[0].email}`);
      res.status(200).json({ message: 'Password reset link sent (check Telegram or email)' });
    } catch (error) {
      logger.error(`Password reset error: ${error.message}, stack: ${error.stack}`);
      res.status(500).json({ message: 'Server error', error: error.message });
    }
  }
);

// Reset password
app.post(
  '/api/auth/reset-password/:token',
  [
    body('password').isLength({ min: 8 }).withMessage('Password must be at least 8 characters'),
    body('confirmPassword').custom((value, { req }) => value === req.body.password).withMessage('Passwords do not match'),
  ],
  async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      logger.warn(`Validation errors: ${JSON.stringify(errors.array())}`);
      return res.status(400).json({ message: 'Validation error', errors: errors.array() });
    }

    try {
      const { token } = req.params;
      const { password } = req.body;
      let decoded;
      try {
        decoded = jwt.verify(token, JWT_SECRET);
      } catch (error) {
        logger.warn(`Invalid reset token: ${error.message}, stack: ${error.stack}`);
        return res.status(400).json({ message: 'Invalid or expired reset token' });
      }

      const [user] = await db.query(
        'SELECT id, email, telegramUsername FROM Users WHERE email = ? AND resetPasswordToken = ? AND resetPasswordExpires > NOW()',
        [decoded.email, token]
      );
      if (!user.length) {
        logger.warn(`Invalid or expired reset token for email: ${decoded.email}`);
        return res.status(400).json({ message: 'Invalid or expired reset token' });
      }

      const salt = await bcrypt.genSalt(10);
      const hashedPassword = await bcrypt.hash(password, salt);
      await db.query(
        'UPDATE Users SET password = ?, resetPasswordToken = NULL, resetPasswordExpires = NULL, jwtToken = NULL WHERE email = ?',
        [hashedPassword, decoded.email]
      );

      if (user[0].telegramUsername) {
        const chatId = await resolveTelegramUsername(user[0].telegramUsername);
        if (chatId) {
          try {
            await bot.sendMessage(chatId, `Password for ${user[0].email} successfully reset.`);
            logger.info(`Password reset notification sent to Telegram for ${user[0].telegramUsername}`);
          } catch (telegramErr) {
            logger.error(`Telegram notification error for ${user[0].telegramUsername}: ${telegramErr.message}`);
          }
        }
      }

      logger.info(`Password reset for ${user[0].email}`);
      res.status(200).json({ message: 'Password successfully reset' });
    } catch (error) {
      logger.error(`Password reset error: ${error.message}, stack: ${error.stack}`);
      res.status(500).json({ message: 'Server error', error: error.message });
    }
  }
);

// Get user profile
app.get('/api/user/profile', authenticateToken, async (req, res) => {
  try {
    const [user] = await db.query(
      'SELECT id, email, accountType, name, phone, telegramUsername, addressStreet, addressCity, addressCountry, addressPostalCode, documents, isVerified, isBlocked, createdAt FROM Users WHERE id = ?',
      [req.user.id]
    );
    if (!user.length) {
      logger.warn(`User not found for ID: ${req.user.id}`);
      return res.status(404).json({ message: 'User not found' });
    }

    let documents = [];
    try {
      if (user[0].documents) {
        documents = typeof user[0].documents === 'string' ? JSON.parse(user[0].documents) : user[0].documents;
        if (!Array.isArray(documents)) {
          documents = [documents];
        }
      }
      logger.info(`User documents for ${user[0].email}: ${JSON.stringify(documents)}`);
    } catch (parseError) {
      logger.error(`Error parsing documents for user ${user[0].email}: ${parseError.message}, documents: ${user[0].documents}`);
      documents = [];
    }

    user[0].documents = documents;
    res.status(200).json(user[0]);
  } catch (error) {
    logger.error(`Error fetching profile: ${error.message}, stack: ${error.stack}`);
    res.status(500).json({ message: 'Server error', error: error.message });
  }
});

// Update user documents
app.post(
  '/api/user/documents',
  authenticateToken,
  upload,
  async (req, res) => {
    try {
      const [user] = await db.query('SELECT id, email, telegramUsername, documents FROM Users WHERE id = ?', [req.user.id]);
      if (!user.length) {
        logger.warn(`User not found for ID: ${req.user.id}`);
        return res.status(404).json({ message: 'User not found' });
      }

      if (!req.files || !req.files.documents || req.files.documents.length === 0) {
        logger.warn('No documents uploaded');
        return res.status(400).json({ message: 'At least one document is required' });
      }

      const newDocuments = await Promise.all(req.files.documents.map(file => uploadToS3(file, 'documents')));
      let currentDocuments = [];
      try {
        currentDocuments = user[0].documents ? JSON.parse(user[0].documents) : [];
        if (!Array.isArray(currentDocuments)) {
          currentDocuments = [currentDocuments];
        }
      } catch (parseError) {
        logger.error(`Error parsing current documents for user ${user[0].email}: ${parseError.message}`);
        currentDocuments = [];
      }

      const updatedDocuments = [...currentDocuments, ...newDocuments].slice(0, 3);
      await db.query('UPDATE Users SET documents = ?, isVerified = ? WHERE id = ?', [
        JSON.stringify(updatedDocuments), false, user[0].id
      ]);

      if (user[0].telegramUsername) {
        const chatId = await resolveTelegramUsername(user[0].telegramUsername);
        if (chatId) {
          try {
            await bot.sendMessage(chatId, `New documents uploaded for ${user[0].email}. Awaiting admin review.`);
            logger.info(`Document upload notification sent to Telegram for ${user[0].telegramUsername}`);
          } catch (telegramErr) {
            logger.error(`Telegram notification error for ${user[0].telegramUsername}: ${telegramErr.message}`);
          }
        }
      }

      try {
        await bot.sendMessage(
          '-1002311447135',
          `New documents for review from user ${user[0].email} (${user[0].telegramUsername || 'no Telegram'}). Count: ${newDocuments.length}`
        );
        logger.info(`Telegram notification sent for user ${user[0].email} documents`);
      } catch (telegramErr) {
        logger.error(`Telegram admin notification error: ${telegramErr.message}`);
      }

      logger.info(`Documents updated for user ${user[0].email}, new documents: ${JSON.stringify(updatedDocuments)}`);
      res.status(200).json({
        message: 'Documents successfully uploaded and awaiting admin review',
        documents: updatedDocuments,
      });
    } catch (error) {
      logger.error(`Error updating documents: ${error.message}, stack: ${error.stack}`);
      res.status(500).json({ message: 'Server error', error: error.message });
    }
  }
);

// Create app
app.post(
  '/api/apps/create',
  authenticateToken,
  upload,
  [
    body('name').notEmpty().trim().withMessage('App name is required'),
    body('description').notEmpty().trim().withMessage('Description is required'),
    body('category').isIn(['games', 'productivity', 'education', 'entertainment']).withMessage('Invalid category'),
  ],
  async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      logger.warn(`Validation errors: ${JSON.stringify(errors.array())}`);
      return res.status(400).json({ message: 'Validation error', errors: errors.array() });
    }

    try {
      const [user] = await db.query('SELECT id, email, telegramUsername, isVerified FROM Users WHERE id = ?', [req.user.id]);
      if (!user.length) {
        logger.warn(`User not found for ID: ${req.user.id}`);
        return res.status(404).json({ message: 'User not found' });
      }

      if (!user[0].isVerified) {
        logger.warn(`User not verified: ${user[0].email}`);
        return res.status(403).json({ message: 'Account must be verified to submit apps' });
      }

      const { name, description, category } = req.body;
      const files = req.files;

      if (!files || !files.icon || !files.icon[0]) {
        logger.warn('Icon file missing');
        return res.status(400).json({ message: 'Icon file required (PNG only)' });
      }
      if (!files.apk || !files.apk[0]) {
        logger.warn('APK file missing');
        return res.status(400).json({ message: 'APK file required' });
      }

      const iconUrl = await uploadToS3(files.icon[0], 'icons');
      const apkUrl = await uploadToS3(files.apk[0], 'apks');

      const [result] = await db.query(
        `INSERT INTO Apps (
          name, description, category, iconPath, apkPath, userId, status
        ) VALUES (?, ?, ?, ?, ?, ?, ?)`,
        [name, description, category, iconUrl, apkUrl, user[0].id, 'pending']
      );

      if (user[0].telegramUsername) {
        const chatId = await resolveTelegramUsername(user[0].telegramUsername);
        if (chatId) {
          try {
            await bot.sendMessage(chatId, `Your app ${name} has been submitted for review.`);
            logger.info(`App creation notification sent to Telegram for ${user[0].telegramUsername}`);
          } catch (telegramErr) {
            logger.error(`Telegram notification error for ${user[0].telegramUsername}: ${telegramErr.message}`);
          }
        }
      }

      try {
        await bot.sendMessage(
          '-1002311447135',
          `New app submitted: ${name} by ${user[0].email} (${user[0].telegramUsername || 'no Telegram'})`
        );
        logger.info(`Telegram notification sent for app ${name}`);
      } catch (telegramErr) {
        logger.error(`Telegram admin notification error: ${telegramErr.message}`);
      }

      logger.info(`App created by user ${user[0].email}: ${name}`);
      res.status(201).json({
        message: 'App successfully submitted',
        app: { id: result.insertId, name, description, category, iconPath: iconUrl, apkPath: apkUrl, userId: user[0].id, status: 'pending' },
      });
    } catch (error) {
      logger.error(`Error creating app: ${error.message}, stack: ${error.stack}`);
      res.status(500).json({ message: 'Server error', error: error.message });
    }
  }
);

// Admin routes
// Get all apps
app.get('/api/admin/apps', authenticateToken, async (req, res) => {
  try {
    const [user] = await db.query('SELECT email, accountType FROM Users WHERE id = ?', [req.user.id]);
    if (!user.length || user[0].email !== 'admin@24webstudio.ru') {
      return res.status(403).json({ message: 'Admin access required' });
    }

    const [apps] = await db.query(`
      SELECT a.*, u.email as userEmail, u.name as userName
      FROM Apps a
      JOIN Users u ON a.userId = u.id
      ORDER BY a.createdAt DESC
    `);
    res.json(apps);
  } catch (err) {
    logger.error(`Error fetching apps for admin: ${err.message}, stack: ${err.stack}`);
    res.status(500).json({ message: 'Server error', error: err.message });
  }
});

// Update app status
app.put('/api/admin/apps/:id', authenticateToken, async (req, res) => {
  const { id } = req.params;
  const { status } = req.body;

  try {
    const [user] = await db.query('SELECT email, accountType FROM Users WHERE id = ?', [req.user.id]);
    if (!user.length || user[0].email !== 'admin@24webstudio.ru') {
      return res.status(403).json({ message: 'Admin access required' });
    }

    if (!['pending', 'approved', 'rejected'].includes(status)) {
      return res.status(400).json({ message: 'Invalid status' });
    }

    const [app] = await db.query('SELECT * FROM Apps WHERE id = ?', [id]);
    if (!app.length) {
      return res.status(404).json({ message: 'App not found' });
    }

    await db.query('UPDATE Apps SET status = ? WHERE id = ?', [status, id]);

    const [appUser] = await db.query('SELECT email, telegramUsername FROM Users WHERE id = ?', [app[0].userId]);
    if (appUser[0].telegramUsername) {
      const chatId = await resolveTelegramUsername(appUser[0].telegramUsername);
      if (chatId) {
        try {
          await bot.sendMessage(chatId, `Your app ${app[0].name} status updated to ${status}.`);
          logger.info(`App status update notification sent to Telegram for ${appUser[0].telegramUsername}`);
        } catch (telegramErr) {
          logger.error(`Telegram notification error for ${appUser[0].telegramUsername}: ${telegramErr.message}`);
        }
      }
    }

    try {
      await bot.sendMessage(
        '-1002311447135',
        `App ${app[0].name} status updated to ${status} for user ${appUser[0].email} (${appUser[0].telegramUsername || 'no Telegram'})`
      );
      logger.info(`Telegram notification sent for app ${app[0].name}`);
    } catch (telegramErr) {
      logger.error(`Telegram admin notification error: ${telegramErr.message}`);
    }

    logger.info(`App ${id} status updated to ${status}`);
    res.json({ message: `App status updated to ${status}` });
  } catch (err) {
    logger.error(`Error updating app: ${err.message}, stack: ${err.stack}`);
    res.status(500).json({ message: 'Server error', error: err.message });
  }
});

// Delete app
app.delete('/api/admin/apps/:id', authenticateToken, async (req, res) => {
  const { id } = req.params;

  try {
    const [user] = await db.query('SELECT email, accountType FROM Users WHERE id = ?', [req.user.id]);
    if (!user.length || user[0].email !== 'admin@24webstudio.ru') {
      return res.status(403).json({ message: 'Admin access required' });
    }

    const [app] = await db.query('SELECT iconPath, apkPath, userId, name FROM Apps WHERE id = ?', [id]);
    if (!app.length) {
      return res.status(404).json({ message: 'App not found' });
    }

    if (app[0].iconPath) {
      const iconKey = app[0].iconPath.split('/').pop();
      if (iconKey) await deleteFromS3(`icons/${iconKey}`);
    }
    if (app[0].apkPath) {
      const apkKey = app[0].apkPath.split('/').pop();
      if (apkKey) await deleteFromS3(`apks/${apkKey}`);
    }

    const [appUser] = await db.query('SELECT email, telegramUsername FROM Users WHERE id = ?', [app[0].userId]);
    await db.query('DELETE FROM Apps WHERE id = ?', [id]);

    if (appUser[0].telegramUsername) {
      const chatId = await resolveTelegramUsername(appUser[0].telegramUsername);
      if (chatId) {
        try {
          await bot.sendMessage(chatId, `Your app ${app[0].name} was deleted by admin.`);
          logger.info(`App deletion notification sent to Telegram for ${appUser[0].telegramUsername}`);
        } catch (telegramErr) {
          logger.error(`Telegram notification error for ${appUser[0].telegramUsername}: ${telegramErr.message}`);
        }
      }
    }

    logger.info(`App ${id} deleted`);
    res.json({ message: 'App deleted' });
  } catch (err) {
    logger.error(`Error deleting app: ${err.message}, stack: ${err.stack}`);
    res.status(500).json({ message: 'Server error', error: err.message });
  }
});

// Get all users and their documents
app.get('/api/admin/users/documents', authenticateToken, async (req, res) => {
  try {
    const [user] = await db.query('SELECT email, accountType FROM Users WHERE id = ?', [req.user.id]);
    if (!user.length || user[0].email !== 'admin@24webstudio.ru') {
      return res.status(403).json({ message: 'Admin access required' });
    }

    const [users] = await db.query(`
      SELECT id, email, name, accountType, documents, isVerified, isBlocked, telegramUsername, createdAt
      FROM Users
      WHERE documents IS NOT NULL
      ORDER BY createdAt DESC
    `);

    const usersWithDocuments = users.map(u => {
      let documents = [];
      try {
        documents = u.documents ? JSON.parse(u.documents) : [];
        if (!Array.isArray(documents)) {
          documents = [documents];
        }
      } catch (parseError) {
        logger.error(`Error parsing documents for user ${u.email}: ${parseError.message}`);
        documents = [];
      }
      return { ...u, documents };
    });

    res.json(usersWithDocuments);
  } catch (err) {
    logger.error(`Error fetching user documents for admin: ${err.message}, stack: ${err.stack}`);
    res.status(500).json({ message: 'Server error', error: err.message });
  }
});

// Verify user documents
app.put('/api/admin/users/:id/verify', authenticateToken, async (req, res) => {
  const { id } = req.params;
  const { isVerified } = req.body;

  try {
    const [admin] = await db.query('SELECT email, accountType FROM Users WHERE id = ?', [req.user.id]);
    if (!admin.length || admin[0].email !== 'admin@24webstudio.ru') {
      return res.status(403).json({ message: 'Admin access required' });
    }

    if (typeof isVerified !== 'boolean') {
      return res.status(400).json({ message: 'Invalid verification status' });
    }

    const [user] = await db.query('SELECT email, telegramUsername, documents FROM Users WHERE id = ?', [id]);
    if (!user.length) {
      return res.status(404).json({ message: 'User not found' });
    }

    await db.query('UPDATE Users SET isVerified = ?, verificationToken = NULL, verificationExpires = NULL WHERE id = ?', [isVerified, id]);

    if (user[0].telegramUsername) {
      const chatId = await resolveTelegramUsername(user[0].telegramUsername);
      if (chatId) {
        try {
          await bot.sendMessage(chatId, `Your account ${user[0].email} has been ${isVerified ? 'verified' : 'rejected'}.`);
          logger.info(`Verification notification sent to Telegram for ${user[0].telegramUsername}`);
        } catch (telegramErr) {
          logger.error(`Telegram notification error for ${user[0].telegramUsername}: ${telegramErr.message}`);
        }
      }
    }

    try {
      await bot.sendMessage(
        '-1002311447135',
        `User ${user[0].email} (${user[0].telegramUsername || 'no Telegram'}) verification status updated to ${isVerified ? 'verified' : 'not verified'}`
      );
      logger.info(`Telegram notification sent for user ${user[0].email} verification`);
    } catch (telegramErr) {
      logger.error(`Telegram admin notification error: ${telegramErr.message}`);
    }

    logger.info(`User ${user[0].email} verification status updated to ${isVerified}`);
    res.json({ message: `Verification status updated to ${isVerified ? 'verified' : 'not verified'}` });
  } catch (err) {
    logger.error(`Error verifying user: ${err.message}, stack: ${err.stack}`);
    res.status(500).json({ message: 'Server error', error: err.message });
  }
});

// Delete user
app.delete('/api/admin/users/:id', authenticateToken, async (req, res) => {
  const { id } = req.params;

  try {
    const [admin] = await db.query('SELECT email, accountType FROM Users WHERE id = ?', [req.user.id]);
    if (!admin.length || admin[0].email !== 'admin@24webstudio.ru') {
      return res.status(403).json({ message: 'Admin access required' });
    }

    const [user] = await db.query('SELECT email, telegramUsername, documents FROM Users WHERE id = ?', [id]);
    if (!user.length) {
      return res.status(404).json({ message: 'User not found' });
    }

    let documents = [];
    try {
      documents = user[0].documents ? JSON.parse(user[0].documents) : [];
      if (!Array.isArray(documents)) documents = [documents];
    } catch (parseError) {
      logger.error(`Error parsing documents for ${user[0].email}: ${parseError.message}`);
    }

    for (const doc of documents) {
      const docKey = doc.split('/').pop();
      if (docKey) await deleteFromS3(`documents/${docKey}`);
    }

    await db.query('DELETE FROM Users WHERE id = ?', [id]);

    if (user[0].telegramUsername) {
      const chatId = await resolveTelegramUsername(user[0].telegramUsername);
      if (chatId) {
        try {
          await bot.sendMessage(chatId, `Your account ${user[0].email} was deleted by admin.`);
          logger.info(`Account deletion notification sent to Telegram for ${user[0].telegramUsername}`);
        } catch (telegramErr) {
          logger.error(`Telegram notification error for ${user[0].telegramUsername}: ${telegramErr.message}`);
        }
      }
    }

    try {
      await bot.sendMessage(
        '-1002311447135',
        `User ${user[0].email} (${user[0].telegramUsername || 'no Telegram'}) deleted`
      );
      logger.info(`Telegram notification sent for user ${user[0].email} deletion`);
    } catch (telegramErr) {
      logger.error(`Telegram admin notification error: ${telegramErr.message}`);
    }

    logger.info(`User ${user[0].email} deleted`);
    res.json({ message: 'User deleted' });
  } catch (err) {
    logger.error(`Error deleting user: ${err.message}, stack: ${err.stack}`);
    res.status(500).json({ message: 'Server error', error: err.message });
  }
});

// Admin routes for advertisements
// Get all advertisements
app.get('/api/admin/advertisements', authenticateToken, async (req, res) => {
  try {
    const [user] = await db.query('SELECT email, accountType FROM Users WHERE id = ?', [req.user.id]);
    if (!user.length || user[0].email !== 'admin@24webstudio.ru') {
      return res.status(403).json({ message: 'Admin access required' });
    }

    const [ads] = await db.query(`
      SELECT a.*, u.email as userEmail
      FROM Advertisements a
      JOIN Users u ON a.userId = u.id
      ORDER BY a.createdAt DESC
    `);
    res.json(ads.map(ad => ({
      ...ad,
      ctr: ad.clicks > 0 ? (ad.clicks / ad.impressions * 100) : 0,
    })));
  } catch (err) {
    logger.error(`Error fetching advertisements: ${err.message}, stack: ${err.stack}`);
    res.status(500).json({ message: 'Server error', error: err.message });
  }
});

// Create advertisement
app.post(
  '/api/admin/advertisements',
  authenticateToken,
  [
    body('name').notEmpty().trim().withMessage('Campaign name is required'),
    body('description').notEmpty().trim().withMessage('Description is required'),
    body('budget').isFloat({ min: 0 }).withMessage('Budget must be a positive number'),
    body('status').isIn(['active', 'paused', 'completed']).withMessage('Invalid status'),
    body('endDate').isDate().withMessage('Invalid end date'),
    body('userEmail').isEmail().normalizeEmail().withMessage('Valid user email is required'),
  ],
  async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      logger.warn(`Validation errors: ${JSON.stringify(errors.array())}`);
      return res.status(400).json({ message: 'Validation error', errors: errors.array() });
    }

    try {
      const [admin] = await db.query('SELECT email, accountType FROM Users WHERE id = ?', [req.user.id]);
      if (!admin.length || admin[0].email !== 'admin@24webstudio.ru') {
        return res.status(403).json({ message: 'Admin access required' });
      }

      const { name, description, budget, status, endDate, userEmail } = req.body;
      const [user] = await db.query('SELECT id, telegramUsername FROM Users WHERE email = ?', [userEmail]);
      if (!user.length) {
        return res.status(404).json({ message: 'User not found' });
      }

      const [result] = await db.query(
        `INSERT INTO Advertisements (name, description, budget, status, endDate, userId, impressions, clicks) 
         VALUES (?, ?, ?, ?, ?, ?, 0, 0)`,
        [name, description, budget, status, endDate, user[0].id]
      );

      if (user[0].telegramUsername) {
        const chatId = await resolveTelegramUsername(user[0].telegramUsername);
        if (chatId) {
          try {
            await bot.sendMessage(chatId, `New ad campaign ${name} created with budget $${budget}.`);
            logger.info(`Ad creation notification sent to Telegram for ${user[0].telegramUsername}`);
          } catch (telegramErr) {
            logger.error(`Telegram notification error for ${user[0].telegramUsername}: ${telegramErr.message}`);
          }
        }
      }

      try {
        await bot.sendMessage(
          '-1002311447135',
          `New ad campaign created: ${name}, budget: ${budget}, status: ${status}, user: ${userEmail}`
        );
        logger.info(`Telegram notification sent for campaign ${name}`);
      } catch (telegramErr) {
        logger.error(`Telegram admin notification error: ${telegramErr.message}`);
      }

      logger.info(`Ad campaign created: ${name}`);
      res.status(201).json({
        message: 'Ad campaign successfully created',
        ad: {
          id: result.insertId,
          name,
          description,
          budget,
          status,
          endDate,
          userEmail,
          impressions: 0,
          clicks: 0,
          createdAt: new Date(),
        },
      });
    } catch (error) {
      logger.error(`Error creating ad campaign: ${error.message}, stack: ${error.stack}`);
      res.status(500).json({ message: 'Server error', error: error.message });
    }
  }
);

// Update advertisement
app.put('/api/admin/advertisements/:id', authenticateToken, async (req, res) => {
  const { id } = req.params;
  const { status, endDate } = req.body;

  try {
    const [user] = await db.query('SELECT email, accountType FROM Users WHERE id = ?', [req.user.id]);
    if (!user.length || user[0].email !== 'admin@24webstudio.ru') {
      return res.status(403).json({ message: 'Admin access required' });
    }

    const [ad] = await db.query('SELECT * FROM Advertisements WHERE id = ?', [id]);
    if (!ad.length) {
      return res.status(404).json({ message: 'Campaign not found' });
    }

    const updates = {};
    if (status && !['active', 'paused', 'completed'].includes(status)) {
      return res.status(400).json({ message: 'Invalid status' });
    }
    if (status) updates.status = status;
    if (endDate) updates.endDate = endDate;

    await db.query('UPDATE Advertisements SET ? WHERE id = ?', [updates, id]);

    const [adUser] = await db.query('SELECT email, telegramUsername FROM Users WHERE id = ?', [ad[0].userId]);
    if (adUser[0].telegramUsername) {
      const chatId = await resolveTelegramUsername(adUser[0].telegramUsername);
      if (chatId) {
        try {
          await bot.sendMessage(chatId, `Your campaign ${ad[0].name} status updated to ${status || ad[0].status}.`);
          logger.info(`Campaign update notification sent to Telegram for ${adUser[0].telegramUsername}`);
        } catch (telegramErr) {
          logger.error(`Telegram notification error for ${adUser[0].telegramUsername}: ${telegramErr.message}`);
        }
      }
    }

    try {
      await bot.sendMessage(
        '-1002311447135',
        `Campaign ${ad[0].name} status updated to ${status || ad[0].status} for user ${adUser[0].email} (${adUser[0].telegramUsername || 'no Telegram'})`
      );
      logger.info(`Telegram notification sent for campaign ${ad[0].name}`);
    } catch (telegramErr) {
      logger.error(`Telegram admin notification error: ${telegramErr.message}`);
    }

    logger.info(`Campaign ${id} updated`);
    res.json({ message: `Campaign updated` });
  } catch (err) {
    logger.error(`Error updating campaign: ${err.message}, stack: ${err.stack}`);
    res.status(500).json({ message: 'Server error', error: err.message });
  }
});

// Delete advertisement
app.delete('/api/admin/advertisements/:id', authenticateToken, async (req, res) => {
  const { id } = req.params;

  try {
    const [user] = await db.query('SELECT email, accountType FROM Users WHERE id = ?', [req.user.id]);
    if (!user.length || user[0].email !== 'admin@24webstudio.ru') {
      return res.status(403).json({ message: 'Admin access required' });
    }

    const [ad] = await db.query('SELECT name, userId FROM Advertisements WHERE id = ?', [id]);
    if (!ad.length) {
      return res.status(404).json({ message: 'Campaign not found' });
    }

    const [adUser] = await db.query('SELECT email, telegramUsername FROM Users WHERE id = ?', [ad[0].userId]);
    await db.query('DELETE FROM Advertisements WHERE id = ?', [id]);

    if (adUser[0].telegramUsername) {
      const chatId = await resolveTelegramUsername(adUser[0].telegramUsername);
      if (chatId) {
        try {
          await bot.sendMessage(chatId, `Your campaign ${ad[0].name} was deleted by admin.`);
          logger.info(`Campaign deletion notification sent to Telegram for ${adUser[0].telegramUsername}`);
        } catch (telegramErr) {
          logger.error(`Telegram notification error for ${adUser[0].telegramUsername}: ${telegramErr.message}`);
        }
      }
    }

    try {
      await bot.sendMessage(
        '-1002311447135',
        `Campaign ${ad[0].name} deleted for user ${adUser[0].email} (${adUser[0].telegramUsername || 'no Telegram'})`
      );
      logger.info(`Telegram notification sent for campaign ${ad[0].name} deletion`);
    } catch (telegramErr) {
      logger.error(`Telegram admin notification error: ${telegramErr.message}`);
    }

    logger.info(`Campaign ${id} deleted`);
    res.json({ message: 'Campaign deleted' });
  } catch (err) {
    logger.error(`Error deleting campaign: ${err.message}, stack: ${err.stack}`);
    res.status(500).json({ message: 'Server error', error: err.message });
  }
});

// Error handling middleware
app.use((err, req, res, next) => {
  logger.error(`Unhandled error: ${err.message}, stack: ${err.stack}, route: ${req.originalUrl}`);
  if (err instanceof multer.MulterError) {
    logger.warn(`Multer error: ${err.message}`);
    return res.status(400).json({ message: `File upload error: ${err.message}` });
  }
  if (err.message.includes('Only')) {
    logger.warn(`File type error: ${err.message}`);
    return res.status(400).json({ message: err.message });
  }
  res.status(500).json({ message: 'Server error', error: err.message });
});

// Graceful shutdown
async function shutdown() {
  logger.info('Performing graceful shutdown...');
  await db.end();
  logger.info('Database connection closed');
  process.exit(0);
}

process.on('SIGINT', shutdown);
process.on('SIGTERM', shutdown);

// Start server
initializeServer();