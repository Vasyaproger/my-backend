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
const TelegramBot = require('node-telegram-bot-api');
const Queue = require('bull');

const app = express();

// Configuration
require('dotenv').config();
const JWT_SECRET = process.env.JWT_SECRET || 'x7b9k3m8p2q5w4z6t1r0y9u2j4n6l8h3';
const DB_HOST = process.env.DB_HOST || 'vh438.timeweb.ru';
const DB_USER = process.env.DB_USER || 'ch79145_project';
const DB_PASSWORD = process.env.DB_PASSWORD || 'Vasya11091109';
const DB_NAME = process.env.DB_NAME || 'ch79145_project';
const S3_ACCESS_KEY = process.env.S3_ACCESS_KEY || 'DN1NLZTORA2L6NZ529JJ';
const S3_SECRET_KEY = process.env.S3_SECRET_KEY || 'iGg3syd3UiWzhoYbYlEEDSVX1HHVmWUptrBt81Y8';
const PORT = process.env.PORT || 5000;
const BUCKET_NAME = process.env.BUCKET_NAME || '4eeafbc6-4af2cd44-4c23-4530-a2bf-750889dfdf75';
const TELEGRAM_BOT_TOKEN = process.env.TELEGRAM_BOT_TOKEN || '7597915834:AAFzMDAKOc5UgcuAXWYdXy4V0Hj4qXL0KeY';
const REDIS_URL = process.env.REDIS_URL || 'redis://127.0.0.1:6379';

// File validation constants
const VALID_IMAGE_MIME_TYPES = ['image/png', 'image/jpeg', 'image/jpg', 'image/gif', 'image/webp'];
const VALID_IMAGE_EXTENSIONS = /\.(png|jpg|jpeg|gif|webp)$/i;
const VALID_DOCUMENT_MIME_TYPES = ['application/pdf', 'image/png', 'image/jpeg', 'image/jpg', 'image/gif', 'image/webp'];
const VALID_DOCUMENT_EXTENSIONS = /\.(pdf|png|jpg|jpeg|gif|webp)$/i;
const VALID_APP_MIME_TYPES = [
  'application/vnd.android.package-archive',
  'application/x-android-app-bundle',
  'application/octet-stream',
  'application/x-apk',
  'application/zip',
  'application/x-zip-compressed',
];
const VALID_APP_EXTENSIONS = /\.(apk|aab)$/i;
const MAX_IMAGE_SIZE = 10 * 1024 * 1024; // 10 MB
const MAX_APP_SIZE = 50 * 1024 * 1024; // 50 MB
const MAX_DOCUMENT_SIZE = 10 * 1024 * 1024; // 10 MB

// Design-related keywords for description validation
const DESIGN_RELATED_KEYWORDS = [
  'дизайн', 'интерфейс', 'визуал', 'цвет', 'тема', 'макет', 'шрифт', 'графика', 'стиль', 'оформление',
  'layout', 'UI', 'UX', 'interface', 'visual', 'color', 'theme', 'font', 'graphic', 'style', 'design'
];

// Environment variable validation
const requiredEnvVars = ['JWT_SECRET', 'DB_HOST', 'DB_USER', 'DB_PASSWORD', 'DB_NAME', 'S3_ACCESS_KEY', 'S3_SECRET_KEY', 'BUCKET_NAME', 'TELEGRAM_BOT_TOKEN'];
for (const envVar of requiredEnvVars) {
  if (!process.env[envVar]) {
    console.error(`Error: ${envVar} not set in environment variables`);
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

// S3 client setup
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
  connectTimeout: 10000,
});

// Multer setup for file uploads
const upload = multer({
  storage: multer.memoryStorage(),
  limits: {
    fileSize: (req, file) => {
      if (file.fieldname === 'icon') return MAX_IMAGE_SIZE;
      if (file.fieldname === 'apk') return MAX_APP_SIZE;
      if (file.fieldname === 'documents') return MAX_DOCUMENT_SIZE;
      return MAX_IMAGE_SIZE;
    },
  },
  fileFilter: (req, file, cb) => {
    try {
      let validMimeTypes, validExtensions, errorMessage;
      if (file.fieldname === 'icon') {
        validMimeTypes = VALID_IMAGE_MIME_TYPES;
        validExtensions = VALID_IMAGE_EXTENSIONS;
        errorMessage = 'Only PNG, JPG, JPEG, GIF, WebP allowed for icons!';
      } else if (file.fieldname === 'apk') {
        validMimeTypes = VALID_APP_MIME_TYPES;
        validExtensions = VALID_APP_EXTENSIONS;
        errorMessage = 'Only APK and AAB files allowed!';
      } else if (file.fieldname === 'documents') {
        validMimeTypes = VALID_DOCUMENT_MIME_TYPES;
        validExtensions = VALID_DOCUMENT_EXTENSIONS;
        errorMessage = 'Only PDF, PNG, JPG, JPEG, GIF, WebP allowed for documents!';
      } else {
        logger.warn(`Invalid field name: ${file.fieldname}`);
        return cb(new Error('Invalid field name!'));
      }

      const extname = validExtensions.test(path.extname(file.originalname).toLowerCase());
      const mimetype = validMimeTypes.includes(file.mimetype);

      if (extname && mimetype) {
        return cb(null, true);
      }

      logger.warn(`Invalid file: field=${file.fieldname}, name=${file.originalname}, MIME=${file.mimetype}`);
      cb(new Error(errorMessage));
    } catch (err) {
      logger.error(`Multer filter error: ${err.message}, stack: ${err.stack}`);
      cb(err);
    }
  },
}).fields([
  { name: 'icon', maxCount: 1 },
  { name: 'apk', maxCount: 1 },
  { name: 'documents', maxCount: 3 },
]);

// S3 upload function
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
    if (file.size > (folder === 'apks' ? MAX_APP_SIZE : MAX_IMAGE_SIZE)) {
      throw new Error(`File too large: ${file.originalname}`);
    }

    const upload = new Upload({
      client: s3Client,
      params,
      timeout: 30000,
    });
    const result = await upload.done();
    const location = `https://s3.twcstorage.ru/${BUCKET_NAME}/${key}`;
    logger.info(`File uploaded to S3: ${key}, URL: ${location}`);
    return location;
  } catch (error) {
    logger.error(`S3 upload error for ${key}: ${error.message}, stack: ${error.stack}`);
    throw new Error(`S3 upload error: ${error.message}`);
  }
}

// S3 delete function
async function deleteFromS3(key) {
  const params = { Bucket: BUCKET_NAME, Key: key };
  try {
    await s3Client.send(new DeleteObjectCommand(params));
    logger.info(`File deleted from S3: ${key}`);
  } catch (err) {
    logger.error(`S3 delete error: ${err.message}, stack: ${err.stack}`);
    throw err;
  }
}

// S3 get function
async function getFromS3(key) {
  const params = { Bucket: BUCKET_NAME, Key: key };
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
    return res.status(403).json({ message: 'Invalid or expired token', error: error.message });
  }
};

// Optional JWT authentication middleware
const optionalAuthenticateToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];
  if (token) {
    jwt.verify(token, JWT_SECRET, (err, user) => {
      if (!err) req.user = user;
      next();
    });
  } else {
    next();
  }
};

// Telegram notification queue setup
const telegramQueue = new Queue('telegram-notifications', REDIS_URL, {
  limiter: { max: 30, duration: 1000 },
});

// Process queue jobs
telegramQueue.process(async (job) => {
  const { chatId, text } = job.data;
  try {
    await axios.post(
      `https://api.telegram.org/bot${TELEGRAM_BOT_TOKEN}/sendMessage`,
      { chat_id: chatId, text, parse_mode: 'Markdown' },
      { timeout: 10000 }
    );
    logger.info(`Notification sent to Telegram ${chatId}: ${text}`);
  } catch (err) {
    logger.error(`Telegram notification error ${chatId}: ${err.message}, stack: ${err.stack}`);
    throw err;
  }
});

// Check description for design-related suggestions
function containsDesignSuggestions(description) {
  const lowerDescription = description.toLowerCase();
  return DESIGN_RELATED_KEYWORDS.some(keyword => lowerDescription.includes(keyword));
}

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
        telegramId VARCHAR(255) UNIQUE,
        addressStreet VARCHAR(255),
        addressCity VARCHAR(255),
        addressCountry VARCHAR(255),
        addressPostalCode VARCHAR(20),
        documents JSON,
        isVerified BOOLEAN DEFAULT FALSE,
        verificationToken VARCHAR(500),
        verificationExpires DATETIME,
        jwtToken VARCHAR(500),
        resetPasswordToken VARCHAR(500),
        resetPasswordExpires DATETIME,
        isBlocked BOOLEAN DEFAULT FALSE,
        createdAt TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        updatedAt TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
      )
    `);
    logger.info('Users table checked/created');

    // Check and add missing columns
    const [columns] = await connection.query(`SHOW COLUMNS FROM Users`);
    const columnNames = columns.map(col => col.Field);
    if (!columnNames.includes('telegramId')) {
      await connection.query(`ALTER TABLE Users ADD COLUMN telegramId VARCHAR(255) UNIQUE`);
      logger.info('telegramId column added');
    }
    if (!columnNames.includes('verificationToken')) {
      await connection.query(`ALTER TABLE Users ADD COLUMN verificationToken VARCHAR(500)`);
      logger.info('verificationToken column added');
    }
    if (!columnNames.includes('verificationExpires')) {
      await connection.query(`ALTER TABLE Users ADD COLUMN verificationExpires DATETIME`);
      logger.info('verificationExpires column added');
    }
    if (!columnNames.includes('isBlocked')) {
      await connection.query(`ALTER TABLE Users ADD COLUMN isBlocked BOOLEAN DEFAULT FALSE`);
      logger.info('isBlocked column added');
    }

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
        title VARCHAR(255) NOT NULL,
        description TEXT NOT NULL,
        imagePath VARCHAR(500),
        userId INT NOT NULL,
        status ENUM('pending', 'approved', 'rejected') DEFAULT 'pending',
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

// Telegram bot initialization
const bot = new TelegramBot(TELEGRAM_BOT_TOKEN, { polling: true });

// Handle /start command
bot.onText(/\/start/, async (msg) => {
  const chatId = msg.chat.id;
  logger.info(`Received /start command from Telegram ID: ${chatId}`);

  try {
    const [user] = await db.query('SELECT email, isVerified FROM Users WHERE telegramId = ?', [chatId]);
    if (user.length > 0) {
      if (user[0].isVerified) {
        bot.sendMessage(chatId, 'Your account is already verified.');
      } else {
        bot.sendMessage(chatId, `Your account is linked to email: ${user[0].email}. Awaiting document verification by admin.`);
      }
    } else {
      bot.sendMessage(chatId, 'Please enter the email you used during registration:');
      bot.once('message', async (msg) => {
        const email = msg.text.trim();
        if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
          bot.sendMessage(chatId, 'Invalid email. Try again with /start.');
          return;
        }

        const [existingUser] = await db.query('SELECT id, isVerified FROM Users WHERE email = ?', [email]);
        if (!existingUser.length) {
          bot.sendMessage(chatId, 'Email not found. Please register on the website.');
          return;
        }

        if (existingUser[0].isVerified) {
          bot.sendMessage(chatId, 'Your account is already verified.');
          return;
        }

        await db.query('UPDATE Users SET telegramId = ? WHERE email = ?', [chatId, email]);
        bot.sendMessage(chatId, 'Your email has been linked successfully. Awaiting document verification by admin.');
        logger.info(`Telegram ID ${chatId} linked to email: ${email}`);
      });
    }
  } catch (err) {
    logger.error(`Error processing /start: ${err.message}, stack: ${err.stack}`);
    bot.sendMessage(chatId, 'An error occurred. Please try again later.');
  }
});

// Handle /status command
bot.onText(/\/status/, async (msg) => {
  const chatId = msg.chat.id;
  logger.info(`Received /status command from Telegram ID: ${chatId}`);

  try {
    const [user] = await db.query('SELECT email, isVerified, isBlocked FROM Users WHERE telegramId = ?', [chatId]);
    if (!user.length) {
      bot.sendMessage(chatId, 'Your Telegram ID is not linked to an account. Use /start to link your email.');
      return;
    }

    if (user[0].isBlocked) {
      bot.sendMessage(chatId, 'Your account is blocked. Contact the administrator.');
      return;
    }

    const [apps] = await db.query('SELECT name, status FROM Apps WHERE userId = (SELECT id FROM Users WHERE telegramId = ?)', [chatId]);
    let response = `Account status (${user[0].email}): ${user[0].isVerified ? 'Verified' : 'Awaiting verification'}\n\n`;
    response += 'Your applications:\n';
    if (apps.length === 0) {
      response += 'You have no applications.';
    } else {
      apps.forEach(app => {
        response += `- ${app.name}: ${app.status}\n`;
      });
    }

    bot.sendMessage(chatId, response);
  } catch (err) {
    logger.error(`Error processing /status: ${err.message}, stack: ${err.stack}`);
    bot.sendMessage(chatId, 'An error occurred. Please try again later.');
  }
});

// Handle /help command
bot.onText(/\/help/, (msg) => {
  const chatId = msg.chat.id;
  logger.info(`Received /help command from Telegram ID: ${chatId}`);
  bot.sendMessage(chatId, `Available commands:\n/start - Link Telegram to account\n/status - Check account and app status\n/help - Show this message`);
});

// Server initialization
async function initializeServer() {
  try {
    await initializeDatabase();
    await checkS3Connection();
    app.listen(PORT, () => {
      logger.info(`Server running on port ${PORT}`);
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

// Get specific app by ID (new route to fix 404 error)
app.get('/api/apps/:id', authenticateToken, async (req, res) => {
  const { id } = req.params;
  try {
    const [app] = await db.query(`
      SELECT id, name, description, category, iconPath AS iconUrl, apkPath AS apkUrl, status, createdAt
      FROM Apps
      WHERE id = ? AND userId = ?
    `, [id, req.user.id]);

    if (!app.length) {
      logger.warn(`Application not found for ID: ${id}, user: ${req.user.email}`);
      return res.status(404).json({ message: 'Application not found' });
    }

    logger.info(`Fetched application ID: ${id} for user: ${req.user.email}`);
    res.json(app[0]);
  } catch (err) {
    logger.error(`Error fetching application ID: ${id}: ${err.message}, stack: ${err.stack}`);
    res.status(500).json({ message: 'Server error', error: err.message });
  }
});

// User pre-registration
app.post(
  '/api/pre-register',
  [body('email').isEmail().normalizeEmail().withMessage('Valid email required')],
  async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      logger.warn(`Validation errors: ${JSON.stringify(errors.array())}`);
      return res.status(400).json({ message: 'Validation error', errors: errors.array() });
    }

    try {
      const { email } = req.body;
      const [existing] = await db.query('SELECT email FROM PreRegisters WHERE email = ?', [email]);
      if (existing.length > 0) {
        return res.status(400).json({ message: 'Email already in waiting list' });
      }

      await db.query('INSERT INTO PreRegisters (email) VALUES (?)', [email]);
      logger.info(`Pre-registration: ${email}`);

      await telegramQueue.add({
        chatId: '-1002311447135',
        text: `New pre-registration: ${email}`,
      });

      res.status(201).json({ message: `Thank you! Your email (${email}) has been added to the waiting list.` });
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
    body('email').isEmail().normalizeEmail().withMessage('Valid email required'),
    body('password').isLength({ min: 8 }).withMessage('Password must be at least 8 characters'),
    body('accountType').isIn(['individual', 'commercial']).withMessage('Invalid account type'),
    body('name').notEmpty().trim().withMessage('Name required'),
    body('phone').notEmpty().trim().withMessage('Phone number required'),
    body('telegramId').optional().matches(/^(@[A-Za-z0-9_]{5,}|[\d]+)$/).withMessage('Invalid Telegram ID format'),
  ],
  async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      logger.warn(`Validation errors: ${JSON.stringify(errors.array())}`);
      return res.status(400).json({ message: 'Validation error', errors: errors.array() });
    }

    try {
      const { email, password, accountType, name, phone, telegramId, addressStreet, addressCity, addressCountry, addressPostalCode } = req.body;

      const [existingUser] = await db.query('SELECT email FROM Users WHERE email = ?', [email]);
      if (existingUser.length > 0) {
        return res.status(400).json({ message: 'Email already registered' });
      }

      if (telegramId) {
        const [existingTelegram] = await db.query('SELECT telegramId FROM Users WHERE telegramId = ?', [telegramId]);
        if (existingTelegram.length > 0) {
          return res.status(400).json({ message: 'Telegram ID already in use' });
        }
      }

      if (!req.files || !req.files.documents || req.files.documents.length === 0) {
        logger.warn('No documents uploaded');
        return res.status(400).json({ message: 'At least one document required' });
      }

      const documentUrls = await Promise.all(req.files.documents.map(file =>
        Promise.race([
          uploadToS3(file, 'documents'),
          new Promise((_, reject) => setTimeout(() => reject(new Error('Document upload timeout')), 30000))
        ])
      ));

      const salt = await bcrypt.genSalt(10);
      const hashedPassword = await bcrypt.hash(password, salt);

      const [result] = await db.query(
        `INSERT INTO Users (
          email, password, accountType, name, phone, telegramId, addressStreet, addressCity, addressCountry, addressPostalCode,
          documents, isVerified
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
        [
          email, hashedPassword, accountType, name, phone, telegramId || null, addressStreet || null, addressCity || null, addressCountry || null,
          addressPostalCode || null, JSON.stringify(documentUrls), false
        ]
      );

      const authToken = jwt.sign({ id: result.insertId, email }, JWT_SECRET, { expiresIn: '7d' });
      await db.query('UPDATE Users SET jwtToken = ? WHERE id = ?', [authToken, result.insertId]);

      telegramQueue.add({
        chatId: '-1002311447135',
        text: `New documents for review from user ${email} (registration). Count: ${documentUrls.length}`,
      }, { attempts: 3, backoff: 5000 });

      if (telegramId) {
        telegramQueue.add({
          chatId: telegramId,
          text: `Welcome, ${name}! Your documents have been submitted for review. You will be notified after verification.`,
        }, { attempts: 3, backoff: 5000 });
      }

      logger.info(`User registered: ${email}, documents: ${JSON.stringify(documentUrls)}`);
      res.status(201).json({
        message: telegramId
          ? 'Registration successful. Your documents have been submitted for review.'
          : 'Registration successful. Please provide your Telegram ID in your profile or via the bot to receive notifications.',
        token: authToken,
        user: { id: result.insertId, email, accountType, name, phone, telegramId, isVerified: false },
      });
    } catch (error) {
      logger.error(`Registration error: ${error.message}, stack: ${error.stack}`);
      res.status(500).json({ message: 'Server error', error: error.message });
    }
  }
);

// User login
app.post(
  '/api/auth/login',
  [
    body('email').isEmail().normalizeEmail().withMessage('Valid email required'),
    body('password').notEmpty().withMessage('Password required'),
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

      if (user[0].isBlocked) {
        logger.warn(`Login attempt by blocked user: ${email}`);
        return res.status(403).json({ message: 'Your account is blocked' });
      }

      const isMatch = await bcrypt.compare(password, user[0].password);
      if (!isMatch) {
        logger.warn(`Incorrect password for email: ${email}`);
        return res.status(400).json({ message: 'Invalid email or password' });
      }

      const token = jwt.sign({ id: user[0].id, email: user[0].email }, JWT_SECRET, { expiresIn: '7d' });
      await db.query('UPDATE Users SET jwtToken = ? WHERE id = ?', [token, user[0].id]);

      logger.info(`User logged in: ${user[0].email}`);
      res.status(200).json({
        token,
        user: { id: user[0].id, email: user[0].email, accountType: user[0].accountType, name: user[0].name, phone: user[0].phone, telegramId: user[0].telegramId, isVerified: user[0].isVerified },
        message: user[0].isVerified ? 'Login successful' : 'Login successful, but account awaits document verification',
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
  [body('email').isEmail().normalizeEmail().withMessage('Valid email required')],
  async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      logger.warn(`Validation errors: ${JSON.stringify(errors.array())}`);
      return res.status(400).json({ message: 'Validation error', errors: errors.array() });
    }

    try {
      const { email } = req.body;
      const [user] = await db.query('SELECT id, email, telegramId FROM Users WHERE email = ?', [email]);
      if (!user.length) {
        logger.warn(`Password reset attempt for non-existent email: ${email}`);
        return res.status(404).json({ message: 'User with this email not found' });
      }

      const resetToken = jwt.sign({ email }, JWT_SECRET, { expiresIn: '1h' });
      await db.query(
        'UPDATE Users SET resetPasswordToken = ?, resetPasswordExpires = ? WHERE email = ?',
        [resetToken, new Date(Date.now() + 3600000), email]
      );

      if (user[0].telegramId) {
        telegramQueue.add({
          chatId: user[0].telegramId,
          text: `Password reset request. Follow the link: https://your-app-domain.com/reset-password/${resetToken}`,
        }, { attempts: 3, backoff: 5000 });
      }

      logger.info(`Password reset requested for ${user[0].email}`);
      res.status(200).json({ message: 'Password reset link sent to your Telegram if linked' });
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
        return res.status(400).json({ message: 'Invalid or expired token' });
      }

      const [user] = await db.query(
        'SELECT id, email FROM Users WHERE email = ? AND resetPasswordToken = ? AND resetPasswordExpires > NOW()',
        [decoded.email, token]
      );
      if (!user.length) {
        logger.warn(`Invalid or expired reset token for email: ${decoded.email}`);
        return res.status(400).json({ message: 'Invalid or expired token' });
      }

      const salt = await bcrypt.genSalt(10);
      const hashedPassword = await bcrypt.hash(password, salt);
      await db.query(
        'UPDATE Users SET password = ?, resetPasswordToken = NULL, resetPasswordExpires = NULL, jwtToken = NULL WHERE email = ?',
        [hashedPassword, decoded.email]
      );

      logger.info(`Password reset for ${user[0].email}`);
      res.status(200).json({ message: 'Password reset successfully' });
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
      'SELECT id, email, accountType, name, phone, telegramId, addressStreet, addressCity, addressCountry, addressPostalCode, documents, isVerified, createdAt FROM Users WHERE id = ?',
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
        if (!Array.isArray(documents)) documents = [documents];
      }
    } catch (parseError) {
      logger.error(`Error parsing documents for user ${user[0].email}: ${parseError.message}`);
      documents = [];
    }

    user[0].documents = documents;
    res.status(200).json(user[0]);
  } catch (error) {
    logger.error(`Error fetching profile: ${error.message}, stack: ${error.stack}`);
    res.status(500).json({ message: 'Server error', error: error.message });
  }
});

// Get user applications
app.get('/api/apps', authenticateToken, async (req, res) => {
  try {
    const [apps] = await db.query(`
      SELECT id, name, description, category, iconPath AS iconUrl, apkPath AS apkUrl, status, createdAt
      FROM Apps
      WHERE userId = ?
      ORDER BY createdAt DESC
    `, [req.user.id]);

    logger.info(`Fetched ${apps.length} applications for user ${req.user.email}`);
    res.json(apps);
  } catch (err) {
    logger.error(`Error fetching user apps: ${err.message}, stack: ${err.stack}`);
    res.status(500).json({ message: 'Server error', error: err.message });
  }
});

// Upload user documents
app.post(
  '/api/user/documents',
  authenticateToken,
  upload,
  async (req, res) => {
    try {
      const [user] = await db.query('SELECT id, email, documents, telegramId FROM Users WHERE id = ?', [req.user.id]);
      if (!user.length) {
        logger.warn(`User not found for ID: ${req.user.id}`);
        return res.status(404).json({ message: 'User not found' });
      }

      if (!req.files || !req.files.documents || req.files.documents.length === 0) {
        logger.warn('No documents uploaded');
        return res.status(400).json({ message: 'At least one document required' });
      }

      const newDocuments = await Promise.all(req.files.documents.map(file =>
        Promise.race([
          uploadToS3(file, 'documents'),
          new Promise((_, reject) => setTimeout(() => reject(new Error('Document upload timeout')), 30000))
        ])
      ));

      let currentDocuments = [];
      try {
        currentDocuments = user[0].documents ? JSON.parse(user[0].documents) : [];
        if (!Array.isArray(currentDocuments)) currentDocuments = [currentDocuments];
      } catch (parseError) {
        logger.error(`Error parsing current documents for user ${user[0].email}: ${parseError.message}`);
        currentDocuments = [];
      }

      const updatedDocuments = [...currentDocuments, ...newDocuments].slice(0, 3);
      await db.query('UPDATE Users SET documents = ?, isVerified = ? WHERE id = ?', [
        JSON.stringify(updatedDocuments), false, user[0].id
      ]);

      telegramQueue.add({
        chatId: '-1002311447135',
        text: `New documents for review from user ${user[0].email}. Count: ${newDocuments.length}`,
      }, { attempts: 3, backoff: 5000 });

      if (user[0].telegramId) {
        telegramQueue.add({
          chatId: user[0].telegramId,
          text: `Your new documents have been submitted for review. You will be notified after verification.`,
        }, { attempts: 3, backoff: 5000 });
      }

      logger.info(`Documents updated for user ${user[0].email}, new documents: ${JSON.stringify(updatedDocuments)}`);
      res.status(200).json({
        message: 'Documents uploaded successfully and awaiting admin review',
        documents: updatedDocuments
      });
    } catch (error) {
      logger.error(`Document upload error: ${error.message}, stack: ${error.stack}`);
      res.status(500).json({ message: 'Server error', error: error.message });
    }
  }
);

// Create application
app.post(
  '/api/apps/create',
  authenticateToken,
  upload,
  [
    body('name').notEmpty().trim().withMessage('Application name required'),
    body('description').notEmpty().trim().withMessage('Description required'),
    body('category').isIn(['games', 'productivity', 'education', 'entertainment']).withMessage('Invalid category'),
  ],
  async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      logger.warn(`Validation errors: ${JSON.stringify(errors.array())}`);
      return res.status(400).json({ message: 'Validation error', errors: errors.array() });
    }

    try {
      const [user] = await db.query('SELECT id, email, isVerified, telegramId FROM Users WHERE id = ?', [req.user.id]);
      if (!user.length) {
        logger.warn(`User not found for ID: ${req.user.id}`);
        return res.status(404).json({ message: 'User not found' });
      }

      if (!user[0].isVerified) {
        logger.warn(`Non-verified user: ${user[0].email}`);
        return res.status(403).json({ message: 'Account must be verified to submit applications' });
      }

      const { name, description, category } = req.body;
      const files = req.files;

      // Check for design-related suggestions in description
      if (containsDesignSuggestions(description)) {
        logger.warn(`Design suggestions detected in description for app: ${name}, user: ${user[0].email}`);
        if (user[0].telegramId) {
          telegramQueue.add({
            chatId: user[0].telegramId,
            text: `Your application "${name}" was rejected because its description contains design-related suggestions (e.g., UI, UX, color). Please revise and resubmit.`,
          }, { attempts: 3, backoff: 5000 });
        }
        return res.status(400).json({
          message: 'Description contains design-related suggestions. Please revise and resubmit.',
        });
      }

      if (!files || !files.icon || !files.icon[0]) {
        logger.warn('Icon file missing');
        return res.status(400).json({ message: 'Icon file required (PNG, JPG, JPEG, GIF, WebP)' });
      }
      if (!files.apk || !files.apk[0]) {
        logger.warn('Application file missing');
        return res.status(400).json({ message: 'Application file required (APK or AAB)' });
      }

      const [iconUrl, apkUrl] = await Promise.all([
        Promise.race([
          uploadToS3(files.icon[0], 'icons'),
          new Promise((_, reject) => setTimeout(() => reject(new Error('Icon upload timeout')), 30000))
        ]),
        Promise.race([
          uploadToS3(files.apk[0], 'apks'),
          new Promise((_, reject) => setTimeout(() => reject(new Error('Application upload timeout')), 30000))
        ])
      ]);

      const [result] = await db.query(
        `INSERT INTO Apps (
          name, description, category, iconPath, apkPath, userId, status
        ) VALUES (?, ?, ?, ?, ?, ?, ?)`,
        [name, description, category, iconUrl, apkUrl, user[0].id, 'pending']
      );

      logger.info(`Application created by user ${user[0].email}: ${name}`);

      telegramQueue.add({
        chatId: '-1002311447135',
        text: `New application submitted: ${name} by ${user[0].email}`,
      }, { attempts: 3, backoff: 5000 });

      res.status(201).json({
        message: 'Application submitted successfully',
        app: { id: result.insertId, name, description, category, iconPath: iconUrl, apkPath: apkUrl, userId: user[0].id, status: 'pending' },
      });
    } catch (error) {
      logger.error(`Application creation error: ${error.message}, stack: ${error.stack}`);
      res.status(500).json({ message: 'Server error', error: error.message });
    }
  }
);

// Update application (new route)
app.put(
  '/api/apps/:id',
  authenticateToken,
  upload,
  [
    body('name').notEmpty().trim().withMessage('Application name required'),
    body('description').notEmpty().trim().withMessage('Description required'),
    body('category').isIn(['games', 'productivity', 'education', 'entertainment']).withMessage('Invalid category'),
  ],
  async (req, res) => {
    const { id } = req.params;
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      logger.warn(`Validation errors: ${JSON.stringify(errors.array())}`);
      return res.status(400).json({ message: 'Validation error', errors: errors.array() });
    }

    try {
      const [user] = await db.query('SELECT id, email, isVerified, telegramId FROM Users WHERE id = ?', [req.user.id]);
      if (!user.length) {
        logger.warn(`User not found for ID: ${req.user.id}`);
        return res.status(404).json({ message: 'User not found' });
      }

      if (!user[0].isVerified) {
        logger.warn(`Non-verified user: ${user[0].email}`);
        return res.status(403).json({ message: 'Account must be verified to update applications' });
      }

      const [app] = await db.query('SELECT * FROM Apps WHERE id = ? AND userId = ?', [id, user[0].id]);
      if (!app.length) {
        logger.warn(`Application not found for ID: ${id}, user: ${user[0].email}`);
        return res.status(404).json({ message: 'Application not found' });
      }

      const { name, description, category } = req.body;
      const files = req.files;
      let iconUrl = app[0].iconPath;
      let apkUrl = app[0].apkPath;

      // Check for design-related suggestions in description
      if (containsDesignSuggestions(description)) {
        logger.warn(`Design suggestions detected in description for app ID: ${id}, user: ${user[0].email}`);
        
        // Delete files from S3
        if (app[0].iconPath) {
          const iconKey = app[0].iconPath.split('/').pop();
          if (iconKey) await deleteFromS3(`icons/${iconKey}`);
        }
        if (app[0].apkPath) {
          const apkKey = app[0].apkPath.split('/').pop();
          if (apkKey) await deleteFromS3(`apks/${apkKey}`);
        }

        // Delete app from database
        await db.query('DELETE FROM Apps WHERE id = ?', [id]);
        logger.info(`Application ID: ${id} deleted due to design suggestions`);

        // Notify user via Telegram
        if (user[0].telegramId) {
          telegramQueue.add({
            chatId: user[0].telegramId,
            text: `Your application "${app[0].name}" (ID: ${id}) was deleted because its updated description contains design-related suggestions (e.g., UI, UX, color). Please revise and resubmit.`,
          }, { attempts: 3, backoff: 5000 });
        }

        return res.status(400).json({
          message: 'Description contains design-related suggestions. Application deleted. Please revise and resubmit.',
        });
      }

      // Handle file uploads if provided
      if (files && files.icon && files.icon[0]) {
        if (app[0].iconPath) {
          const oldIconKey = app[0].iconPath.split('/').pop();
          if (oldIconKey) await deleteFromS3(`icons/${oldIconKey}`);
        }
        iconUrl = await Promise.race([
          uploadToS3(files.icon[0], 'icons'),
          new Promise((_, reject) => setTimeout(() => reject(new Error('Icon upload timeout')), 30000))
        ]);
      }

      if (files && files.apk && files.apk[0]) {
        if (app[0].apkPath) {
          const oldApkKey = app[0].apkPath.split('/').pop();
          if (oldApkKey) await deleteFromS3(`apks/${oldApkKey}`);
        }
        apkUrl = await Promise.race([
          uploadToS3(files.apk[0], 'apks'),
          new Promise((_, reject) => setTimeout(() => reject(new Error('Application upload timeout')), 30000))
        ]);
      }

      await db.query(
        `UPDATE Apps SET name = ?, description = ?, category = ?, iconPath = ?, apkPath = ?, status = 'pending' WHERE id = ?`,
        [name, description, category, iconUrl, apkUrl, id]
      );

      logger.info(`Application ID: ${id} updated by user ${user[0].email}`);

      telegramQueue.add({
        chatId: '-1002311447135',
        text: `Application updated: ${name} (ID: ${id}) by ${user[0].email}`,
      }, { attempts: 3, backoff: 5000 });

      if (user[0].telegramId) {
        telegramQueue.add({
          chatId: user[0].telegramId,
          text: `Your application "${name}" (ID: ${id}) has been updated and is pending review.`,
        }, { attempts: 3, backoff: 5000 });
      }

      res.status(200).json({
        message: 'Application updated successfully',
        app: { id, name, description, category, iconPath: iconUrl, apkPath: apkUrl, userId: user[0].id, status: 'pending' },
      });
    } catch (error) {
      logger.error(`Application update error for ID: ${id}: ${error.message}, stack: ${error.stack}`);
      res.status(500).json({ message: 'Server error', error: error.message });
    }
  }
);

// Admin routes
// Get all applications
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
    logger.error(`Error fetching admin apps: ${err.message}, stack: ${err.stack}`);
    res.status(500).json({ message: 'Server error', error: err.message });
  }
});

// Update application status
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
      return res.status(404).json({ message: 'Application not found' });
    }

    await db.query('UPDATE Apps SET status = ? WHERE id = ?', [status, id]);
    logger.info(`Application ${id} status updated to ${status}`);

    if (status !== 'pending') {
      const [appUser] = await db.query('SELECT email, telegramId FROM Users WHERE id = ?', [app[0].userId]);
      if (appUser[0].telegramId) {
        telegramQueue.add({
          chatId: appUser[0].telegramId,
          text: `Application ${app[0].name} status updated to ${status} for user ${appUser[0].email}`,
        }, { attempts: 3, backoff: 5000 });
      }
    }

    res.json({ message: `Application status updated to ${status}` });
  } catch (err) {
    logger.error(`Error updating application: ${err.message}, stack: ${err.stack}`);
    res.status(500).json({ message: 'Server error', error: err.message });
  }
});

// Delete application
app.delete('/api/admin/apps/:id', authenticateToken, async (req, res) => {
  const { id } = req.params;

  try {
    const [user] = await db.query('SELECT email, accountType FROM Users WHERE id = ?', [req.user.id]);
    if (!user.length || user[0].email !== 'admin@24webstudio.ru') {
      return res.status(403).json({ message: 'Admin access required' });
    }

    const [app] = await db.query('SELECT iconPath, apkPath FROM Apps WHERE id = ?', [id]);
    if (!app.length) {
      return res.status(404).json({ message: 'Application not found' });
    }

    if (app[0].iconPath) {
      const iconKey = app[0].iconPath.split('/').pop();
      if (iconKey) await deleteFromS3(`icons/${iconKey}`);
    }
    if (app[0].apkPath) {
      const apkKey = app[0].apkPath.split('/').pop();
      if (apkKey) await deleteFromS3(`apks/${apkKey}`);
    }

    await db.query('DELETE FROM Apps WHERE id = ?', [id]);
    logger.info(`Application ${id} deleted`);

    res.json({ message: 'Application deleted' });
  } catch (err) {
    logger.error(`Error deleting application: ${err.message}, stack: ${err.stack}`);
    res.status(500).json({ message: 'Server error', error: err.message });
  }
});

// Get user documents for admin
app.get('/api/admin/users/documents', authenticateToken, async (req, res) => {
  try {
    const [user] = await db.query('SELECT email, accountType FROM Users WHERE id = ?', [req.user.id]);
    if (!user.length || user[0].email !== 'admin@24webstudio.ru') {
      return res.status(403).json({ message: 'Admin access required' });
    }

    const [users] = await db.query(`
      SELECT id, email, name, accountType, telegramId, documents, isVerified, createdAt
      FROM Users
      WHERE documents IS NOT NULL
      ORDER BY createdAt DESC
    `);

    const usersWithDocuments = users.map(u => {
      let documents = [];
      try {
        documents = u.documents ? JSON.parse(u.documents) : [];
        if (!Array.isArray(documents)) documents = [documents];
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

// Verify user
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

    const [user] = await db.query('SELECT email, telegramId, name FROM Users WHERE id = ?', [id]);
    if (!user.length) {
      return res.status(404).json({ message: 'User not found' });
    }

    await db.query('UPDATE Users SET isVerified = ? WHERE id = ?', [isVerified, id]);
    logger.info(`Verification status for user ${user[0].email} updated to ${isVerified}`);

    if (user[0].telegramId) {
      telegramQueue.add({
        chatId: user[0].telegramId,
        text: isVerified
          ? `Congratulations, ${user[0].name}! Your account has been verified.`
          : `Dear ${user[0].name}, your account verification was not approved. Please upload valid documents.`,
      }, { attempts: 3, backoff: 5000 });
    }

    res.json({ message: `Verification status updated to ${isVerified ? 'verified' : 'not verified'}` });
  } catch (err) {
    logger.error(`Error verifying user: ${err.message}, stack: ${err.stack}`);
    res.status(500).json({ message: 'Server error', error: err.message });
  }
});

// Get advertisements
app.get('/api/admin/advertisements', authenticateToken, async (req, res) => {
  try {
    const [user] = await db.query('SELECT email, accountType FROM Users WHERE id = ?', [req.user.id]);
    if (!user.length || user[0].email !== 'admin@24webstudio.ru') {
      return res.status(403).json({ message: 'Admin access required' });
    }

    const [ads] = await db.query(`
      SELECT a.*, u.email as userEmail, u.name as userName
      FROM Advertisements a
      JOIN Users u ON a.userId = u.id
      ORDER BY a.createdAt DESC
    `);
    res.json(ads);
  } catch (err) {
    logger.error(`Error fetching advertisements: ${err.message}, stack: ${err.stack}`);
    res.status(500).json({ message: 'Server error', error: err.message });
  }
});

// Block/unblock user
app.put('/api/admin/users/:id/block', authenticateToken, async (req, res) => {
  const { id } = req.params;
  const { isBlocked } = req.body;

  try {
    const [admin] = await db.query('SELECT email, accountType FROM Users WHERE id = ?', [req.user.id]);
    if (!admin.length || admin[0].email !== 'admin@24webstudio.ru') {
      return res.status(403).json({ message: 'Admin access required' });
    }

    if (typeof isBlocked !== 'boolean') {
      return res.status(400).json({ message: 'Invalid block status' });
    }

    const [user] = await db.query('SELECT email, telegramId FROM Users WHERE id = ?', [id]);
    if (!user.length) {
      return res.status(404).json({ message: 'User not found' });
    }

    await db.query('UPDATE Users SET isBlocked = ? WHERE id = ?', [isBlocked, id]);
    logger.info(`Block status for user ${user[0].email} updated to ${isBlocked}`);

    if (user[0].telegramId) {
      telegramQueue.add({
        chatId: user[0].telegramId,
        text: isBlocked
          ? 'Your account has been blocked. Contact the administrator.'
          : 'Your account has been unblocked.',
      }, { attempts: 3, backoff: 5000 });
    }

    res.json({ message: `User ${isBlocked ? 'blocked' : 'unblocked'}` });
  } catch (err) {
    logger.error(`Error blocking user: ${err.message}, stack: ${err.stack}`);
    res.status(500).json({ message: 'Server error', error: err.message });
  }
});

// Mass notification
app.post('/api/admin/notify-all', authenticateToken, async (req, res) => {
  const { message } = req.body;

  try {
    const [admin] = await db.query('SELECT email, accountType FROM Users WHERE id = ?', [req.user.id]);
    if (!admin.length || admin[0].email !== 'admin@24webstudio.ru') {
      return res.status(403).json({ message: 'Admin access required' });
    }

    if (!message || typeof message !== 'string') {
      return res.status(400).json({ message: 'Message text required' });
    }

    const [users] = await db.query('SELECT telegramId, email FROM Users WHERE telegramId IS NOT NULL AND isBlocked = FALSE');
    let successCount = 0;
    let errorCount = 0;

    for (const user of users) {
      try {
        await telegramQueue.add({
          chatId: user.telegramId,
          text: message,
        }, { attempts: 3, backoff: 5000 });
        successCount++;
      } catch (err) {
        errorCount++;
        logger.error(`Error sending notification to user ${user.email}: ${err.message}`);
      }
    }

    logger.info(`Mass notification completed: ${successCount} successful, ${errorCount} errors`);
    res.status(200).json({
      message: `Notifications scheduled for ${successCount} users`,
      successCount,
      errorCount
    });
  } catch (err) {
    logger.error(`Mass notification error: ${err.message}, stack: ${err.stack}`);
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
  if (err.message.includes('Only allowed') || err.message.includes('upload timeout')) {
    logger.warn(`File type or timeout error: ${err.message}`);
    return res.status(400).json({ message: err.message });
  }
  res.status(500).json({ message: 'Server error', error: err.message });
});

// Graceful shutdown
async function shutdown() {
  logger.info('Performing graceful shutdown...');
  try {
    await telegramQueue.close();
    await db.end();
    logger.info('Database and queue connections closed');
  } catch (err) {
    logger.error(`Shutdown error: ${err.message}`);
  }
  process.exit(0);
}

process.on('SIGINT', shutdown);
process.on('SIGTERM', shutdown);

// Start server
initializeServer();