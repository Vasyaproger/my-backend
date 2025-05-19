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
const admin = require('firebase-admin'); // Firebase Admin SDK
const axios = require('axios');

const app = express();

// Configuration
const JWT_SECRET = 'x7b9k3m8p2q5w4z6t1r0y9u2j4n6l8h3';
const DB_HOST = 'vh438.timeweb.ru'; // Corrected host
const DB_USER = 'ch79145_project';
const DB_PASSWORD = 'Vasya11091109';
const DB_NAME = 'ch79145_project';
const S3_ACCESS_KEY = 'DN1NLZTORA2L6NZ529JJ';
const S3_SECRET_KEY = 'iGg3syd3UiWzhoYbYlEEDSVX1HHVmWUptrBt81Y8';
const CORS_ORIGIN = 'https://24webstudio.ru';
const PORT = 5000;
const BUCKET_NAME = '4eeafbc6-4af2cd44-4c23-4530-a2bf-750889dfdf75';
const TELEGRAM_BOT_TOKEN = process.env.TELEGRAM_BOT_TOKEN || ''; // Optional: Set in environment

// Validate required variables
const requiredEnvVars = ['JWT_SECRET', 'DB_HOST', 'DB_USER', 'DB_PASSWORD', 'DB_NAME', 'S3_ACCESS_KEY', 'S3_SECRET_KEY'];
for (const envVar of requiredEnvVars) {
  const value = eval(envVar);
  if (!value || value === `YOUR_${envVar}`) {
    console.error(`Error: ${envVar} is not set or has default value`);
    process.exit(1);
  }
}

// Logger
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



// S3 Client
const s3Client = new S3Client({
  endpoint: 'https://s3.twcstorage.ru',
  credentials: {
    accessKeyId: S3_ACCESS_KEY,
    secretAccessKey: S3_SECRET_KEY,
  },
  region: 'ru-1',
  forcePathStyle: true,
});

// Test S3 Connection
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
  origin: CORS_ORIGIN,
  methods: ['GET', 'POST', 'PUT', 'DELETE'],
  allowedHeaders: ['Content-Type', 'Authorization'],
}));
app.use(express.json());

// MySQL Connection Pool
const db = mysql.createPool({
  host: DB_HOST,
  user: DB_USER,
  password: DB_PASSWORD,
  database: DB_NAME,
  port: 3306,
  connectionLimit: 10,
  connectTimeout: 30000,
});

// Multer Configuration
const upload = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: 10 * 1024 * 1024 }, // 10MB limit
  fileFilter: (req, file, cb) => {
    if (file.fieldname === 'documents') {
      const validMimeTypes = ['application/pdf', 'image/jpeg', 'image/png', 'image/jpg'];
      const validExtensions = /\.(pdf|jpg|jpeg|png)$/i;
      const extname = validExtensions.test(path.extname(file.originalname).toLowerCase());
      const mimetype = validMimeTypes.includes(file.mimetype);
      if (extname && mimetype) {
        return cb(null, true);
      }
      logger.warn(`Invalid document: name=${file.originalname}, MIME=${file.mimetype}`);
      cb(new Error('Only PDF, JPG, JPEG, and PNG files are allowed for documents!'));
    } else if (file.fieldname === 'icon') {
      const validMimeTypes = ['image/jpeg', 'image/png', 'image/jpg'];
      const validExtensions = /\.(jpg|jpeg|png)$/i;
      const extname = validExtensions.test(path.extname(file.originalname).toLowerCase());
      const mimetype = validMimeTypes.includes(file.mimetype);
      if (extname && mimetype) {
        return cb(null, true);
      }
      logger.warn(`Invalid icon: name=${file.originalname}, MIME=${file.mimetype}`);
      cb(new Error('Only JPG, JPEG, and PNG files are allowed for icons!'));
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
        logger.info(`APK accepted: name=${file.originalname}, MIME=${file.mimetype}`);
        return cb(null, true);
      }
      logger.warn(`Invalid APK: name=${file.originalname}, MIME=${file.mimetype}`);
      cb(new Error('Only APK files are allowed!'));
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

// S3 Upload Function
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
    logger.info(`File uploaded to S3: ${key}`);
    return location;
  } catch (error) {
    logger.error(`S3 upload error for ${key}: ${error.message}, stack: ${error.stack}`);
    throw new Error(`S3 upload error: ${error.message}`);
  }
}

// S3 Delete Function
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

// S3 Get Function
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

// JWT Authentication Middleware
const authenticateToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];
  if (!token) {
    logger.warn('Authorization token missing');
    return res.status(401).json({ message: 'Authorization token required' });
  }
  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    req.user = decoded;
    next();
  } catch (error) {
    logger.error(`Invalid token: ${error.message}, stack: ${error.stack}`);
    return res.status(403).json({ message: 'Invalid or expired token' });
  }
};

// Optional Authentication Middleware
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

// Database Schema Initialization
async function initializeDatabase() {
  try {
    const connection = await db.getConnection();
    logger.info('Connected to MySQL');

    // Create Users table
    await connection.query(`
      CREATE TABLE IF NOT EXISTS Users (
        id INT AUTO_INCREMENT PRIMARY KEY,
        email VARCHAR(255) NOT NULL UNIQUE,
        password VARCHAR(255) NOT NULL,
        accountType ENUM('individual', 'commercial') NOT NULL,
        name VARCHAR(255) NOT NULL,
        phone VARCHAR(20) NOT NULL,
        addressStreet VARCHAR(255),
        addressCity VARCHAR(255),
        addressCountry VARCHAR(255),
        addressPostalCode VARCHAR(20),
        documents JSON,
        isVerified BOOLEAN DEFAULT FALSE,
        jwtToken VARCHAR(500),
        resetPasswordToken VARCHAR(500),
        resetPasswordExpires DATETIME,
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

    // Create default admin user
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

// Initialize Server
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

// Routes

// Public Routes
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
    res.status(500).json({ error: 'Server error: ' + err.message });
  }
});

app.get('/api/public/app-image/:key', optionalAuthenticateToken, async (req, res) => {
  const { key } = req.params;
  try {
    const image = await getFromS3(`icons/${key}`);
    res.setHeader('Content-Type', image.ContentType || 'image/jpeg');
    image.Body.pipe(res);
  } catch (err) {
    logger.error(`Error fetching image: ${err.message}, stack: ${err.stack}`);
    res.status(500).json({ error: 'Error fetching image: ' + err.message });
  }
});

// Pre-registration
app.post(
  '/api/pre-register',
  [
    body('email').isEmail().normalizeEmail().withMessage('Valid email required'),
  ],
  async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      logger.warn(`Validation errors: ${JSON.stringify(errors.array())}`);
      return res.status(400).json({ message: 'Validation error', errors: errors.array() });
    }

    try {
      const { email } = req.body;
      const [existing] = await db.query('SELECT email FROM PreRegisters WHERE email = ?', [email]);
      if (existing) {
        return res.status(400).json({ message: 'Email already in waitlist' });
      }

      await db.query('INSERT INTO PreRegisters (email) VALUES (?)', [email]);
      logger.info(`Pre-registration: ${email}`);

      // Optional: Send Telegram notification
      if (TELEGRAM_BOT_TOKEN) {
        try {
          await axios.post(
            `https://api.telegram.org/bot${TELEGRAM_BOT_TOKEN}/sendMessage`,
            {
              chat_id: '-1002311447135', // Replace with your chat ID
              text: `New pre-registration: ${email}`,
              parse_mode: 'Markdown',
            }
          );
          logger.info(`Telegram notification sent for ${email}`);
        } catch (telegramErr) {
          logger.error(`Telegram notification error: ${telegramErr.message}`);
        }
      }

      res.status(201).json({ message: `Thank you! Your email (${email}) has been added to the waitlist.` });
    } catch (error) {
      logger.error(`Pre-registration error: ${error.message}, stack: ${error.stack}`);
      res.status(500).json({ message: 'Server error', error: error.message });
    }
  }
);

// User Registration
app.post(
  '/api/auth/register',
  upload,
  [
    body('email').isEmail().normalizeEmail().withMessage('Valid email required'),
    body('password').isLength({ min: 8 }).withMessage('Password must be at least 8 characters'),
    body('accountType').isIn(['individual', 'commercial']).withMessage('Invalid account type'),
    body('name').notEmpty().trim().withMessage('Name required'),
    body('phone').notEmpty().trim().withMessage('Phone number required'),
  ],
  async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      logger.warn(`Validation errors: ${JSON.stringify(errors.array())}`);
      return res.status(400).json({ message: 'Validation error', errors: errors.array() });
    }

    try {
      const { email, password, accountType, name, phone, addressStreet, addressCity, addressCountry, addressPostalCode } = req.body;
      if (!req.files || !req.files.documents || req.files.documents.length === 0) {
        logger.warn('Documents not uploaded');
        return res.status(400).json({ message: 'At least one document is required' });
      }

      const [existingUser] = await db.query('SELECT email FROM Users WHERE email = ?', [email]);
      if (existingUser) {
        return res.status(400).json({ message: 'Email already registered' });
      }

      const documentUrls = await Promise.all(req.files.documents.map(file => uploadToS3(file, 'documents')));
      const salt = await bcrypt.genSalt(10);
      const hashedPassword = await bcrypt.hash(password, salt);
      const authToken = jwt.sign({ email, accountType, name }, JWT_SECRET, { expiresIn: '7d' });

      const [result] = await db.query(
        `INSERT INTO Users (
          email, password, accountType, name, phone, addressStreet, addressCity, addressCountry, addressPostalCode,
          documents, isVerified, jwtToken
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
        [
          email, hashedPassword, accountType, name, phone, addressStreet || null, addressCity || null, addressCountry || null,
          addressPostalCode || null, JSON.stringify(documentUrls), true, authToken,
        ]
      );

      logger.info(`User registered: ${email}`);
      res.status(201).json({
        message: 'Registration successful',
        token: authToken,
        user: { id: result.insertId, email, accountType, name, phone },
      });
    } catch (error) {
      logger.error(`Registration error: ${error.message}, stack: ${error.stack}`);
      res.status(500).json({ message: 'Server error', error: error.message });
    }
  }
);

// User Login
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
      if (!user) {
        logger.warn(`Login attempt with non-existent email: ${email}`);
        return res.status(400).json({ message: 'Invalid email or password' });
      }

      const isMatch = await bcrypt.compare(password, user.password);
      if (!isMatch) {
        logger.warn(`Incorrect password for email: ${email}`);
        return res.status(400).json({ message: 'Invalid email or password' });
      }

      let token = user.jwtToken;
      if (!token) {
        token = jwt.sign({ id: user.id, email: user.email }, JWT_SECRET, { expiresIn: '7d' });
        await db.query('UPDATE Users SET jwtToken = ? WHERE id = ?', [token, user.id]);
      }

      logger.info(`User logged in: ${user.email}`);
      res.status(200).json({
        token,
        user: { id: user.id, email: user.email, accountType: user.accountType, name: user.name, phone: user.phone },
        message: 'Login successful',
      });
    } catch (error) {
      logger.error(`Login error: ${error.message}, stack: ${error.stack}`);
      res.status(500).json({ message: 'Server error', error: error.message });
    }
  }
);

// Forgot Password
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
      const [user] = await db.query('SELECT id, email FROM Users WHERE email = ?', [email]);
      if (!user) {
        logger.warn(`Password reset attempt for non-existent email: ${email}`);
        return res.status(404).json({ message: 'User with this email not found' });
      }

      const resetToken = jwt.sign({ email }, JWT_SECRET, { expiresIn: '1h' });
      await db.query(
        'UPDATE Users SET resetPasswordToken = ?, resetPasswordExpires = ? WHERE email = ?',
        [resetToken, new Date(Date.now() + 3600000), email]
      );

      logger.info(`Password reset requested for ${user.email}`);
      // Optional: Implement email sending logic here
      res.status(200).json({ message: 'Password reset link sent (implement email sending)' });
    } catch (error) {
      logger.error(`Password reset error: ${error.message}, stack: ${error.stack}`);
      res.status(500).json({ message: 'Server error', error: error.message });
    }
  }
);

// Reset Password
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
      if (!user) {
        logger.warn(`Invalid or expired reset token for email: ${decoded.email}`);
        return res.status(400).json({ message: 'Invalid or expired token' });
      }

      const salt = await bcrypt.genSalt(10);
      const hashedPassword = await bcrypt.hash(password, salt);
      await db.query(
        'UPDATE Users SET password = ?, resetPasswordToken = NULL, resetPasswordExpires = NULL, jwtToken = NULL WHERE email = ?',
        [hashedPassword, decoded.email]
      );

      logger.info(`Password reset for ${user.email}`);
      res.status(200).json({ message: 'Password reset successful' });
    } catch (error) {
      logger.error(`Password reset error: ${error.message}, stack: ${error.stack}`);
      res.status(500).json({ message: 'Server error', error: error.message });
    }
  }
);

// User Profile
app.get('/api/user/profile', authenticateToken, async (req, res) => {
  try {
    const [user] = await db.query(
      'SELECT id, email, accountType, name, phone, addressStreet, addressCity, addressCountry, addressPostalCode, documents, isVerified, createdAt FROM Users WHERE id = ?',
      [req.user.id]
    );
    if (!user) {
      logger.warn(`User not found for ID: ${req.user.id}`);
      return res.status(404).json({ message: 'User not found' });
    }
    user.documents = JSON.parse(user.documents || '[]');
    res.status(200).json(user);
  } catch (error) {
    logger.error(`Profile fetch error: ${error.message}, stack: ${error.stack}`);
    res.status(500).json({ message: 'Server error', error: error.message });
  }
});

// Update Documents
app.post(
  '/api/user/documents',
  authenticateToken,
  upload,
  async (req, res) => {
    try {
      const [user] = await db.query('SELECT id, email, documents FROM Users WHERE id = ?', [req.user.id]);
      if (!user) {
        logger.warn(`User not found for ID: ${req.user.id}`);
        return res.status(404).json({ message: 'User not found' });
      }

      if (!req.files || !req.files.documents || req.files.documents.length === 0) {
        logger.warn('Documents not uploaded');
        return res.status(400).json({ message: 'At least one document is required' });
      }

      const newDocuments = await Promise.all(req.files.documents.map(file => uploadToS3(file, 'documents')));
      const currentDocuments = JSON.parse(user.documents || '[]');
      const updatedDocuments = [...currentDocuments, ...newDocuments].slice(0, 3);
      await db.query('UPDATE Users SET documents = ?, isVerified = ? WHERE id = ?', [
        JSON.stringify(updatedDocuments), true, user.id
      ]);

      logger.info(`Documents updated for user ${user.email}`);
      res.status(200).json({ message: 'Documents updated successfully', documents: updatedDocuments });
    } catch (error) {
      logger.error(`Document update error: ${error.message}, stack: ${error.stack}`);
      res.status(500).json({ message: 'Server error', error: error.message });
    }
  }
);

// Create App
app.post(
  '/api/apps/create',
  authenticateToken,
  upload,
  [
    body('name').notEmpty().trim().withMessage('App name required'),
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
      const [user] = await db.query('SELECT id, email, isVerified FROM Users WHERE id = ?', [req.user.id]);
      if (!user) {
        logger.warn(`User not found for ID: ${req.user.id}`);
        return res.status(404).json({ message: 'User not found' });
      }

      if (!user.isVerified) {
        logger.warn(`User not verified: ${user.email}`);
        return res.status(403).json({ message: 'Account must be verified to submit apps' });
      }

      const { name, description, category } = req.body;
      const files = req.files;

      if (!files || !files.icon || !files.icon[0]) {
        logger.warn('Icon file missing');
        return res.status(400).json({ message: 'Icon file required (JPG, JPEG, or PNG)' });
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
        [name, description, category, iconUrl, apkUrl, user.id, 'pending']
      );

      logger.info(`App created by user ${user.email}: ${name}`);

      // Optional: Send Telegram notification
      if (TELEGRAM_BOT_TOKEN) {
        try {
          await axios.post(
            `https://api.telegram.org/bot${TELEGRAM_BOT_TOKEN}/sendMessage`,
            {
              chat_id: '-1002311447135', // Replace with your chat ID
              text: `New app submitted: ${name} by ${user.email}`,
              parse_mode: 'Markdown',
            }
          );
          logger.info(`Telegram notification sent for app ${name}`);
        } catch (telegramErr) {
          logger.error(`Telegram notification error: ${telegramErr.message}`);
        }
      }

      res.status(201).json({
        message: 'App submitted successfully',
        app: { id: result.insertId, name, description, category, iconPath: iconUrl, apkPath: apkUrl, userId: user.id, status: 'pending' },
      });
    } catch (error) {
      logger.error(`App creation error: ${error.message}, stack: ${error.stack}`);
      res.status(500).json({ message: 'Server error', error: error.message });
    }
  }
);

// Admin Routes (assuming admin is identified by email or accountType)
app.get('/api/admin/apps', authenticateToken, async (req, res) => {
  try {
    const [user] = await db.query('SELECT email, accountType FROM Users WHERE id = ?', [req.user.id]);
    if (!user || user.email !== 'admin@24webstudio.ru') {
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
    res.status(500).json({ error: 'Server error: ' + err.message });
  }
});

app.put('/api/admin/apps/:id', authenticateToken, async (req, res) => {
  const { id } = req.params;
  const { status } = req.body;

  try {
    const [user] = await db.query('SELECT email, accountType FROM Users WHERE id = ?', [req.user.id]);
    if (!user || user.email !== 'admin@24webstudio.ru') {
      return res.status(403).json({ message: 'Admin access required' });
    }

    if (!['pending', 'approved', 'rejected'].includes(status)) {
      return res.status(400).json({ message: 'Invalid status' });
    }

    const [app] = await db.query('SELECT * FROM Apps WHERE id = ?', [id]);
    if (!app) {
      return res.status(404).json({ message: 'App not found' });
    }

    await db.query('UPDATE Apps SET status = ? WHERE id = ?', [status, id]);
    logger.info(`App ${id} status updated to ${status}`);

    // Optional: Notify user via Firebase or Telegram
    if (status !== 'pending') {
      const [appUser] = await db.query('SELECT email FROM Users WHERE id = ?', [app.userId]);
      if (TELEGRAM_BOT_TOKEN) {
        try {
          await axios.post(
            `https://api.telegram.org/bot${TELEGRAM_BOT_TOKEN}/sendMessage`,
            {
              chat_id: '-1002311447135', // Replace with your chat ID
              text: `App ${app.name} status updated to ${status} for user ${appUser.email}`,
              parse_mode: 'Markdown',
            }
          );
          logger.info(`Telegram notification sent for app ${app.name}`);
        } catch (telegramErr) {
          logger.error(`Telegram notification error: ${telegramErr.message}`);
        }
      }
    }

    res.json({ message: `App status updated to ${status}` });
  } catch (err) {
    logger.error(`Error updating app: ${err.message}, stack: ${err.stack}`);
    res.status(500).json({ error: 'Server error: ' + err.message });
  }
});

app.delete('/api/admin/apps/:id', authenticateToken, async (req, res) => {
  const { id } = req.params;

  try {
    const [user] = await db.query('SELECT email, accountType FROM Users WHERE id = ?', [req.user.id]);
    if (!user || user.email !== 'admin@24webstudio.ru') {
      return res.status(403).json({ message: 'Admin access required' });
    }

    const [app] = await db.query('SELECT iconPath, apkPath FROM Apps WHERE id = ?', [id]);
    if (!app) {
      return res.status(404).json({ message: 'App not found' });
    }

    if (app.iconPath) await deleteFromS3(app.iconPath.split('/').pop());
    if (app.apkPath) await deleteFromS3(app.apkPath.split('/').pop());

    await db.query('DELETE FROM Apps WHERE id = ?', [id]);
    logger.info(`App ${id} deleted`);

    res.json({ message: 'App deleted' });
  } catch (err) {
    logger.error(`Error deleting app: ${err.message}, stack: ${err.stack}`);
    res.status(500).json({ error: 'Server error: ' + err.message });
  }
});

// Error Handling
app.use((err, req, res, next) => {
  logger.error(`Unhandled error: ${err.message}, stack: ${err.stack}`);
  if (err instanceof multer.MulterError) {
    logger.warn(`Multer error: ${err.message}`);
    return res.status(400).json({ message: `File upload error: ${err.message}` });
  }
  if (err.message.includes('Разрешены только')) {
    logger.warn(`File type error: ${err.message}`);
    return res.status(400).json({ message: err.message });
  }
  res.status(500).json({ message: 'Server error', error: err.message });
});

// Graceful Shutdown
async function shutdown() {
  logger.info('Performing graceful shutdown...');
  await db.end();
  logger.info('Database connection closed');
  process.exit(0);
}

process.on('SIGINT', shutdown);
process.on('SIGTERM', shutdown);

// Start Server
initializeServer();