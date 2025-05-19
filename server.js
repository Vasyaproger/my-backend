const express = require('express');
const { Sequelize, DataTypes } = require('sequelize');
const mysql = require('mysql'); // Замена mysql2 на mysql
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const TelegramBot = require('node-telegram-bot-api');
const multer = require('multer');
const path = require('path');
const cors = require('cors');
const helmet = require('helmet');
const { body, validationResult } = require('express-validator');
const winston = require('winston');
const AWS = require('aws-sdk');

const app = express();

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

// AWS S3 setup
const s3 = new AWS.S3({
  endpoint: 'https://s3.twcstorage.ru',
  accessKeyId: 'DN1NLZTORA2L6NZ529JJ',
  secretAccessKey: 'iGg3syd3UiWzhoYbYlEEDSVX1HHVmWUptrBt81Y8',
  region: 'ru-1',
  s3ForcePathStyle: true,
  httpOptions: { timeout: 30000 },
});

const BUCKET_NAME = '4eeafbc6-4af2cd44-4c23-4530-a2bf-750889dfdf75';

// Check S3 connection
s3.listBuckets((err) => {
  if (err) {
    logger.error(`Failed to connect to S3: ${err.message}`);
  } else {
    logger.info('S3 connection successful');
  }
});

// Middleware
app.use(helmet());
app.use(cors({
  origin: '*',
  methods: ['GET', 'POST', 'PUT', 'DELETE'],
  allowedHeaders: ['Content-Type', 'Authorization'],
}));
app.use(express.json());

// Database connection
const sequelize = new Sequelize({
  dialect: 'mysql',
  host: 'vh438.timeweb.ru',
  username: 'ch79145_project',
  password: 'Vasya11091109',
  database: 'ch79145_project',
  port: 3306,
  dialectModule: mysql, // Используем mysql вместо mysql2
  logging: (msg) => logger.debug(msg),
  pool: {
    max: 2, // Уменьшено до 2 для снижения нагрузки
    min: 0,
    acquire: 30000,
    idle: 10000,
  },
});

// Connection retry mechanism
async function connectWithRetry(maxRetries = 5, retryDelay = 20000) { // Интервал увеличен до 20 секунд
  for (let attempt = 1; attempt <= maxRetries; attempt++) {
    try {
      await sequelize.authenticate();
      logger.info('Database connection successful');
      return;
    } catch (error) {
      logger.error(`Connection attempt ${attempt} failed: ${error.message}`);
      if (error.message.includes('Host') && error.message.includes('blocked')) {
        logger.error('Host blocked by MySQL. Run "mysqladmin flush-hosts" on the server.');
      }
      if (attempt === maxRetries) {
        logger.error('Failed to connect to database after all attempts');
        throw new Error('Database connection failed');
      }
      await new Promise(resolve => setTimeout(resolve, retryDelay));
    }
  }
}

// User model
const User = sequelize.define('User', {
  email: {
    type: DataTypes.STRING,
    allowNull: false,
    unique: true,
    validate: { isEmail: true },
  },
  password: {
    type: DataTypes.STRING,
    allowNull: false,
  },
  accountType: {
    type: DataTypes.ENUM('individual', 'commercial'),
    allowNull: false,
  },
  name: {
    type: DataTypes.STRING,
    allowNull: false,
  },
  phone: {
    type: DataTypes.STRING,
    allowNull: false,
  },
  telegramId: {
    type: DataTypes.STRING,
    allowNull: false,
  },
  addressStreet: { type: DataTypes.STRING },
  addressCity: { type: DataTypes.STRING },
  addressCountry: { type: DataTypes.STRING },
  addressPostalCode: { type: DataTypes.STRING },
  documents: {
    type: DataTypes.JSON,
    allowNull: false,
    defaultValue: [],
  },
  isVerified: {
    type: DataTypes.BOOLEAN,
    defaultValue: false,
  },
  verificationToken: { type: DataTypes.STRING },
  resetPasswordToken: { type: DataTypes.STRING },
  resetPasswordExpires: { type: DataTypes.DATE },
  jwtToken: {
    type: DataTypes.STRING,
    allowNull: true,
  },
}, {
  timestamps: true,
  tableName: 'Users',
});

// PreRegister model
const PreRegister = sequelize.define('PreRegister', {
  email: {
    type: DataTypes.STRING,
    allowNull: false,
    unique: true,
    validate: { isEmail: true },
  },
  telegramId: {
    type: DataTypes.STRING,
    allowNull: true,
  },
}, {
  timestamps: true,
  tableName: 'PreRegisters',
});

// TelegramMapping model
const TelegramMapping = sequelize.define('TelegramMapping', {
  username: {
    type: DataTypes.STRING,
    allowNull: false,
    unique: true,
  },
  chatId: {
    type: DataTypes.STRING,
    allowNull: false,
  },
}, {
  timestamps: true,
  tableName: 'TelegramMappings',
});

// App model
const App = sequelize.define('App', {
  name: {
    type: DataTypes.STRING,
    allowNull: false,
  },
  description: {
    type: DataTypes.TEXT,
    allowNull: false,
  },
  category: {
    type: DataTypes.ENUM('games', 'productivity', 'education', 'entertainment'),
    allowNull: false,
  },
  iconPath: {
    type: DataTypes.STRING,
    allowNull: false,
  },
  apkPath: {
    type: DataTypes.STRING,
    allowNull: false,
  },
  userId: {
    type: DataTypes.INTEGER,
    allowNull: false,
    references: {
      model: User,
      key: 'id',
    },
  },
  status: {
    type: DataTypes.ENUM('pending', 'approved', 'rejected'),
    defaultValue: 'pending',
  },
}, {
  timestamps: true,
  tableName: 'Apps',
});

// File upload setup
const upload = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: 10 * 1024 * 1024 }, // 10 MB max
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
      cb(new Error('Only PDF, JPG, JPEG, and PNG files allowed for documents!'));
    } else if (file.fieldname === 'icon') {
      const validMimeTypes = ['image/jpeg', 'image/png', 'image/jpg'];
      const validExtensions = /\.(jpg|jpeg|png)$/i;
      const extname = validExtensions.test(path.extname(file.originalname).toLowerCase());
      const mimetype = validMimeTypes.includes(file.mimetype);
      if (extname && mimetype) {
        return cb(null, true);
      }
      logger.warn(`Invalid icon: name=${file.originalname}, MIME=${file.mimetype}`);
      cb(new Error('Only JPG, JPEG, and PNG files allowed for icons!'));
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
      cb(new Error('Only APK files allowed!'));
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
    const { Location } = await s3.upload(params).promise();
    logger.info(`File uploaded to S3: ${key}`);
    return Location;
  } catch (error) {
    logger.error(`S3 upload error for ${key}: ${error.message}`);
    throw new Error(`S3 upload failed: ${error.message}`);
  }
}

// Telegram bot setup
const TELEGRAM_BOT_TOKEN = '7597915834:AAFzMDAKOc5UgcuAXWYdXy4V0Hj4qXL0KeY';
let bot;
try {
  bot = new TelegramBot(TELEGRAM_BOT_TOKEN, {
    polling: {
      interval: 300,
      autoStart: true,
      params: { timeout: 10 },
    },
  });
  logger.info('Telegram bot initialized');

  // Handle polling errors
  bot.on('polling_error', (error) => {
    logger.error(`Telegram polling error: ${error.message}`);
    if (error.message.includes('409 Conflict')) {
      logger.error('Conflict detected: Another bot instance is running. Stopping polling.');
      bot.stopPolling();
    }
  });
} catch (error) {
  logger.error(`Failed to initialize Telegram bot: ${error.message}`);
}

// Telegram /start command
bot?.onText(/\/start/, async (msg) => {
  const chatId = msg.chat.id;
  const username = msg.from.username || `user_${chatId}`;
  try {
    await TelegramMapping.upsert({
      username: `@${username.replace(/^@/, '')}`,
      chatId: chatId.toString(),
    });
    await bot.sendMessage(
      chatId,
      `🌟 Welcome to PlayEvit!\nYour Telegram chat ID: ${chatId}\nUse this ID or your username (@${username}) during registration.\nWe'll send notifications here!`
    );
    logger.info(`Captured chat ID ${chatId} for username @${username}`);
  } catch (error) {
    logger.error(`Error saving Telegram mapping for chat ID ${chatId}: ${error.message}`);
    await bot.sendMessage(chatId, 'Error saving your chat ID. Try again or contact support.');
  }
});

// Resolve Telegram ID
async function resolveTelegramId(telegramId) {
  if (!telegramId) {
    throw new Error('Telegram ID is required');
  }
  if (/^\d+$/.test(telegramId)) {
    const mapping = await TelegramMapping.findOne({ where: { chatId: telegramId } });
    if (!mapping) {
      throw new Error(`Chat ID ${telegramId} not found. Send /start to the bot.`);
    }
    return telegramId;
  }
  const username = telegramId.startsWith('@') ? telegramId : `@${telegramId}`;
  const mapping = await TelegramMapping.findOne({ where: { username } });
  if (!mapping) {
    throw new Error(`Username ${telegramId} not found. Send /start to the bot.`);
  }
  return mapping.chatId;
}

// Send Telegram message
async function sendTelegramMessage(telegramId, message) {
  if (!bot) {
    logger.warn('Telegram bot not initialized, skipping message send');
    return;
  }
  try {
    const chatId = await resolveTelegramId(telegramId);
    await bot.sendMessage(chatId, message);
    logger.info(`Message sent to chat ID ${chatId}`);
  } catch (error) {
    logger.error(`Error sending message to Telegram ID ${telegramId}: ${error.message}`);
  }
}

// Send verification message
async function sendVerificationTelegram(telegramId, email, token) {
  if (!bot) {
    logger.warn('Telegram bot not initialized, skipping verification message');
    return;
  }
  try {
    const chatId = await resolveTelegramId(telegramId);
    const verificationUrl = `https://vasyaproger-my-backend-9f42.twc1.net/api/auth/verify/${token}`;
    const message = `
🌟 Welcome to PlayEvit, ${telegramId}! 🌟
Verify your email (${email}) by clicking the link:
${verificationUrl}
Or use the token in the verification form on the website:
Token: ${token}
🔗 Token valid for 100 years.
`;
    await bot.sendMessage(chatId, message);
    logger.info(`Verification message sent to chat ID ${chatId}`);
  } catch (error) {
    logger.error(`Error sending verification message to Telegram ID ${telegramId}: ${error.message}`);
  }
}

// Send password reset message
async function sendPasswordResetTelegram(telegramId, token) {
  if (!bot) {
    logger.warn('Telegram bot not initialized, skipping password reset message');
    return;
  }
  try {
    const chatId = await resolveTelegramId(telegramId);
    const resetUrl = `https://vasyaproger-my-backend-9f42.twc1.net/reset-password/${token}`;
    const message = `
🔐 Password Reset for PlayEvit 🔐
You requested a password reset. Click the link:
${resetUrl}
🔗 Link valid for 1 hour.
If you didn't request this, ignore this message.
`;
    await bot.sendMessage(chatId, message);
    logger.info(`Password reset message sent to chat ID ${chatId}`);
  } catch (error) {
    logger.error(`Error sending password reset message to Telegram ID ${telegramId}: ${error.message}`);
  }
}

// JWT authentication middleware
const authenticateToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];
  if (!token) {
    logger.warn('Authorization token missing');
    return res.status(401).json({ message: 'Authorization token required' });
  }
  try {
    const decoded = jwt.verify(token, 'your_jwt_secret');
    req.user = decoded;
    next();
  } catch (error) {
    logger.error(`Invalid token: ${error.message}`);
    return res.status(403).json({ message: 'Invalid or expired token' });
  }
};

// Database synchronization
async function syncDatabase() {
  try {
    await sequelize.sync({ alter: true });
    logger.info('Database synchronized');
    const [results] = await sequelize.query("SHOW TABLES LIKE 'Users'");
    if (results.length > 0) {
      logger.info('Table Users exists');
    } else {
      logger.error('Table Users not created');
    }
    const [preRegisterResults] = await sequelize.query("SHOW TABLES LIKE 'PreRegisters'");
    if (preRegisterResults.length > 0) {
      logger.info('Table PreRegisters exists');
    } else {
      logger.error('Table PreRegisters not created');
    }
    const [telegramMappingResults] = await sequelize.query("SHOW TABLES LIKE 'TelegramMappings'");
    if (telegramMappingResults.length > 0) {
      logger.info('Table TelegramMappings exists');
    } else {
      logger.error('Table TelegramMappings not created');
    }
    const [appResults] = await sequelize.query("SHOW TABLES LIKE 'Apps'");
    if (appResults.length > 0) {
      logger.info('Table Apps exists');
    } else {
      logger.error('Table Apps not created');
    }
  } catch (error) {
    logger.error(`Error synchronizing database: ${error.message}`);
    throw error;
  }
}

// Initialize app
async function initializeApp() {
  try {
    await connectWithRetry();
    await syncDatabase();
  } catch (error) {
    logger.error(`Critical initialization error: ${error.message}`);
    process.exit(1);
  }
}

initializeApp();

// Routes

// Pre-registration
app.post(
  '/api/pre-register',
  [
    body('email').isEmail().normalizeEmail().withMessage('Valid email is required'),
    body('telegramId').optional().trim().custom((value) => {
      if (!value || /^\d+$/.test(value) || /^@/.test(value)) {
        return true;
      }
      throw new Error('Telegram ID must be a numeric chat ID or username with @');
    }),
  ],
  async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      logger.warn(`Validation errors: ${JSON.stringify(errors.array())}`);
      return res.status(400).json({ message: 'Validation error', errors: errors.array() });
    }

    try {
      const { email, telegramId } = req.body;

      const existingPreRegister = await PreRegister.findOne({ where: { email } });
      if (existingPreRegister) {
        return res.status(400).json({ message: 'This email is already in the waitlist' });
      }

      const preRegister = await PreRegister.create({ email, telegramId });

      let message = `🌟 Thank you for your interest in PlayEvit!\nYour email (${email}) has been added to the waitlist.\nWe'll notify you about the launch in 2025!`;
      if (telegramId) {
        try {
          await sendTelegramMessage(telegramId, message);
        } catch (error) {
          message = 'We couldn’t send a Telegram message. Ensure you sent /start to the bot.';
        }
      }

      logger.info(`Pre-registration: ${email}`);
      res.status(201).json({ message });
    } catch (error) {
      logger.error(`Pre-registration error: ${error.message}`);
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
    body('telegramId').notEmpty().trim().custom((value) => {
      if (/^\d+$/.test(value) || /^@/.test(value)) {
        return true;
      }
      throw new Error('Telegram ID must be a numeric chat ID or username with @');
    }).withMessage('Invalid Telegram ID'),
  ],
  async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      logger.warn(`Validation errors: ${JSON.stringify(errors.array())}`);
      return res.status(400).json({ message: 'Validation error', errors: errors.array() });
    }

    try {
      const {
        email, password, accountType, name, phone, telegramId,
        addressStreet, addressCity, addressCountry, addressPostalCode,
      } = req.body;

      if (!req.files || !req.files.documents || req.files.documents.length === 0) {
        logger.warn('No documents uploaded during registration');
        return res.status(400).json({ message: 'At least one document is required' });
      }

      const existingUser = await User.findOne({ where: { email } });
      if (existingUser) {
        return res.status(400).json({ message: 'Email already registered' });
      }

      const documentUrls = await Promise.all(
        req.files.documents.map(file => uploadToS3(file, 'documents'))
      );

      const salt = await bcrypt.genSalt(10);
      const hashedPassword = await bcrypt.hash(password, salt);
      const verificationToken = jwt.sign(
        { email },
        'your_jwt_secret',
        { expiresIn: '100y' }
      );

      const authToken = jwt.sign(
        { email, accountType, name, telegramId },
        'your_jwt_secret',
        { expiresIn: '7d' }
      );

      const user = await User.create({
        email,
        password: hashedPassword,
        accountType,
        name,
        phone,
        telegramId,
        addressStreet,
        addressCity,
        addressCountry,
        addressPostalCode,
        documents: documentUrls,
        verificationToken,
        jwtToken: authToken,
      });

      try {
        await sendVerificationTelegram(telegramId, email, verificationToken);
        logger.info(`User registered: ${email}`);
        res.status(201).json({
          message: `Registration successful! Check your Telegram (${telegramId}) for verification.`,
          token: authToken,
          user: {
            id: user.id,
            email: user.email,
            accountType: user.accountType,
            name: user.name,
            telegramId: user.telegramId,
          },
        });
      } catch (telegramError) {
        logger.warn(`Telegram message not sent for ${email}: ${telegramError.message}`);
        res.status(201).json({
          message: `Registration successful, but Telegram message failed. Send /start to the bot with your ${telegramId}.`,
          token: authToken,
          user: {
            id: user.id,
            email: user.email,
            accountType: user.accountType,
            name: user.name,
            telegramId: user.telegramId,
          },
        });
      }
    } catch (error) {
      logger.error(`Registration error: ${error.message}`);
      res.status(500).json({ message: 'Server error', error: error.message });
    }
  }
);

// Email verification via link
app.get('/api/auth/verify/:token', async (req, res) => {
  try {
    const { token } = req.params;
    let decoded;
    try {
      decoded = jwt.verify(token, 'your_jwt_secret');
    } catch (error) {
      logger.warn(`Invalid verification token: ${error.message}`);
      return res.status(400).json({ message: 'Invalid or expired token' });
    }

    const user = await User.findOne({ where: { email: decoded.email } });
    if (!user) {
      logger.warn(`User with email ${decoded.email} not found`);
      return res.status(400).json({ message: 'User not found' });
    }

    if (user.verificationToken !== token) {
      logger.warn(`Verification token mismatch for email ${decoded.email}`);
      return res.status(400).json({ message: 'Invalid token' });
    }

    if (user.isVerified) {
      return res.status(200).json({ message: 'Email already verified' });
    }

    user.isVerified = true;
    user.verificationToken = null;
    await user.save();

    try {
      await sendTelegramMessage(user.telegramId, `✅ Your email (${user.email}) is verified! Welcome to PlayEvit!`);
    } catch (telegramError) {
      logger.warn(`Failed to send verification message to Telegram for ${user.email}: ${telegramError.message}`);
    }

    logger.info(`Email verified for ${user.email}`);
    res.status(200).json({ message: 'Email verified successfully!' });
  } catch (error) {
    logger.error(`Verification error: ${error.message}`);
    res.status(500).json({ message: 'Server error', error: error.message });
  }
});

// Email verification via form
app.post(
  '/api/auth/verify-form',
  [
    body('email').isEmail().normalizeEmail().withMessage('Valid email is required'),
    body('token').notEmpty().trim().withMessage('Token is required'),
  ],
  async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      logger.warn(`Validation errors: ${JSON.stringify(errors.array())}`);
      return res.status(400).json({ message: 'Validation error', errors: errors.array() });
    }

    try {
      const { email, token } = req.body;

      let decoded;
      try {
        decoded = jwt.verify(token, 'your_jwt_secret');
      } catch (error) {
        logger.warn(`Invalid verification token in form: ${error.message}`);
        return res.status(400).json({ message: 'Invalid or expired token' });
      }

      if (decoded.email !== email) {
        logger.warn(`Email ${email} does not match token`);
        return res.status(400).json({ message: 'Token does not match provided email' });
      }

      const user = await User.findOne({ where: { email } });
      if (!user) {
        logger.warn(`User with email ${email} not found`);
        return res.status(400).json({ message: 'User not found' });
      }

      if (user.verificationToken !== token) {
        logger.warn(`Verification token mismatch for email ${email}`);
        return res.status(400).json({ message: 'Invalid token' });
      }

      if (user.isVerified) {
        return res.status(200).json({ message: 'Email already verified' });
      }

      user.isVerified = true;
      user.verificationToken = null;
      await user.save();

      try {
        await sendTelegramMessage(user.telegramId, `✅ Your email (${user.email}) is verified! Welcome to PlayEvit!`);
      } catch (telegramError) {
        logger.warn(`Failed to send verification message to Telegram for ${user.email}: ${telegramError.message}`);
      }

      logger.info(`Email verified via form for ${user.email}`);
      res.status(200).json({ message: 'Email verified successfully!' });
    } catch (error) {
      logger.error(`Form verification error: ${error.message}`);
      res.status(500).json({ message: 'Server error', error: error.message });
    }
  }
);

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

      const user = await User.findOne({ where: { email } });
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
        token = jwt.sign(
          { id: user.id, email: user.email },
          'your_jwt_secret',
          { expiresIn: '7d' }
        );
        user.jwtToken = token;
        await user.save();
      }

      try {
        await sendTelegramMessage(user.telegramId, `🔐 You logged into PlayEvit with email: ${user.email}`);
      } catch (telegramError) {
        logger.warn(`Failed to send login message to Telegram for ${user.email}: ${telegramError.message}`);
      }

      logger.info(`User logged in: ${user.email}`);
      res.status(200).json({
        token,
        user: {
          id: user.id,
          email: user.email,
          accountType: user.accountType,
          name: user.name,
          telegramId: user.telegramId,
        },
        message: 'Login successful',
      });
    } catch (error) {
      logger.error(`Login error: ${error.message}`);
      res.status(500).json({ message: 'Server error', error: error.message });
    }
  }
);

// Password reset request
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
      const user = await User.findOne({ where: { email } });
      if (!user) {
        logger.warn(`Password reset attempt for non-existent email: ${email}`);
        return res.status(404).json({ message: 'User with this email not found' });
      }

      const resetToken = jwt.sign(
        { email },
        'your_jwt_secret',
        { expiresIn: '1h' }
      );
      user.resetPasswordToken = resetToken;
      user.resetPasswordExpires = new Date(Date.now() + 3600000);
      await user.save();

      try {
        await sendPasswordResetTelegram(user.telegramId, resetToken);
        logger.info(`Password reset requested for ${user.email}`);
        res.status(200).json({ message: 'Password reset link sent to Telegram' });
      } catch (telegramError) {
        logger.warn(`Password reset message not sent to Telegram for ${user.email}: ${telegramError.message}`);
        res.status(200).json({
          message: 'Password reset link not sent to Telegram. Ensure you sent /start to the bot.',
          email,
        });
      }
    } catch (error) {
      logger.error(`Password reset request error: ${error.message}`);
      res.status(500).json({ message: 'Server error', error: error.message });
    }
  }
);

// Password reset
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
        decoded = jwt.verify(token, 'your_jwt_secret');
      } catch (error) {
        logger.warn(`Invalid reset token: ${error.message}`);
        return res.status(400).json({ message: 'Invalid or expired token' });
      }

      const user = await User.findOne({
        where: {
          email: decoded.email,
          resetPasswordToken: token,
          resetPasswordExpires: { [Sequelize.Op.gt]: new Date() },
        },
      });
      if (!user) {
        logger.warn(`Invalid or expired reset token for email: ${decoded.email}`);
        return res.status(400).json({ message: 'Invalid token or expired' });
      }

      const salt = await bcrypt.genSalt(10);
      user.password = await bcrypt.hash(password, salt);
      user.resetPasswordToken = null;
      user.resetPasswordExpires = null;
      user.jwtToken = null;
      await user.save();

      try {
        await sendTelegramMessage(user.telegramId, `🔑 Your password was reset for email: ${user.email}`);
      } catch (telegramError) {
        logger.warn(`Failed to send password reset message to Telegram for ${user.email}: ${telegramError.message}`);
      }

      logger.info(`Password reset for ${user.email}`);
      res.status(200).json({ message: 'Password reset successfully' });
    } catch (error) {
      logger.error(`Password reset error: ${error.message}`);
      res.status(500).json({ message: 'Server error', error: error.message });
    }
  }
);

// Get user profile
app.get('/api/user/profile', authenticateToken, async (req, res) => {
  try {
    const user = await User.findByPk(req.user.id, {
      attributes: { exclude: ['password', 'verificationToken', 'resetPasswordToken', 'resetPasswordExpires', 'jwtToken'] },
    });
    if (!user) {
      logger.warn(`User not found for ID: ${req.user.id}`);
      return res.status(404).json({ message: 'User not found' });
    }
    res.status(200).json(user);
  } catch (error) {
    logger.error(`Error fetching profile: ${error.message}`);
    res.status(500).json({ message: 'Server error', error: error.message });
  }
});

// Update documents
app.post(
  '/api/user/documents',
  authenticateToken,
  upload,
  async (req, res) => {
    try {
      const user = await User.findByPk(req.user.id);
      if (!user) {
        logger.warn(`User not found for ID: ${req.user.id}`);
        return res.status(404).json({ message: 'User not found' });
      }

      if (!req.files || !req.files.documents || req.files.documents.length === 0) {
        logger.warn('No documents uploaded');
        return res.status(400).json({ message: 'At least one document is required' });
      }

      const newDocuments = await Promise.all(
        req.files.documents.map(file => uploadToS3(file, 'documents'))
      );

      user.documents = [...user.documents, ...newDocuments].slice(0, 3);
      user.isVerified = true;
      await user.save();

      try {
        await sendTelegramMessage(user.telegramId, `📄 Your documents were updated for email: ${user.email}`);
      } catch (telegramError) {
        logger.warn(`Failed to send document update message to Telegram for ${user.email}: ${telegramError.message}`);
      }

      logger.info(`Documents updated for user ${user.email}`);
      res.status(200).json({ message: 'Documents updated successfully', documents: user.documents });
    } catch (error) {
      logger.error(`Error updating documents: ${error.message}`);
      res.status(500).json({ message: 'Server error', error: error.message });
    }
  }
);

// Create new app
app.post(
  '/api/apps/create',
  authenticateToken,
  upload,
  [
    body('name').notEmpty().trim().withMessage('App name is required'),
    body('description').notEmpty().trim().withMessage('Description is required'),
    body('category').isIn(['games', 'productivity', 'education', 'entertainment']).withMessage('Invalid category; must be one of: games, productivity, education, entertainment'),
  ],
  async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      logger.warn(`Validation errors: ${JSON.stringify(errors.array())}`);
      return res.status(400).json({ message: 'Validation error', errors: errors.array() });
    }

    try {
      const user = await User.findByPk(req.user.id);
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
        return res.status(400).json({ message: 'Icon file (JPG, JPEG, or PNG) is required' });
      }
      if (!files.apk || !files.apk[0]) {
        logger.warn('APK file missing');
        return res.status(400).json({ message: 'APK file is required' });
      }

      const iconUrl = await uploadToS3(files.icon[0], 'icons');
      const apkUrl = await uploadToS3(files.apk[0], 'apks');

      const app = await App.create({
        name,
        description,
        category,
        iconPath: iconUrl,
        apkPath: apkUrl,
        userId: user.id,
        status: 'pending',
      });

      try {
        await sendTelegramMessage(
          user.telegramId,
          `🚀 Your app "${name}" has been submitted for review! We'll notify you once it's processed.`
        );
      } catch (telegramError) {
        logger.warn(`Failed to send app submission message to Telegram for ${user.email}: ${telegramError.message}`);
      }

      logger.info(`App created by ${user.email}: ${name}`);
      res.status(201).json({ message: 'App submitted successfully', app });
    } catch (error) {
      logger.error(`Error creating app: ${error.message}`);
      res.status(500).json({ message: 'Server error', error: error.message });
    }
  }
);

// Error handling middleware
app.use((err, req, res, next) => {
  logger.error(`Unhandled error: ${err.message}`);
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

// Start server
const PORT = 5000;
app.listen(PORT, () => {
  logger.info(`Server running on port ${PORT}`);
});