const express = require('express');
const { Sequelize, DataTypes } = require('sequelize');
const mysql2 = require('mysql2');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const TelegramBot = require('node-telegram-bot-api');
const multer = require('multer');
const path = require('path');
const cors = require('cors');
const helmet = require('helmet');
const { body, validationResult } = require('express-validator');
const winston = require('winston');

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

// Middleware
app.use(helmet());
app.use(cors());
app.use(express.json());
app.use('/uploads', express.static(path.join(__dirname, 'Uploads')));

// Database connection
const sequelize = new Sequelize({
  dialect: 'mysql',
  host: 'vh438.timeweb.ru',
  username: process.env.DB_USER || 'ch79145_myprojec',
  password: process.env.DB_PASS || 'Vasya11091109',
  database: 'ch79145_myprojec',
  port: 3306,
  dialectModule: mysql2,
  logging: (msg) => logger.debug(msg),
});

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
const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    if (file.fieldname === 'documents') {
      cb(null, './Uploads/documents/');
    } else if (file.fieldname === 'icon') {
      cb(null, './Uploads/icons/');
    } else if (file.fieldname === 'apk') {
      cb(null, './Uploads/apks/');
    }
  },
  filename: (req, file, cb) => {
    const sanitizedName = path.basename(file.originalname, path.extname(file.originalname)).replace(/[^a-zA-Z0-9]/g, '_');
    cb(null, `${Date.now()}-${sanitizedName}${path.extname(file.originalname)}`);
  },
});

const upload = multer({
  storage,
  limits: { fileSize: 10 * 1024 * 1024 }, // 10 MB max
  fileFilter: (req, file, cb) => {
    if (file.fieldname === 'documents') {
      const filetypes = /pdf|jpg|jpeg|png/;
      const extname = filetypes.test(path.extname(file.originalname).toLowerCase());
      const mimetype = filetypes.test(file.mimetype);
      if (extname && mimetype) {
        return cb(null, true);
      }
      cb(new Error('Only PDF, JPG, JPEG, and PNG files allowed for documents!'));
    } else if (file.fieldname === 'icon') {
      const filetypes = /jpg|jpeg|png/;
      const extname = filetypes.test(path.extname(file.originalname).toLowerCase());
      const mimetype = filetypes.test(file.mimetype);
      if (extname && mimetype) {
        return cb(null, true);
      }
      cb(new Error('Only JPG, JPEG, and PNG files allowed for icons!'));
    } else if (file.fieldname === 'apk') {
      if (file.originalname.endsWith('.apk')) {
        return cb(null, true);
      }
      cb(new Error('Only APK files allowed!'));
    }
  },
});

// Telegram bot setup
const TELEGRAM_BOT_TOKEN = process.env.TELEGRAM_BOT_TOKEN || '7597915834:AAFzMDAKOc5UgcuAXWYdXy4V0Hj4qXL0KeY';
const bot = new TelegramBot(TELEGRAM_BOT_TOKEN, {
  polling: {
    interval: 300,
    autoStart: true,
    params: { timeout: 10 },
  },
});

// Telegram /start command
bot.onText(/\/start/, async (msg) => {
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
  try {
    const chatId = await resolveTelegramId(telegramId);
    await bot.sendMessage(chatId, message);
    logger.info(`Message sent to chat ID ${chatId}`);
  } catch (error) {
    logger.error(`Error sending message to Telegram ID ${telegramId}: ${error.message}`);
    throw error;
  }
}

// Send verification message
async function sendVerificationTelegram(telegramId, email, token) {
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
    throw error;
  }
}

// Send password reset message
async function sendPasswordResetTelegram(telegramId, token) {
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
    throw error;
  }
}

// JWT authentication middleware
const authenticateToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];
  if (!token) {
    return res.status(401).json({ message: 'Authorization token required' });
  }
  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET || 'your_jwt_secret');
    req.user = decoded;
    next();
  } catch (error) {
    logger.error(`Invalid token: ${error.message}`);
    return res.status(403).json({ message: 'Invalid token' });
  }
};

// Database synchronization
sequelize.sync({ alter: true }).then(() => {
  logger.info('Database synchronized');
}).catch((error) => {
  logger.error(`Error synchronizing database: ${error.message}`);
});

// Routes

// Pre-registration
app.post(
  '/api/pre-register',
  [
    body('email').isEmail().normalizeEmail(),
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
      res.status(500).json({ message: 'Server error' });
    }
  }
);

// User registration
app.post(
  '/api/auth/register',
  upload.array('documents', 3),
  [
    body('email').isEmail().normalizeEmail(),
    body('password').isLength({ min: 8 }),
    body('accountType').isIn(['individual', 'commercial']),
    body('name').notEmpty().trim(),
    body('phone').notEmpty().trim(),
    body('telegramId').notEmpty().trim().custom((value) => {
      if (/^\d+$/.test(value) || /^@/.test(value)) {
        return true;
      }
      throw new Error('Telegram ID must be a numeric chat ID or username with @');
    }),
  ],
  async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ message: 'Validation error', errors: errors.array() });
    }

    try {
      const {
        email, password, accountType, name, phone, telegramId,
        addressStreet, addressCity, addressCountry, addressPostalCode,
      } = req.body;

      if (!req.files || req.files.length === 0) {
        return res.status(400).json({ message: 'At least one document is required' });
      }

      const existingUser = await User.findOne({ where: { email } });
      if (existingUser) {
        return res.status(400).json({ message: 'Email already registered' });
      }

      const salt = await bcrypt.genSalt(10);
      const hashedPassword = await bcrypt.hash(password, salt);
      const verificationToken = jwt.sign(
        { email },
        process.env.JWT_SECRET || 'your_jwt_secret',
        { expiresIn: '100y' }
      );

      const authToken = jwt.sign(
        { email, accountType, name, telegramId },
        process.env.JWT_SECRET || 'your_jwt_secret',
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
        documents: req.files.map(file => file.path),
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
      res.status(500).json({ message: 'Server error' });
    }
  }
);

// Email verification via link
app.get('/api/auth/verify/:token', async (req, res) => {
  try {
    const { token } = req.params;
    let decoded;
    try {
      decoded = jwt.verify(token, process.env.JWT_SECRET || 'your_jwt_secret');
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
      logger.warn(`Failed to send verification message to Telegram for ${user.email}`);
    }

    logger.info(`Email verified for ${user.email}`);
    res.status(200).json({ message: 'Email verified successfully!' });
  } catch (error) {
    logger.error(`Verification error: ${error.message}`);
    res.status(500).json({ message: 'Server error' });
  }
});

// Email verification via form
app.post(
  '/api/auth/verify-form',
  [
    body('email').isEmail().normalizeEmail(),
    body('token').notEmpty().trim(),
  ],
  async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ message: 'Validation error', errors: errors.array() });
    }

    try {
      const { email, token } = req.body;

      let decoded;
      try {
        decoded = jwt.verify(token, process.env.JWT_SECRET || 'your_jwt_secret');
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
        logger.warn(`Failed to send verification message to Telegram for ${user.email}`);
      }

      logger.info(`Email verified via form for ${user.email}`);
      res.status(200).json({ message: 'Email verified successfully!' });
    } catch (error) {
      logger.error(`Form verification error: ${error.message}`);
      res.status(500).json({ message: 'Server error' });
    }
  }
);

// User login
app.post(
  '/api/auth/login',
  [
    body('email').isEmail().normalizeEmail(),
    body('password').notEmpty(),
  ],
  async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
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
          process.env.JWT_SECRET || 'your_jwt_secret',
          { expiresIn: '7d' }
        );
        user.jwtToken = token;
        await user.save();
      }

      try {
        await sendTelegramMessage(user.telegramId, `🔐 You logged into PlayEvit with email: ${email}`);
      } catch (telegramError) {
        logger.warn(`Failed to send login message to Telegram for ${email}`);
      }

      logger.info(`User logged in: ${email}`);
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
      res.status(500).json({ message: 'Server error' });
    }
  }
);

// Password reset request
app.post(
  '/api/auth/forgot-password',
  [body('email').isEmail().normalizeEmail()],
  async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ message: 'Validation error', errors: errors.array() });
    }

    try {
      const { email } = req.body;
      const user = await User.findOne({ where: { email } });
      if (!user) {
        return res.status(404).json({ message: 'User with this email not found' });
      }

      const resetToken = jwt.sign({ email }, process.env.JWT_SECRET || 'your_jwt_secret', { expiresIn: '1h' });
      user.resetPasswordToken = resetToken;
      user.resetPasswordExpires = new Date(Date.now() + 3600000);
      await user.save();

      try {
        await sendPasswordResetTelegram(user.telegramId, resetToken);
        logger.info(`Password reset requested for ${email}`);
        res.status(200).json({ message: 'Password reset link sent to Telegram' });
      } catch (telegramError) {
        logger.warn(`Password reset message not sent to Telegram for ${email}: ${telegramError.message}`);
        res.status(200).json({
          message: 'Password reset link not sent to Telegram. Ensure you sent /start to the bot.',
          email,
        });
      }
    } catch (error) {
      logger.error(`Password reset request error: ${error.message}`);
      res.status(500).json({ message: 'Server error' });
    }
  }
);

// Password reset
app.post(
  '/api/auth/reset-password/:token',
  [
    body('password').isLength({ min: 8 }),
    body('confirmPassword').custom((value, { req }) => value === req.body.password),
  ],
  async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ message: 'Validation error', errors: errors.array() });
    }

    try {
      const { token } = req.params;
      const { password } = req.body;

      let decoded;
      try {
        decoded = jwt.verify(token, process.env.JWT_SECRET || 'your_jwt_secret');
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
        logger.warn(`Failed to send password reset message to Telegram for ${user.email}`);
      }

      logger.info(`Password reset for ${user.email}`);
      res.status(200).json({ message: 'Password reset successfully' });
    } catch (error) {
      logger.error(`Password reset error: ${error.message}`);
      res.status(500).json({ message: 'Server error' });
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
      return res.status(404).json({ message: 'User not found' });
    }
    res.status(200).json(user);
  } catch (error) {
    logger.error(`Error fetching profile: ${error.message}`);
    res.status(500).json({ message: 'Server error' });
  }
});

// Update documents
app.post(
  '/api/user/documents',
  authenticateToken,
  upload.array('documents', 3),
  async (req, res) => {
    try {
      const user = await User.findByPk(req.user.id);
      if (!user) {
        return res.status(404).json({ message: 'User not found' });
      }

      if (!req.files || req.files.length === 0) {
        return res.status(400).json({ message: 'At least one document is required' });
      }

      const newDocuments = req.files.map(file => file.path);
      user.documents = [...user.documents, ...newDocuments].slice(0, 3);
      user.isVerified = true; // Auto-verify after document upload
      await user.save();

      try {
        await sendTelegramMessage(user.telegramId, `📄 Your documents were updated for email: ${user.email}`);
      } catch (telegramError) {
        logger.warn(`Failed to send document update message to Telegram for ${user.email}`);
      }

      logger.info(`Documents updated for user ${user.email}`);
      res.status(200).json({ message: 'Documents updated successfully', documents: user.documents });
    } catch (error) {
      logger.error(`Error updating documents: ${error.message}`);
      res.status(500).json({ message: 'Server error' });
    }
  }
);

// Create new app
app.post(
  '/api/apps/create',
  authenticateToken,
  upload.fields([
    { name: 'icon', maxCount: 1 },
    { name: 'apk', maxCount: 1 },
  ]),
  [
    body('name').notEmpty().trim(),
    body('description').notEmpty().trim(),
    body('category').isIn(['games', 'productivity', 'education', 'entertainment']),
  ],
  async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ message: 'Validation error', errors: errors.array() });
    }

    try {
      const user = await User.findByPk(req.user.id);
      if (!user) {
        return res.status(404).json({ message: 'User not found' });
      }

      if (!user.isVerified) {
        return res.status(403).json({ message: 'Account must be verified to submit apps' });
      }

      const { name, description, category } = req.body;
      const files = req.files;

      if (!files || !files.icon || !files.apk) {
        return res.status(400).json({ message: 'Icon and APK files are required' });
      }

      const app = await App.create({
        name,
        description,
        category,
        iconPath: files.icon[0].path,
        apkPath: files.apk[0].path,
        userId: user.id,
        status: 'pending',
      });

      try {
        await sendTelegramMessage(
          user.telegramId,
          `🚀 Your app "${name}" has been submitted for review! We'll notify you once it's processed.`
        );
      } catch (telegramError) {
        logger.warn(`Failed to send app submission message to Telegram for ${user.email}`);
      }

      logger.info(`App created by ${user.email}: ${name}`);
      res.status(201).json({ message: 'App submitted successfully', app });
    } catch (error) {
      logger.error(`Error creating app: ${error.message}`);
      res.status(500).json({ message: 'Server error' });
    }
  }
);

// Error handling
app.use((err, req, res, next) => {
  logger.error(`Unhandled error: ${err.message}`);
  if (err instanceof multer.MulterError) {
    return res.status(400).json({ message: 'File upload error: ' + err.message });
  }
  res.status(500).json({ message: 'Server error' });
});

// Start server
const PORT = process.env.PORT || 5000;
app.listen(PORT, () => {
  logger.info(`Server running on port ${PORT}`);
});