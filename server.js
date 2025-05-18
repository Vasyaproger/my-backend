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
const rateLimit = require('express-rate-limit');
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

// Rate limiter
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100, // Limit each IP to 100 requests
});
app.use(limiter);

// MySQL setup
const sequelize = new Sequelize({
  dialect: 'mysql',
  host: 'vh438.timeweb.ru',
  username: 'ch79145_myprojec',
  password: 'Vasya11091109',
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
    allowNull: false, // Stores Telegram chat ID (numeric string)
  },
  addressStreet: {
    type: DataTypes.STRING,
  },
  addressCity: {
    type: DataTypes.STRING,
  },
  addressCountry: {
    type: DataTypes.STRING,
  },
  addressPostalCode: {
    type: DataTypes.STRING,
  },
  documents: {
    type: DataTypes.JSON,
    allowNull: false,
    defaultValue: [],
  },
  isVerified: {
    type: DataTypes.BOOLEAN,
    defaultValue: false,
  },
  verificationToken: {
    type: DataTypes.STRING,
  },
  resetPasswordToken: {
    type: DataTypes.STRING,
  },
  resetPasswordExpires: {
    type: DataTypes.DATE,
  },
}, {
  timestamps: true,
  tableName: 'Users',
});

// TelegramMapping model to store username-to-chat-ID mappings
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

// Multer setup
const storage = multer.diskStorage({
  destination: './Uploads/documents/',
  filename: (req, file, cb) => {
    const sanitizedName = path.basename(file.originalname, path.extname(file.originalname)).replace(/[^a-zA-Z0-9]/g, '_');
    cb(null, `${Date.now()}-${sanitizedName}${path.extname(file.originalname)}`);
  },
});
const upload = multer({
  storage,
  limits: { fileSize: 5 * 1024 * 1024 }, // 5 MB
  fileFilter: (req, file, cb) => {
    const filetypes = /pdf|jpg|jpeg|png/;
    const extname = filetypes.test(path.extname(file.originalname).toLowerCase());
    const mimetype = filetypes.test(file.mimetype);
    if (extname && mimetype) {
      return cb(null, true);
    }
    cb(new Error('Разрешены только PDF, JPG, JPEG и PNG файлы!'));
  },
});

// Telegram Bot setup
const TELEGRAM_BOT_TOKEN = '7597915834:AAFzMDAKOc5UgcuAXWYdXy4V0Hj4qXL0KeY'; // Secure this in production (e.g., use environment variables)
const bot = new TelegramBot(TELEGRAM_BOT_TOKEN, { polling: true }); // Enable polling to handle /start command

// Handle /start command to capture chat ID
bot.onText(/\/start/, async (msg) => {
  const chatId = msg.chat.id;
  const username = msg.from.username || `user_${chatId}`; // Fallback if no username
  try {
    await TelegramMapping.upsert({
      username: `@${username.replace(/^@/, '')}`,
      chatId: chatId.toString(),
    });
    await bot.sendMessage(chatId, `Ваш Telegram chat ID: ${chatId}\nИспользуйте этот ID при регистрации в PlayEvit.`);
    logger.info(`Captured chat ID ${chatId} for username @${username}`);
  } catch (error) {
    logger.error(`Error saving Telegram mapping for chat ID ${chatId}: ${error.message}`);
    await bot.sendMessage(chatId, 'Ошибка при сохранении вашего chat ID. Пожалуйста, попробуйте снова или свяжитесь с поддержкой.');
  }
});

// Resolve telegramId to chatId
async function resolveTelegramId(telegramId) {
  // Check if telegramId is a numeric chat ID
  if (/^\d+$/.test(telegramId)) {
    return telegramId;
  }
  // Otherwise, treat as username and look up chat ID
  const mapping = await TelegramMapping.findOne({ where: { username: telegramId } });
  if (!mapping) {
    throw new Error(`Chat ID not found for username ${telegramId}. User must send /start to the bot.`);
  }
  return mapping.chatId;
}

// Telegram message functions
async function sendVerificationTelegram(telegramId, token) {
  try {
    const chatId = await resolveTelegramId(telegramId);
    const verificationUrl = `https://vasyaproger-my-backend-9f42.twc1.net/api/auth/verify/${token}`;
    const message = `
🌟 Добро пожаловать в PlayEvit! 🌟
Пожалуйста, подтвердите ваш email, перейдя по ссылке:
${verificationUrl}
🔗 Ссылка действительна 24 часа.
`;
    logger.info(`Attempting to send verification message to Telegram chat ID ${chatId}`);
    await bot.sendMessage(chatId, message);
    logger.info(`Verification message sent to Telegram chat ID ${chatId}`);
  } catch (error) {
    logger.error(`Failed to send verification message to Telegram ID ${telegramId}: ${error.message}`);
    throw error;
  }
}

async function sendPasswordResetTelegram(telegramId, token) {
  try {
    const chatId = await resolveTelegramId(telegramId);
    const resetUrl = `https://vasyaproger-my-backend-9f42.twc1.net/reset-password/${token}`;
    const message = `
🔐 Сброс пароля в PlayEvit 🔐
Вы запросили сброс пароля. Перейдите по ссылке, чтобы установить новый пароль:
${resetUrl}
🔗 Ссылка действительна 1 час.
Если вы не запрашивали сброс, проигнорируйте это сообщение.
`;
    logger.info(`Attempting to send password reset message to Telegram chat ID ${chatId}`);
    await bot.sendMessage(chatId, message);
    logger.info(`Password reset message sent to Telegram chat ID ${chatId}`);
  } catch (error) {
    logger.error(`Failed to send password reset message to Telegram ID ${telegramId}: ${error.message}`);
    throw error;
  }
}

// Middleware to authenticate JWT
const authenticateToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];
  if (!token) {
    return res.status(401).json({ message: 'Требуется токен авторизации' });
  }
  try {
    const decoded = jwt.verify(token, 'your_jwt_secret'); // REPLACE with a secure random string in production
    req.user = decoded;
    next();
  } catch (error) {
    logger.error(`Invalid token: ${error.message}`);
    return res.status(403).json({ message: 'Недействительный токен' });
  }
};

// Database sync
sequelize.sync({ alter: true }).then(() => {
  logger.info('Database synchronized');
}).catch((error) => {
  logger.error(`Database sync failed: ${error.message}`);
});

// Routes

// Register
app.post('/api/auth/register',
  upload.array('documents', 3),
  [
    body('email').isEmail().normalizeEmail(),
    body('password').isLength({ min: 8 }),
    body('accountType').isIn(['individual', 'commercial']),
    body('name').notEmpty().trim(),
    body('phone').notEmpty().trim(),
    body('telegramId').notEmpty().trim().custom((value) => {
      // Allow numeric chat ID or username starting with @
      if (/^\d+$/.test(value) || /^@/.test(value)) {
        return true;
      }
      throw new Error('Telegram ID должен быть числовым chat ID или username, начинающимся с @');
    }),
  ],
  async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ message: 'Ошибка валидации', errors: errors.array() });
    }

    try {
      const {
        email, password, accountType, name, phone, telegramId,
        addressStreet, addressCity, addressCountry, addressPostalCode,
      } = req.body;

      if (!req.files || req.files.length === 0) {
        return res.status(400).json({ message: 'Требуется хотя бы один документ' });
      }

      const existingUser = await User.findOne({ where: { email } });
      if (existingUser) {
        return res.status(400).json({ message: 'Email уже зарегистрирован' });
      }

      const salt = await bcrypt.genSalt(10);
      const hashedPassword = await bcrypt.hash(password, salt);
      const verificationToken = jwt.sign({ email }, 'your_jwt_secret', { expiresIn: '1d' });

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
      });

      try {
        await sendVerificationTelegram(telegramId, verificationToken);
        logger.info(`User registered: ${email}`);
        res.status(201).json({ message: 'Регистрация успешна! Проверьте Telegram для подтверждения.' });
      } catch (telegramError) {
        logger.warn(`User registered but Telegram message failed for ${email}: ${telegramError.message}`);
        res.status(201).json({
          message: 'Регистрация успешна, но сообщение в Telegram не отправлено. Убедитесь, что вы отправили /start боту, или свяжитесь с поддержкой.',
          email,
        });
      }
    } catch (error) {
      logger.error(`Registration error: ${error.message}`);
      res.status(500).json({ message: 'Ошибка сервера' });
    }
  }
);

// Verify email
app.get('/api/auth/verify/:token', async (req, res) => {
  try {
    const { token } = req.params;
    let decoded;
    try {
      decoded = jwt.verify(token, 'your_jwt_secret');
    } catch (error) {
      logger.warn(`Invalid verification token: ${error.message}`);
      return res.status(400).json({ message: 'Недействительный или истекший токен' });
    }

    const user = await User.findOne({ where: { email: decoded.email, verificationToken: token } });
    if (!user) {
      return res.status(400).json({ message: 'Пользователь не найден или токен недействителен' });
    }

    user.isVerified = true;
    user.verificationToken = null;
    await user.save();

    logger.info(`Email verified for ${user.email}`);
    res.status(200).json({ message: 'Email успешно подтвержден!' });
  } catch (error) {
    logger.error(`Verification error: ${error.message}`);
    res.status(500).json({ message: 'Ошибка сервера' });
  }
});

// Login
app.post('/api/auth/login',
  [
    body('email').isEmail().normalizeEmail(),
    body('password').notEmpty(),
  ],
  async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ message: 'Ошибка валидации', errors: errors.array() });
    }

    try {
      const { email, password } = req.body;

      const user = await User.findOne({ where: { email } });
      if (!user) {
        logger.warn(`Login attempt with non-existent email: ${email}`);
        return res.status(400).json({ message: 'Неверный email или пароль' });
      }

      const isMatch = await bcrypt.compare(password, user.password);
      if (!isMatch) {
        logger.warn(`Invalid password for email: ${email}`);
        return res.status(400).json({ message: 'Неверный email или пароль' });
      }

      if (!user.isVerified) {
        return res.status(400).json({ message: 'Подтвердите ваш email через Telegram перед входом' });
      }

      const token = jwt.sign(
        { id: user.id, email: user.email },
        'your_jwt_secret',
        { expiresIn: '7d' }
      );

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
        message: 'Вход успешен',
      });
    } catch (error) {
      logger.error(`Login error: ${error.message}`);
      res.status(500).json({ message: 'Ошибка сервера' });
    }
  }
);

// Forgot password
app.post('/api/auth/forgot-password',
  [body('email').isEmail().normalizeEmail()],
  async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ message: 'Ошибка валидации', errors: errors.array() });
    }

    try {
      const { email } = req.body;
      const user = await User.findOne({ where: { email } });
      if (!user) {
        return res.status(404).json({ message: 'Пользователь с таким email не найден' });
      }

      const resetToken = jwt.sign({ email }, 'your_jwt_secret', { expiresIn: '1h' });
      user.resetPasswordToken = resetToken;
      user.resetPasswordExpires = new Date(Date.now() + 3600000); // 1 hour
      await user.save();

      try {
        await sendPasswordResetTelegram(user.telegramId, resetToken);
        logger.info(`Password reset requested for ${email}`);
        res.status(200).json({ message: 'Ссылка для сброса пароля отправлена в Telegram' });
      } catch (telegramError) {
        logger.warn(`Password reset Telegram message failed for ${email}: ${telegramError.message}`);
        res.status(200).json({
          message: 'Ссылка для сброса пароля не отправлена в Telegram. Убедитесь, что вы отправили /start боту, или свяжитесь с поддержкой.',
          email,
        });
      }
    } catch (error) {
      logger.error(`Forgot password error: ${error.message}`);
      res.status(500).json({ message: 'Ошибка сервера' });
    }
  }
);

// Reset password
app.post('/api/auth/reset-password/:token',
  [
    body('password').isLength({ min: 8 }),
    body('confirmPassword').custom((value, { req }) => value === req.body.password),
  ],
  async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ message: 'Ошибка валидации', errors: errors.array() });
    }

    try {
      const { token } = req.params;
      const { password } = req.body;

      let decoded;
      try {
        decoded = jwt.verify(token, 'your_jwt_secret');
      } catch (error) {
        logger.warn(`Invalid reset token: ${error.message}`);
        return res.status(400).json({ message: 'Недействительный или истекший токен' });
      }

      const user = await User.findOne({
        where: {
          email: decoded.email,
          resetPasswordToken: token,
          resetPasswordExpires: { [Sequelize.Op.gt]: new Date() },
        },
      });
      if (!user) {
        return res.status(400).json({ message: 'Недействительный токен или срок действия истек' });
      }

      const salt = await bcrypt.genSalt(10);
      user.password = await bcrypt.hash(password, salt);
      user.resetPasswordToken = null;
      user.resetPasswordExpires = null;
      await user.save();

      logger.info(`Password reset for ${user.email}`);
      res.status(200).json({ message: 'Пароль успешно сброшен' });
    } catch (error) {
      logger.error(`Reset password error: ${error.message}`);
      res.status(500).json({ message: 'Ошибка сервера' });
    }
  }
);

// Get user profile
app.get('/api/user/profile', authenticateToken, async (req, res) => {
  try {
    const user = await User.findByPk(req.user.id, {
      attributes: { exclude: ['password', 'verificationToken', 'resetPasswordToken', 'resetPasswordExpires'] },
    });
    if (!user) {
      return res.status(404).json({ message: 'Пользователь не найден' });
    }
    res.status(200).json(user);
  } catch (error) {
    logger.error(`Profile error: ${error.message}`);
    res.status(500).json({ message: 'Ошибка сервера' });
  }
});

// Update documents
app.post('/api/user/documents',
  authenticateToken,
  upload.array('documents', 3),
  async (req, res) => {
    try {
      const user = await User.findByPk(req.user.id);
      if (!user) {
        return res.status(404).json({ message: 'Пользователь не найден' });
      }

      if (!req.files || req.files.length === 0) {
        return res.status(400).json({ message: 'Требуется хотя бы один документ' });
      }

      const newDocuments = req.files.map(file => file.path);
      user.documents = [...user.documents, ...newDocuments].slice(0, 3); // Max 3 documents
      await user.save();

      logger.info(`Documents updated for user ${user.email}`);
      res.status(200).json({ message: 'Документы успешно обновлены', documents: user.documents });
    } catch (error) {
      logger.error(`Document update error: ${error.message}`);
      res.status(500).json({ message: 'Ошибка сервера' });
    }
  }
);

// Error handling middleware
app.use((err, req, res, next) => {
  logger.error(`Unhandled error: ${err.message}`);
  if (err instanceof multer.MulterError) {
    return res.status(400).json({ message: 'Ошибка загрузки файла: ' + err.message });
  }
  res.status(500).json({ message: 'Ошибка сервера' });
});

// Start server
const PORT = 5000;
app.listen(PORT, () => {
  logger.info(`Server running on port ${PORT}`);
});