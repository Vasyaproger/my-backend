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

// Настройка логгера
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

// Настройка подключения к MySQL
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

// Модель пользователя
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
  jwtToken: { // New field for storing JWT token
    type: DataTypes.STRING,
    allowNull: true,
  },
}, {
  timestamps: true,
  tableName: 'Users',
});

// Модель для Telegram маппинга
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

// Настройка загрузки файлов
const storage = multer.diskStorage({
  destination: './Uploads/documents/',
  filename: (req, file, cb) => {
    const sanitizedName = path.basename(file.originalname, path.extname(file.originalname)).replace(/[^a-zA-Z0-9]/g, '_');
    cb(null, `${Date.now()}-${sanitizedName}${path.extname(file.originalname)}`);
  },
});
const upload = multer({
  storage,
  limits: { fileSize: 5 * 1024 * 1024 },
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

// Настройка Telegram бота
const TELEGRAM_BOT_TOKEN = process.env.TELEGRAM_BOT_TOKEN || '7597915834:AAFzMDAKOc5UgcuAXWYdXy4V0Hj4qXL0KeY';
const bot = new TelegramBot(TELEGRAM_BOT_TOKEN, {
  polling: {
    interval: 300,
    autoStart: true,
    params: { timeout: 10 },
  },
});

// Обработка команды /start
bot.onText(/\/start/, async (msg) => {
  const chatId = msg.chat.id;
  const username = msg.from.username || `user_${chatId}`;
  try {
    await TelegramMapping.upsert({
      username: `@${username.replace(/^@/, '')}`,
      chatId: chatId.toString(),
    });
    await bot.sendMessage(chatId, `Ваш Telegram chat ID: ${chatId}\nИспользуйте этот ID при регистрации в PlayEvit.`);
    logger.info(`Захвачен chat ID ${chatId} для username @${username}`);
  } catch (error) {
    logger.error(`Ошибка сохранения маппинга Telegram для chat ID ${chatId}: ${error.message}`);
    await bot.sendMessage(chatId, 'Ошибка при сохранении вашего chat ID. Попробуйте снова или свяжитесь с поддержкой.');
  }
});

// Функция преобразования Telegram ID
async function resolveTelegramId(telegramId) {
  if (/^\d+$/.test(telegramId)) {
    return telegramId;
  }
  const mapping = await TelegramMapping.findOne({ where: { username: telegramId } });
  if (!mapping) {
    throw new Error(`Chat ID не найден для username ${telegramId}. Пользователь должен отправить /start боту.`);
  }
  return mapping.chatId;
}

// Отправка верификационного сообщения
async function sendVerificationTelegram(telegramId, token) {
  try {
    const chatId = await resolveTelegramId(telegramId);
    const verificationUrl = `https://vasyaproger-my-backend-9f42.twc1.net/api/auth/verify/${token}`;
    const message = `
🌟 Добро пожаловать в PlayEvit! 🌟
Подтвердите ваш email по ссылке:
${verificationUrl}
🔗 Ссылка действительна 24 часа.
`;
    logger.info(`Попытка отправки верификационного сообщения на chat ID ${chatId}`);
    await bot.sendMessage(chatId, message);
    logger.info(`Верификационное сообщение отправлено на chat ID ${chatId}`);
  } catch (error) {
    logger.error(`Ошибка отправки верификационного сообщения на Telegram ID ${telegramId}: ${error.message}`);
    throw error;
  }
}

// Отправка сообщения сброса пароля
async function sendPasswordResetTelegram(telegramId, token) {
  try {
    const chatId = await resolveTelegramId(telegramId);
    const resetUrl = `https://vasyaproger-my-backend-9f42.twc1.net/reset-password/${token}`;
    const message = `
🔐 Сброс пароля в PlayEvit 🔐
Вы запросили сброс пароля. Перейдите по ссылке:
${resetUrl}
🔗 Ссылка действительна 1 час.
Если не запрашивали, проигнорируйте.
`;
    logger.info(`Попытка отправки сообщения сброса пароля на chat ID ${chatId}`);
    await bot.sendMessage(chatId, message);
    logger.info(`Сообщение сброса пароля отправлено на chat ID ${chatId}`);
  } catch (error) {
    logger.error(`Ошибка отправки сообщения сброса пароля на Telegram ID ${telegramId}: ${error.message}`);
    throw error;
  }
}

// Middleware для проверки JWT токена
const authenticateToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];
  if (!token) {
    return res.status(401).json({ message: 'Требуется токен авторизации' });
  }
  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET || 'your_jwt_secret');
    req.user = decoded;
    next();
  } catch (error) {
    logger.error(`Недействительный токен: ${error.message}`);
    return res.status(403).json({ message: 'Недействительный токен' });
  }
};

// Синхронизация базы данных
sequelize.sync({ alter: true }).then(() => {
  logger.info('База данных синхронизирована');
}).catch((error) => {
  logger.error(`Ошибка синхронизации базы данных: ${error.message}`);
});

// Маршруты

// Регистрация пользователя
app.post('/api/auth/register',
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
      throw new Error('Telegram ID должен быть числовым chat ID или username с @');
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
      const verificationToken = jwt.sign({ email }, process.env.JWT_SECRET || 'your_jwt_secret', { expiresIn: '1d' });
      
      // Generate JWT token for authentication
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
        jwtToken: authToken, // Store the token in the database
      });

      try {
        await sendVerificationTelegram(telegramId, verificationToken);
        logger.info(`Пользователь зарегистрирован: ${email}`);
        res.status(201).json({
          message: 'Регистрация успешна! Проверьте Telegram для подтверждения.',
          token: authToken, // Return the token to the client
          user: {
            id: user.id,
            email: user.email,
            accountType: user.accountType,
            name: user.name,
            telegramId: user.telegramId,
          }
        });
      } catch (telegramError) {
        logger.warn(`Пользователь зарегистрирован, но сообщение в Telegram не отправлено для ${email}: ${telegramError.message}`);
        res.status(201).json({
          message: 'Регистрация успешна, но сообщение в Telegram не отправлено. Убедитесь, что вы отправили /start боту.',
          token: authToken,
          email,
          user: {
            id: user.id,
            email: user.email,
            accountType: user.accountType,
            name: user.name,
            telegramId: user.telegramId,
          }
        });
      }
    } catch (error) {
      logger.error(`Ошибка регистрации: ${error.message}`);
      res.status(500).json({ message: 'Ошибка сервера' });
    }
  }
);

// Верификация email
app.get('/api/auth/verify/:token', async (req, res) => {
  try {
    const { token } = req.params;
    let decoded;
    try {
      decoded = jwt.verify(token, process.env.JWT_SECRET || 'your_jwt_secret');
    } catch (error) {
      logger.warn(`Недействительный токен верификации: ${error.message}`);
      return res.status(400).json({ message: 'Недействительный или истекший токен' });
    }

    const user = await User.findOne({ where: { email: decoded.email, verificationToken: token } });
    if (!user) {
      return res.status(400).json({ message: 'Пользователь не найден или токен недействителен' });
    }

    user.isVerified = true;
    user.verificationToken = null;
    await user.save();

    logger.info(`Email верифицирован для ${user.email}`);
    res.status(200).json({ message: 'Email успешно подтвержден!' });
  } catch (error) {
    logger.error(`Ошибка верификации: ${error.message}`);
    res.status(500).json({ message: 'Ошибка сервера' });
  }
});

// Вход в систему
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
        logger.warn(`Попытка входа с несуществующим email: ${email}`);
        return res.status(400).json({ message: 'Неверный email или пароль' });
      }

      const isMatch = await bcrypt.compare(password, user.password);
      if (!isMatch) {
        logger.warn(`Неверный пароль для email: ${email}`);
        return res.status(400).json({ message: 'Неверный email или пароль' });
      }

      if (!user.isVerified) {
        return res.status(400).json({ message: 'Подтвердите ваш email через Telegram перед входом' });
      }

      // Use existing token if available, or generate new one
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

      logger.info(`Пользователь вошел: ${email}`);
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
      logger.error(`Ошибка входа: ${error.message}`);
      res.status(500).json({ message: 'Ошибка сервера' });
    }
  }
);

// Запрос сброса пароля
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

      const resetToken = jwt.sign({ email }, process.env.JWT_SECRET || 'your_jwt_secret', { expiresIn: '1h' });
      user.resetPasswordToken = resetToken;
      user.resetPasswordExpires = new Date(Date.now() + 3600000);
      await user.save();

      try {
        await sendPasswordResetTelegram(user.telegramId, resetToken);
        logger.info(`Запрос сброса пароля для ${email}`);
        res.status(200).json({ message: 'Ссылка для сброса пароля отправлена в Telegram' });
      } catch (telegramError) {
        logger.warn(`Сообщение сброса пароля в Telegram не отправлено для ${email}: ${telegramError.message}`);
        res.status(200).json({
          message: 'Ссылка для сброса пароля не отправлена в Telegram. Убедитесь, что вы отправили /start боту.',
          email,
        });
      }
    } catch (error) {
      logger.error(`Ошибка запроса сброса пароля: ${error.message}`);
      res.status(500).json({ message: 'Ошибка сервера' });
    }
  }
);

// Сброс пароля
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
        decoded = jwt.verify(token, process.env.JWT_SECRET || 'your_jwt_secret');
      } catch (error) {
        logger.warn(`Недействительный токен сброса: ${error.message}`);
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
      user.jwtToken = null; // Invalidate existing token on password reset
      await user.save();

      logger.info(`Пароль сброшен для ${user.email}`);
      res.status(200).json({ message: 'Пароль успешно сброшен' });
    } catch (error) {
      logger.error(`Ошибка сброса пароля: ${error.message}`);
      res.status(500).json({ message: 'Ошибка сервера' });
    }
  }
);

// Получение профиля пользователя
app.get('/api/user/profile', authenticateToken, async (req, res) => {
  try {
    const user = await User.findByPk(req.user.id, {
      attributes: { exclude: ['password', 'verificationToken', 'resetPasswordToken', 'resetPasswordExpires', 'jwtToken'] },
    });
    if (!user) {
      return res.status(404).json({ message: 'Пользователь не найден' });
    }
    res.status(200).json(user);
  } catch (error) {
    logger.error(`Ошибка получения профиля: ${error.message}`);
    res.status(500).json({ message: 'Ошибка сервера' });
  }
});

// Обновление документов
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
      user.documents = [...user.documents, ...newDocuments].slice(0, 3);
      await user.save();

      logger.info(`Документы обновлены для пользователя ${user.email}`);
      res.status(200).json({ message: 'Документы успешно обновлены', documents: user.documents });
    } catch (error) {
      logger.error(`Ошибка обновления документов: ${error.message}`);
      res.status(500).json({ message: 'Ошибка сервера' });
    }
  }
);

// Обработка ошибок
app.use((err, req, res, next) => {
  logger.error(`Необработанная ошибка: ${err.message}`);
  if (err instanceof multer.MulterError) {
    return res.status(400).json({ message: 'Ошибка загрузки файла: ' + err.message });
  }
  res.status(500).json({ message: 'Ошибка сервера' });
});

// Запуск сервера
const PORT = process.env.PORT || 5000;
app.listen(PORT, () => {
  logger.info(`Сервер запущен на порту ${PORT}`);
});