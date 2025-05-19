// Подключение модулей
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
const fs = require('fs').promises;

// Инициализация приложения
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
app.use(helmet()); // Защита от уязвимостей
app.use(cors({
  origin: '*', // В продакшене замените на конкретный домен
  methods: ['GET', 'POST', 'PUT', 'DELETE'],
  allowedHeaders: ['Content-Type', 'Authorization'],
}));
app.use(express.json());
app.use('/uploads', express.static(path.join(__dirname, 'Uploads'), {
  setHeaders: (res) => {
    res.set('Access-Control-Allow-Origin', '*');
  }
}));

// Создание директорий для загрузки
const ensureDirectories = async () => {
  const dirs = [
    path.join(__dirname, 'Uploads/documents'),
    path.join(__dirname, 'Uploads/icons'),
    path.join(__dirname, 'Uploads/apks'),
  ];
  for (const dir of dirs) {
    try {
      await fs.mkdir(dir, { recursive: true });
      await fs.chmod(dir, 0o755);
      logger.info(`Создана директория: ${dir}`);
    } catch (error) {
      logger.error(`Ошибка создания директории ${dir}: ${error.message}`);
    }
  }
};
ensureDirectories();

// Подключение к базе данных
const sequelize = new Sequelize({
  dialect: 'mysql',
  host: process.env.DB_HOST || 'vh438.timeweb.ru',
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
  jwtToken: {
    type: DataTypes.STRING,
    allowNull: true,
  },
}, {
  timestamps: true,
  tableName: 'Users',
});

// Модель предрегистрации
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

// Модель маппинга Telegram
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

// Модель приложения
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
  downloads: {
    type: DataTypes.INTEGER,
    defaultValue: 0,
  },
}, {
  timestamps: true,
  tableName: 'Apps',
});

// Настройка загрузки файлов
const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    if (file.fieldname === 'documents') {
      cb(null, './Uploads/documents/');
    } else if (file.fieldname === 'icon') {
      cb(null, './Uploads/icons/');
    } else if (file.fieldname === 'apk') {
      cb(null, './Uploads/apks/');
    } else {
      cb(new Error('Недопустимое имя поля'), null);
    }
  },
  filename: (req, file, cb) => {
    const sanitizedName = path.basename(file.originalname, path.extname(file.originalname)).replace(/[^a-zA-Z0-9]/g, '_');
    cb(null, `${Date.now()}-${sanitizedName}${path.extname(file.originalname)}`);
  },
});

const upload = multer({
  storage,
  limits: { fileSize: 100 * 1024 * 1024 }, // 100 МБ для APK
  fileFilter: (req, file, cb) => {
    if (file.fieldname === 'documents') {
      const filetypes = /pdf|jpg|jpeg|png/;
      const extname = filetypes.test(path.extname(file.originalname).toLowerCase());
      const mimetype = filetypes.test(file.mimetype);
      if (extname && mimetype) {
        return cb(null, true);
      }
      cb(new Error('Для документов разрешены только PDF, JPG, JPEG и PNG!'));
    } else if (file.fieldname === 'icon') {
      const filetypes = /jpg|jpeg|png/;
      const extname = filetypes.test(path.extname(file.originalname).toLowerCase());
      const mimetype = filetypes.test(file.mimetype);
      if (extname && mimetype) {
        return cb(null, true);
      }
      cb(new Error('Для иконок разрешены только JPG, JPEG и PNG!'));
    } else if (file.fieldname === 'apk') {
      if (file.originalname.toLowerCase().endsWith('.apk') && file.mimetype === 'application/vnd.android.package-archive') {
        return cb(null, true);
      }
      cb(new Error('Разрешены только APK файлы с правильным MIME-типом!'));
    } else {
      cb(new Error('Недопустимое имя поля!'));
    }
  },
}).fields([
  { name: 'icon', maxCount: 1 },
  { name: 'apk', maxCount: 1 },
  { name: 'documents', maxCount: 3 },
]);

// Настройка Telegram-бота
const TELEGRAM_BOT_TOKEN = process.env.TELEGRAM_BOT_TOKEN || '7597915834:AAFzMDAKOc5UgcuAXWYdXy4V0Hj4qXL0KeY';
let bot;
try {
  bot = new TelegramBot(TELEGRAM_BOT_TOKEN, {
    polling: {
      interval: 300,
      autoStart: true,
      params: { timeout: 10 },
    },
  });
  logger.info('Telegram-бот инициализирован');
} catch (error) {
  logger.error(`Ошибка инициализации Telegram-бота: ${error.message}`);
}

// Обработка команды /start
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
      `🌟 Добро пожаловать в PlayEvit!\nВаш Telegram chat ID: ${chatId}\nИспользуйте этот ID или имя (@${username}) при регистрации.\nУведомления будут здесь!`
    );
    logger.info(`Зарегистрирован chat ID ${chatId} для @${username}`);
  } catch (error) {
    logger.error(`Ошибка сохранения маппинга для chat ID ${chatId}: ${error.message}`);
    await bot.sendMessage(chatId, 'Ошибка сохранения chat ID. Попробуйте снова или обратитесь в поддержку.');
  }
});

// Разрешение Telegram ID
async function resolveTelegramId(telegramId) {
  if (!telegramId) {
    throw new Error('Требуется Telegram ID');
  }
  if (/^\d+$/.test(telegramId)) {
    const mapping = await TelegramMapping.findOne({ where: { chatId: telegramId } });
    if (!mapping) {
      throw new Error(`Chat ID ${telegramId} не найден. Отправьте /start боту.`);
    }
    return telegramId;
  }
  const username = telegramId.startsWith('@') ? telegramId : `@${telegramId}`;
  const mapping = await TelegramMapping.findOne({ where: { username } });
  if (!mapping) {
    throw new Error(`Имя ${telegramId} не найдено. Отправьте /start боту.`);
  }
  return mapping.chatId;
}

// Отправка сообщения в Telegram
async function sendTelegramMessage(telegramId, message) {
  if (!bot) {
    logger.warn('Telegram-бот не инициализирован, пропуск отправки');
    return;
  }
  try {
    const chatId = await resolveTelegramId(telegramId);
    await bot.sendMessage(chatId, message);
    logger.info(`Сообщение отправлено на chat ID ${chatId}`);
  } catch (error) {
    logger.error(`Ошибка отправки сообщения на Telegram ID ${telegramId}: ${error.message}`);
  }
}

// Отправка верификационного сообщения
async function sendVerificationTelegram(telegramId, email, token) {
  if (!bot) {
    logger.warn('Telegram-бот не инициализирован, пропуск верификации');
    return;
  }
  try {
    const chatId = await resolveTelegramId(telegramId);
    const verificationUrl = `https://vasyaproger-my-backend-9f42.twc1.net/api/auth/verify/${token}`;
    const message = `
🌟 Добро пожаловать в PlayEvit, ${telegramId}! 🌟
Подтвердите email (${email}) по ссылке:
${verificationUrl}
Или используйте токен в форме на сайте:
Токен: ${token}
🔗 Токен действителен 100 лет.
`;
    await bot.sendMessage(chatId, message);
    logger.info(`Верификационное сообщение отправлено на chat ID ${chatId}`);
  } catch (error) {
    logger.error(`Ошибка отправки верификации на Telegram ID ${telegramId}: ${error.message}`);
  }
}

// Отправка сообщения для сброса пароля
async function sendPasswordResetTelegram(telegramId, token) {
  if (!bot) {
    logger.warn('Telegram-бот не инициализирован, пропуск сброса пароля');
    return;
  }
  try {
    const chatId = await resolveTelegramId(telegramId);
    const resetUrl = `https://vasyaproger-my-backend-9f42.twc1.net/reset-password/${token}`;
    const message = `
🔐 Сброс пароля для PlayEvit 🔐
Вы запросили сброс пароля. Перейдите по ссылке:
${resetUrl}
🔗 Ссылка действительна 1 час.
Если не запрашивали, проигнорируйте.
`;
    await bot.sendMessage(chatId, message);
    logger.info(`Сообщение сброса пароля отправлено на chat ID ${chatId}`);
  } catch (error) {
    logger.error(`Ошибка отправки сброса пароля на Telegram ID ${telegramId}: ${error.message}`);
  }
}

// Middleware для проверки JWT
const authenticateToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];
  if (!token) {
    logger.warn('Отсутствует токен авторизации');
    return res.status(401).json({ message: 'Требуется токен авторизации' });
  }
  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET || 'your_jwt_secret');
    req.user = decoded;
    next();
  } catch (error) {
    logger.error(`Недействительный токен: ${error.message}`);
    return res.status(403).json({ message: 'Недействительный или истекший токен' });
  }
};

// Синхронизация базы данных
sequelize.sync({ alter: true }).then(() => {
  logger.info('База данных синхронизирована');
}).catch((error) => {
  logger.error(`Ошибка синхронизации базы данных: ${error.message}`);
});

// Маршруты

// Предрегистрация
app.post(
  '/api/pre-register',
  [
    body('email').isEmail().normalizeEmail().withMessage('Требуется действительный email'),
    body('telegramId').optional().trim().custom((value) => {
      if (!value || /^\d+$/.test(value) || /^@/.test(value)) {
        return true;
      }
      throw new Error('Telegram ID должен быть числовым или с @');
    }),
  ],
  async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      logger.warn(`Ошибки валидации: ${JSON.stringify(errors.array())}`);
      return res.status(400).json({ message: 'Ошибка валидации', errors: errors.array() });
    }

    try {
      const { email, telegramId } = req.body;
      const existingPreRegister = await PreRegister.findOne({ where: { email } });
      if (existingPreRegister) {
        return res.status(400).json({ message: 'Email уже в списке ожидания' });
      }

      const preRegister = await PreRegister.create({ email, telegramId });
      let message = `🌟 Спасибо за интерес к PlayEvit!\nВаш email (${email}) добавлен в список ожидания.\nУведомим о запуске в 2025!`;
      if (telegramId) {
        try {
          await sendTelegramMessage(telegramId, message);
        } catch (error) {
          message = 'Не удалось отправить сообщение в Telegram. Отправьте /start боту.';
        }
      }

      logger.info(`Предрегистрация: ${email}`);
      res.status(201).json({ message });
    } catch (error) {
      logger.error(`Ошибка предрегистрации: ${error.message}`);
      res.status(500).json({ message: 'Ошибка сервера', error: error.message });
    }
  }
);

// Регистрация пользователя
app.post(
  '/api/auth/register',
  upload,
  [
    body('email').isEmail().normalizeEmail().withMessage('Требуется действительный email'),
    body('password').isLength({ min: 8 }).withMessage('Пароль минимум 8 символов'),
    body('accountType').isIn(['individual', 'commercial']).withMessage('Недопустимый тип аккаунта'),
    body('name').notEmpty().trim().withMessage('Требуется имя'),
    body('phone').notEmpty().trim().withMessage('Требуется телефон'),
    body('telegramId').notEmpty().trim().custom((value) => {
      if (/^\d+$/.test(value) || /^@/.test(value)) {
        return true;
      }
      throw new Error('Telegram ID должен быть числовым или с @');
    }).withMessage('Недопустимый Telegram ID'),
  ],
  async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      logger.warn(`Ошибки валидации: ${JSON.stringify(errors.array())}`);
      return res.status(400).json({ message: 'Ошибка валидации', errors: errors.array() });
    }

    try {
      const {
        email, password, accountType, name, phone, telegramId,
        addressStreet, addressCity, addressCountry, addressPostalCode,
      } = req.body;

      if (!req.files || !req.files.documents || req.files.documents.length === 0) {
        logger.warn('Документы не загружены при регистрации');
        return res.status(400).json({ message: 'Требуется минимум один документ' });
      }

      const existingUser = await User.findOne({ where: { email } });
      if (existingUser) {
        return res.status(400).json({ message: 'Email уже зарегистрирован' });
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
        documents: req.files.documents.map(file => file.path),
        verificationToken,
        jwtToken: authToken,
      });

      try {
        await sendVerificationTelegram(telegramId, email, verificationToken);
        logger.info(`Пользователь зарегистрирован: ${email}`);
        res.status(201).json({
          message: `Регистрация успешна! Проверьте Telegram (${telegramId}) для верификации.`,
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
        logger.warn(`Сообщение Telegram не отправлено для ${email}: ${telegramError.message}`);
        res.status(201).json({
          message: `Регистрация успешна, но Telegram-сообщение не отправлено. Отправьте /start боту с ${telegramId}.`,
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
      logger.error(`Ошибка регистрации: ${error.message}`);
      res.status(500).json({ message: 'Ошибка сервера', error: error.message });
    }
  }
);

// Верификация email по ссылке
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

    const user = await User.findOne({ where: { email: decoded.email } });
    if (!user) {
      logger.warn(`Пользователь с email ${decoded.email} не найден`);
      return res.status(400).json({ message: 'Пользователь не найден' });
    }

    if (user.verificationToken !== token) {
      logger.warn(`Токен верификации не совпадает для ${decoded.email}`);
      return res.status(400).json({ message: 'Недействительный токен' });
    }

    if (user.isVerified) {
      return res.status(200).json({ message: 'Email уже верифицирован' });
    }

    user.isVerified = true;
    user.verificationToken = null;
    await user.save();

    try {
      await sendTelegramMessage(user.telegramId, `✅ Ваш email (${user.email}) верифицирован! Добро пожаловать в PlayEvit!`);
    } catch (telegramError) {
      logger.warn(`Не удалось отправить сообщение верификации для ${user.email}: ${telegramError.message}`);
    }

    logger.info(`Email верифицирован для ${user.email}`);
    res.status(200).json({ message: 'Email успешно верифицирован!' });
  } catch (error) {
    logger.error(`Ошибка верификации: ${error.message}`);
    res.status(500).json({ message: 'Ошибка сервера', error: error.message });
  }
});

// Верификация email через форму
app.post(
  '/api/auth/verify-form',
  [
    body('email').isEmail().normalizeEmail().withMessage('Требуется действительный email'),
    body('token').notEmpty().trim().withMessage('Требуется токен'),
  ],
  async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      logger.warn(`Ошибки валидации: ${JSON.stringify(errors.array())}`);
      return res.status(400).json({ message: 'Ошибка валидации', errors: errors.array() });
    }

    try {
      const { email, token } = req.body;
      let decoded;
      try {
        decoded = jwt.verify(token, process.env.JWT_SECRET || 'your_jwt_secret');
      } catch (error) {
        logger.warn(`Недействительный токен в форме: ${error.message}`);
        return res.status(400).json({ message: 'Недействительный или истекший токен' });
      }

      if (decoded.email !== email) {
        logger.warn(`Email ${email} не совпадает с токеном`);
        return res.status(400).json({ message: 'Токен не соответствует email' });
      }

      const user = await User.findOne({ where: { email } });
      if (!user) {
        logger.warn(`Пользователь с email ${email} не найден`);
        return res.status(400).json({ message: 'Пользователь не найден' });
      }

      if (user.verificationToken !== token) {
        logger.warn(`Токен верификации не совпадает для ${email}`);
        return res.status(400).json({ message: 'Недействительный токен' });
      }

      if (user.isVerified) {
        return res.status(200).json({ message: 'Email уже верифицирован' });
      }

      user.isVerified = true;
      user.verificationToken = null;
      await user.save();

      try {
        await sendTelegramMessage(user.telegramId, `✅ Ваш email (${user.email}) верифицирован! Добро пожаловать в PlayEvit!`);
      } catch (telegramError) {
        logger.warn(`Не удалось отправить сообщение верификации для ${user.email}: ${telegramError.message}`);
      }

      logger.info(`Email верифицирован через форму для ${user.email}`);
      res.status(200).json({ message: 'Email успешно верифицирован!' });
    } catch (error) {
      logger.error(`Ошибка верификации формы: ${error.message}`);
      res.status(500).json({ message: 'Ошибка сервера', error: error.message });
    }
  }
);

// Авторизация
app.post(
  '/api/auth/login',
  [
    body('email').isEmail().normalizeEmail().withMessage('Требуется действительный email'),
    body('password').notEmpty().withMessage('Требуется пароль'),
  ],
  async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      logger.warn(`Ошибки валидации: ${JSON.stringify(errors.array())}`);
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
        logger.warn(`Неверный пароль для ${email}`);
        return res.status(400).json({ message: 'Неверный email или пароль' });
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
        await sendTelegramMessage(user.telegramId, `🔐 Вы вошли в PlayEvit с email: ${user.email}`);
      } catch (telegramError) {
        logger.warn(`Не удалось отправить сообщение входа для ${user.email}: ${telegramError.message}`);
      }

      logger.info(`Пользователь вошел: ${user.email}`);
      res.status(200).json({
        token,
        user: {
          id: user.id,
          email: user.email,
          accountType: user.accountType,
          name: user.name,
          telegramId: user.telegramId,
          isVerified: user.isVerified,
        },
        message: 'Вход успешен',
      });
    } catch (error) {
      logger.error(`Ошибка входа: ${error.message}`);
      res.status(500).json({ message: 'Ошибка сервера', error: error.message });
    }
  }
);

// Запрос сброса пароля
app.post(
  '/api/auth/forgot-password',
  [body('email').isEmail().normalizeEmail().withMessage('Требуется действительный email')],
  async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      logger.warn(`Ошибки валидации: ${JSON.stringify(errors.array())}`);
      return res.status(400).json({ message: 'Ошибка валидации', errors: errors.array() });
    }

    try {
      const { email } = req.body;
      const user = await User.findOne({ where: { email } });
      if (!user) {
        logger.warn(`Попытка сброса пароля для несуществующего email: ${email}`);
        return res.status(404).json({ message: 'Пользователь с этим email не найден' });
      }

      const resetToken = jwt.sign(
        { email },
        process.env.JWT_SECRET || 'your_jwt_secret',
        { expiresIn: '1h' }
      );
      user.resetPasswordToken = resetToken;
      user.resetPasswordExpires = new Date(Date.now() + 3600000);
      await user.save();

      try {
        await sendPasswordResetTelegram(user.telegramId, resetToken);
        logger.info(`Запрос сброса пароля для ${user.email}`);
        res.status(200).json({ message: 'Ссылка для сброса пароля отправлена в Telegram' });
      } catch (telegramError) {
        logger.warn(`Сообщение сброса пароля не отправлено для ${user.email}: ${telegramError.message}`);
        res.status(200).json({
          message: 'Ссылка для сброса пароля не отправлена. Отправьте /start боту.',
          email,
        });
      }
    } catch (error) {
      logger.error(`Ошибка запроса сброса пароля: ${error.message}`);
      res.status(500).json({ message: 'Ошибка сервера', error: error.message });
    }
  }
);

// Сброс пароля
app.post(
  '/api/auth/reset-password/:token',
  [
    body('password').isLength({ min: 8 }).withMessage('Пароль минимум 8 символов'),
    body('confirmPassword').custom((value, { req }) => value === req.body.password).withMessage('Пароли не совпадают'),
  ],
  async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      logger.warn(`Ошибки валидации: ${JSON.stringify(errors.array())}`);
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
        logger.warn(`Недействительный токен сброса для ${decoded.email}`);
        return res.status(400).json({ message: 'Недействительный или истекший токен' });
      }

      const salt = await bcrypt.genSalt(10);
      user.password = await bcrypt.hash(password, salt);
      user.resetPasswordToken = null;
      user.resetPasswordExpires = null;
      user.jwtToken = null;
      await user.save();

      try {
        await sendTelegramMessage(user.telegramId, `🔑 Пароль сброшен для email: ${user.email}`);
      } catch (telegramError) {
        logger.warn(`Не удалось отправить сообщение сброса для ${user.email}: ${telegramError.message}`);
      }

      logger.info(`Пароль сброшен для ${user.email}`);
      res.status(200).json({ message: 'Пароль успешно сброшен' });
    } catch (error) {
      logger.error(`Ошибка сброса пароля: ${error.message}`);
      res.status(500).json({ message: 'Ошибка сервера', error: error.message });
    }
  }
);

// Получение профиля
app.get('/api/user/profile', authenticateToken, async (req, res) => {
  try {
    const user = await User.findByPk(req.user.id, {
      attributes: { exclude: ['password', 'verificationToken', 'resetPasswordToken', 'resetPasswordExpires', 'jwtToken'] },
    });
    if (!user) {
      logger.warn(`Пользователь не найден для ID: ${req.user.id}`);
      return res.status(404).json({ message: 'Пользователь не найден' });
    }
    res.status(200).json(user);
  } catch (error) {
    logger.error(`Ошибка получения профиля: ${error.message}`);
    res.status(500).json({ message: 'Ошибка сервера', error: error.message });
  }
});

// Обновление документов
app.post(
  '/api/user/documents',
  authenticateToken,
  upload,
  async (req, res) => {
    try {
      const user = await User.findByPk(req.user.id);
      if (!user) {
        logger.warn(`Пользователь не найден для ID: ${req.user.id}`);
        return res.status(404).json({ message: 'Пользователь не найден' });
      }

      if (!req.files || !req.files.documents || req.files.documents.length === 0) {
        logger.warn('Документы не загружены');
        return res.status(400).json({ message: 'Требуется минимум один документ' });
      }

      const newDocuments = req.files.documents.map(file => file.path);
      user.documents = [...user.documents, ...newDocuments].slice(0, 3);
      user.isVerified = true;
      await user.save();

      try {
        await sendTelegramMessage(user.telegramId, `📄 Документы обновлены для email: ${user.email}`);
      } catch (telegramError) {
        logger.warn(`Не удалось отправить сообщение обновления для ${user.email}: ${telegramError.message}`);
      }

      logger.info(`Документы обновлены для ${user.email}`);
      res.status(200).json({ message: 'Документы успешно обновлены', documents: user.documents });
    } catch (error) {
      logger.error(`Ошибка обновления документов: ${error.message}`);
      res.status(500).json({ message: 'Ошибка сервера', error: error.message });
    }
  }
);

// Создание приложения
app.post(
  '/api/apps/create',
  authenticateToken,
  upload,
  [
    body('name').notEmpty().trim().withMessage('Требуется название приложения'),
    body('description').notEmpty().trim().withMessage('Требуется описание'),
    body('category').isIn(['games', 'productivity', 'education', 'entertainment']).withMessage('Недопустимая категория: выберите games, productivity, education, entertainment'),
  ],
  async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      logger.warn(`Ошибки валидации: ${JSON.stringify(errors.array())}`);
      return res.status(400).json({ message: 'Ошибка валидации', errors: errors.array() });
    }

    try {
      const user = await User.findByPk(req.user.id);
      if (!user) {
        logger.warn(`Пользователь не найден для ID: ${req.user.id}`);
        return res.status(404).json({ message: 'Пользователь не найден' });
      }

      if (!user.isVerified) {
        logger.warn(`Пользователь не верифицирован: ${user.email}`);
        return res.status(403).json({ message: 'Требуется верифицированный аккаунт для отправки приложений' });
      }

      const { name, description, category } = req.body;
      const files = req.files;

      if (!files || !files.icon || !files.icon[0]) {
        logger.warn('Отсутствует файл иконки');
        return res.status(400).json({ message: 'Требуется иконка (JPG, JPEG или PNG)' });
      }
      if (!files.apk || !files.apk[0]) {
        logger.warn('Отсутствует файл APK');
        return res.status(400).json({ message: 'Требуется APK файл' });
      }

      const app = await App.create({
        name,
        description,
        category,
        iconPath: files.icon[0].path,
        apkPath: files.apk[0].path,
        userId: user.id,
        status: 'pending',
        downloads: 0,
      });

      try {
        await sendTelegramMessage(
          user.telegramId,
          `🚀 Приложение "${name}" отправлено на проверку! Уведомим, когда будет обработано.`
        );
      } catch (telegramError) {
        logger.warn(`Не удалось отправить сообщение подачи для ${user.email}: ${telegramError.message}`);
      }

      logger.info(`Приложение создано ${user.email}: ${name}`);
      res.status(201).json({ message: 'Приложение успешно отправлено', app });
    } catch (error) {
      logger.error(`Ошибка создания приложения: ${error.message}`);
      res.status(500).json({ message: 'Ошибка сервера', error: error.message });
    }
  }
);

// Обработка ошибок
app.use((err, req, res, next) => {
  logger.error(`Необработанная ошибка: ${err.message}`);
  if (err instanceof multer.MulterError) {
    logger.warn(`Ошибка Multer: ${err.message}`);
    return res.status(400).json({ message: `Ошибка загрузки файла: ${err.message}` });
  }
  if (err.message.includes('Only')) {
    logger.warn(`Ошибка типа файла: ${err.message}`);
    return res.status(400).json({ message: err.message });
  }
  res.status(500).json({ message: 'Ошибка сервера', error: err.message });
});

// Запуск сервера
const PORT = process.env.PORT || 5000;
app.listen(PORT, () => {
  logger.info(`Сервер запущен на порту ${PORT}`);
});