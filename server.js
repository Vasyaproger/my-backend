// Подключение необходимых модулей
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
const AWS = require('aws-sdk');

// Инициализация приложения Express
const app = express();

// Настройка логгера для записи логов
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

// Настройка AWS S3 для хранения файлов
const s3 = new AWS.S3({
  endpoint: 'https://s3.twcstorage.ru',
  accessKeyId: 'DN1NLZTORA2L6NZ529JJ',
  secretAccessKey: 'iGg3syd3UiWzhoYbYlEEDSVX1HHVmWUptrBt81Y8',
  region: 'ru-1',
  s3ForcePathStyle: true,
});

const BUCKET_NAME = '4eeafbc6-4af2cd44-4c23-4530-a2bf-750889dfdf75';

// Middleware для безопасности и обработки запросов
app.use(helmet()); // Защита от уязвимостей
app.use(cors({
  origin: ['https://24webstudio.ru', 'http://localhost:3000'], // Разрешенные домены
  methods: ['GET', 'POST', 'PUT', 'DELETE'],
  allowedHeaders: ['Content-Type', 'Authorization'],
}));
app.use(express.json()); // Парсинг JSON-запросов

// Подключение к базе данных MySQL
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

// Проверка подключения к базе данных
sequelize.authenticate()
  .then(() => logger.info('Подключение к базе данных успешно'))
  .catch((error) => logger.error(`Ошибка подключения к базе данных: ${error.message}`));

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
    allowNull: true,
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

// Настройка загрузки файлов с помощью Multer
const upload = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: 100 * 1024 * 1024 }, // Лимит 100 МБ
  fileFilter: (req, file, cb) => {
    if (file.fieldname === 'documents') {
      const validMimeTypes = ['application/pdf', 'image/jpeg', 'image/png', 'image/jpg'];
      const validExtensions = /\.(pdf|jpg|jpeg|png)$/i;
      const extname = validExtensions.test(path.extname(file.originalname).toLowerCase());
      const mimetype = validMimeTypes.includes(file.mimetype);
      if (extname && mimetype) {
        return cb(null, true);
      }
      logger.warn(`Недопустимый документ: имя=${file.originalname}, MIME=${file.mimetype}`);
      cb(new Error('Для документов разрешены только PDF, JPG, JPEG и PNG!'));
    } else if (file.fieldname === 'icon') {
      const validMimeTypes = ['image/jpeg', 'image/png', 'image/jpg'];
      const validExtensions = /\.(jpg|jpeg|png)$/i;
      const extname = validExtensions.test(path.extname(file.originalname).toLowerCase());
      const mimetype = validMimeTypes.includes(file.mimetype);
      if (extname && mimetype) {
        return cb(null, true);
      }
      logger.warn(`Недопустимая иконка: имя=${file.originalname}, MIME=${file.mimetype}`);
      cb(new Error('Для иконок разрешены только JPG, JPEG и PNG!'));
    } else if (file.fieldname === 'apk') {
      const extname = file.originalname.toLowerCase().endsWith('.apk');
      const mimetype = file.mimetype === 'application/vnd.android.package-archive';
      if (extname && mimetype) {
        return cb(null, true);
      }
      logger.warn(`Недопустимый APK: имя=${file.originalname}, MIME=${file.mimetype}`);
      cb(new Error('Разрешены только APK файлы с правильным MIME-типом!'));
    } else {
      logger.warn(`Недопустимое имя поля: ${file.fieldname}`);
      cb(new Error('Недопустимое имя поля!'));
    }
  },
}).fields([
  { name: 'icon', maxCount: 1 },
  { name: 'apk', maxCount: 1 },
  { name: 'documents', maxCount: 3 },
]);

// Функция загрузки файла в S3
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
    logger.info(`Файл загружен в S3: ${key}`);
    return Location;
  } catch (error) {
    logger.error(`Ошибка загрузки в S3: ${error.message}`);
    throw new Error(`Ошибка загрузки файла в S3: ${error.message}`);
  }
}

// Настройка Telegram-бота
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
  logger.info('Telegram-бот успешно инициализирован');
} catch (error) {
  logger.error(`Ошибка инициализации Telegram-бота: ${error.message}`);
  bot = null; // Устанавливаем null при ошибке
}

// Обработка команды /start для Telegram-бота
if (bot) {
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
        `🌟 Добро пожаловать в PlayEvit!\nВаш Telegram chat ID: ${chatId}\nИспользуйте этот ID или имя (@${username}) при регистрации.\nУведомления будут здесь!`
      );
      logger.info(`Зарегистрирован chat ID ${chatId} для @${username}`);
    } catch (error) {
      logger.error(`Ошибка сохранения маппинга для chat ID ${chatId}: ${error.message}`);
      await bot.sendMessage(chatId, 'Ошибка сохранения chat ID. Попробуйте снова или обратитесь в поддержку.');
    }
  });
}

// Разрешение Telegram ID
async function resolveTelegramId(telegramId) {
  if (!telegramId) {
    logger.warn('Telegram ID отсутствует, пропуск отправки');
    return null;
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
  if (!telegramId) {
    logger.warn('Telegram ID отсутствует, пропуск отправки');
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

// Отправка верификационного сообщения в Telegram
async function sendVerificationTelegram(telegramId, email, token) {
  if (!bot) {
    logger.warn('Telegram-бот не инициализирован, пропуск верификации');
    return;
  }
  if (!telegramId) {
    logger.warn('Telegram ID отсутствует, пропуск верификации');
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

// Отправка сообщения для сброса пароля в Telegram
async function sendPasswordResetTelegram(telegramId, token) {
  if (!bot) {
    logger.warn('Telegram-бот не инициализирован, пропуск сброса пароля');
    return;
  }
  if (!telegramId) {
    logger.warn('Telegram ID отсутствует, пропуск сброса пароля');
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

// Middleware для проверки JWT-токена
const authenticateToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];
  if (!token) {
    logger.warn('Отсутствует токен авторизации');
    return res.status(401).json({ message: 'Требуется токен авторизации' });
  }
  try {
    const decoded = jwt.verify(token, 'my_jwt_secret');
    req.user = decoded;
    next();
  } catch (error) {
    logger.error(`Ошибка верификации токена: ${error.message}`);
    if (error.name === 'TokenExpiredError') {
      return res.status(403).json({ message: 'Токен истек' });
    }
    return res.status(403).json({ message: 'Недействительный токен' });
  }
};

// Синхронизация базы данных
sequelize.sync({ alter: true })
  .then(() => logger.info('База данных успешно синхронизирована'))
  .catch((error) => logger.error(`Ошибка синхронизации базы данных: ${error.message}`));

// Маршруты API

// Предрегистрация пользователя
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
        await sendTelegramMessage(telegramId, message);
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

      const documentUrls = await Promise.all(
        req.files.documents.map(file => uploadToS3(file, 'documents'))
      );

      const salt = await bcrypt.genSalt(10);
      const hashedPassword = await bcrypt.hash(password, salt);
      const verificationToken = jwt.sign(
        { email },
        'my_jwt_secret',
        { expiresIn: '100y' }
      );

      const authToken = jwt.sign(
        { email, accountType, name, telegramId },
        'my_jwt_secret',
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

      if (telegramId) {
        await sendVerificationTelegram(telegramId, email, verificationToken);
      }

      logger.info(`Пользователь зарегистрирован: ${email}`);
      res.status(201).json({
        message: telegramId
          ? `Регистрация успешна! Проверьте Telegram (${telegramId}) для верификации.`
          : `Регистрация успешна! Проверьте email для верификации.`,
        token: authToken,
        user: {
          id: user.id,
          email: user.email,
          accountType: user.accountType,
          name: user.name,
          telegramId: user.telegramId,
        },
      });
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
      decoded = jwt.verify(token, 'my_jwt_secret');
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

    if (user.telegramId) {
      await sendTelegramMessage(user.telegramId, `✅ Ваш email (${user.email}) верифицирован! Добро пожаловать в PlayEvit!`);
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
        decoded = jwt.verify(token, 'my_jwt_secret');
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

      if (user.telegramId) {
        await sendTelegramMessage(user.telegramId, `✅ Ваш email (${user.email}) верифицирован! Добро пожаловать в PlayEvit!`);
      }

      logger.info(`Email верифицирован через форму для ${user.email}`);
      res.status(200).json({ message: 'Email успешно верифицирован!' });
    } catch (error) {
      logger.error(`Ошибка верификации формы: ${error.message}`);
      res.status(500).json({ message: 'Ошибка сервера', error: error.message });
    }
  }
);

// Авторизация пользователя
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
      logger.info(`Попытка входа для email: ${email}`);

      // Поиск пользователя
      const user = await User.findOne({ where: { email } });
      if (!user) {
        logger.warn(`Пользователь с email ${email} не найден`);
        return res.status(400).json({ message: 'Неверный email или пароль' });
      }

      // Проверка пароля
      if (!user.password) {
        logger.error(`Пароль отсутствует для пользователя ${email}`);
        return res.status(500).json({ message: 'Ошибка сервера: пользовательская запись повреждена' });
      }
      const isMatch = await bcrypt.compare(password, user.password);
      if (!isMatch) {
        logger.warn(`Неверный пароль для ${email}`);
        return res.status(400).json({ message: 'Неверный email или пароль' });
      }

      // Проверка существующего токена
      let token = user.jwtToken;
      if (!token || !isValidJwt(token)) {
        token = jwt.sign(
          { id: user.id, email: user.email },
          'my_jwt_secret',
          { expiresIn: '7d' }
        );
        user.jwtToken = token;
        try {
          await user.save();
          logger.info(`Новый JWT токен сохранен для ${email}`);
        } catch (saveError) {
          logger.error(`Ошибка сохранения токена для ${email}: ${saveError.message}`);
          return res.status(500).json({ message: 'Ошибка сервера при сохранении токена' });
        }
      }

      // Отправка сообщения в Telegram
      let message = `🔐 Вы вошли в PlayEvit с email: ${user.email}`;
      if (!user.telegramId) {
        message = 'Ваш Telegram ID отсутствует. Отправьте /start боту и обновите профиль в настройках.';
      } else {
        try {
          await sendTelegramMessage(user.telegramId, message);
        } catch (telegramError) {
          logger.warn(`Ошибка отправки Telegram сообщения для ${email}: ${telegramError.message}`);
          message += ' (Не удалось отправить уведомление в Telegram)';
        }
      }

      logger.info(`Пользователь успешно вошел: ${email}`);
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
        message,
      });
    } catch (error) {
      logger.error(`Ошибка входа для ${req.body.email}: ${error.message}`);
      res.status(500).json({ message: 'Ошибка сервера', error: error.message });
    }
  }
);

// Вспомогательная функция для проверки JWT
function isValidJwt(token) {
  try {
    jwt.verify(token, 'my_jwt_secret', { ignoreExpiration: true });
    return true;
  } catch (error) {
    logger.warn(`Недействительный JWT токен: ${error.message}`);
    return false;
  }
}

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
        'my_jwt_secret',
        { expiresIn: '1h' }
      );
      user.resetPasswordToken = resetToken;
      user.resetPasswordExpires = new Date(Date.now() + 3600000); // 1 час
      await user.save();

      if (user.telegramId) {
        await sendPasswordResetTelegram(user.telegramId, resetToken);
        logger.info(`Запрос сброса пароля для ${user.email}`);
        res.status(200).json({ message: 'Ссылка для сброса пароля отправлена в Telegram' });
      } else {
        logger.warn(`Telegram ID отсутствует для ${user.email}`);
        res.status(200).json({
          message: 'Ссылка для сброса пароля не отправлена. Обновите Telegram ID в профиле.',
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
        decoded = jwt.verify(token, 'my_jwt_secret');
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

      if (user.telegramId) {
        await sendTelegramMessage(user.telegramId, `🔑 Пароль сброшен для email: ${user.email}`);
      }

      logger.info(`Пароль сброшен для ${user.email}`);
      res.status(200).json({ message: 'Пароль успешно сброшен' });
    } catch (error) {
      logger.error(`Ошибка сброса пароля: ${error.message}`);
      res.status(500).json({ message: 'Ошибка сервера', error: error.message });
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
      logger.warn(`Пользователь не найден для ID: ${req.user.id}`);
      return res.status(404).json({ message: 'Пользователь не найден' });
    }
    res.status(200).json(user);
  } catch (error) {
    logger.error(`Ошибка получения профиля: ${error.message}`);
    res.status(500).json({ message: 'Ошибка сервера', error: error.message });
  }
});

// Обновление профиля пользователя
app.put(
  '/api/user/profile',
  authenticateToken,
  [
    body('name').notEmpty().trim().withMessage('Требуется имя'),
    body('email').isEmail().normalizeEmail().withMessage('Требуется действительный email'),
    body('telegramId').optional().trim().custom((value) => {
      if (!value || /^\d+$/.test(value) || /^@/.test(value)) {
        return true;
      }
      throw new Error('Telegram ID должен быть числовым или с @');
    }),
    body('password').optional().isLength({ min: 8 }).withMessage('Пароль минимум 8 символов'),
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

      const { name, email, telegramId, password } = req.body;
      user.name = name;
      user.email = email;
      user.telegramId = telegramId || null;
      if (password) {
        const salt = await bcrypt.genSalt(10);
        user.password = await bcrypt.hash(password, salt);
      }
      await user.save();

      if (telegramId) {
        await sendTelegramMessage(telegramId, `📝 Ваш профиль обновлен: ${user.email}`);
      }

      logger.info(`Профиль обновлен для ${user.email}`);
      res.status(200).json({
        id: user.id,
        name: user.name,
        email: user.email,
        telegramId: user.telegramId,
      });
    } catch (error) {
      logger.error(`Ошибка обновления профиля: ${error.message}`);
      res.status(500).json({ message: 'Ошибка сервера', error: error.message });
    }
  }
);

// Обновление документов пользователя
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

      const newDocuments = await Promise.all(
        req.files.documents.map(file => uploadToS3(file, 'documents'))
      );

      user.documents = [...user.documents, ...newDocuments].slice(0, 3);
      user.isVerified = true;
      await user.save();

      if (user.telegramId) {
        await sendTelegramMessage(user.telegramId, `📄 Документы обновлены для email: ${user.email}`);
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
    body('category').isIn(['games', 'productivity', 'education', 'entertainment']).withMessage('Недопустимая категория'),
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
        downloads: 0,
      });

      if (user.telegramId) {
        await sendTelegramMessage(
          user.telegramId,
          `🚀 Приложение "${name}" отправлено на проверку! Уведомим, когда будет обработано.`
        );
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
const PORT = 5000;
app.listen(PORT, () => {
  logger.info(`Сервер запущен на порту ${PORT}`);
});