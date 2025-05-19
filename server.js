const express = require('express');
const { Sequelize, DataTypes } = require('sequelize');
const mysql = require('mysql');
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

// Переменные окружения для секретных данных
const JWT_SECRET = process.env.JWT_SECRET || 'your_secure_random_string_32_chars'; // Секрет для JWT
const DB_HOST = process.env.DB_HOST || 'vh438.timeweb.ru'; // Хост базы данных
const DB_USER = process.env.DB_USER || 'ch79145_project'; // Пользователь базы данных
const DB_PASSWORD = process.env.DB_PASSWORD || 'Vasya11091109'; // Пароль базы данных
const DB_NAME = process.env.DB_NAME || 'ch79145_project'; // Имя базы данных
const S3_ACCESS_KEY = process.env.S3_ACCESS_KEY || 'DN1NLZTORA2L6NZ529JJ'; // Ключ S3
const S3_SECRET_KEY = process.env.S3_SECRET_KEY || 'iGg3syd3UiWzhoYbYlEEDSVX1HHVmWUptrBt81Y8'; // Секретный ключ S3
const TELEGRAM_BOT_TOKEN = process.env.TELEGRAM_BOT_TOKEN || '7597915834:AAFzMDAKOc5UgcuAXWYdXy4V0Hj4qXL0KeY'; // Токен Telegram-бота

// Настройка логирования
const logger = winston.createLogger({
  level: 'info',
  format: winston.format.combine(
    winston.format.timestamp(),
    winston.format.json()
  ),
  transports: [
    new winston.transports.File({ filename: 'error.log', level: 'error' }), // Логи ошибок
    new winston.transports.File({ filename: 'combined.log' }), // Все логи
    new winston.transports.Console(), // Вывод в консоль
  ],
});

// Настройка AWS S3
const s3 = new AWS.S3({
  endpoint: 'https://s3.twcstorage.ru',
  accessKeyId: S3_ACCESS_KEY,
  secretAccessKey: S3_SECRET_KEY,
  region: 'ru-1',
  s3ForcePathStyle: true,
  httpOptions: { timeout: 30000 },
});

const BUCKET_NAME = '4eeafbc6-4af2cd44-4c23-4530-a2bf-750889dfdf75'; // Имя бакета S3

// Проверка подключения к S3
s3.listBuckets((err) => {
  if (err) {
    logger.error(`Ошибка подключения к S3: ${err.message}`);
  } else {
    logger.info('Подключение к S3 успешно');
  }
});

// Промежуточные слои (middleware)
app.use(helmet()); // Защита от уязвимостей
app.use(cors({
  origin: '*',
  methods: ['GET', 'POST', 'PUT', 'DELETE'],
  allowedHeaders: ['Content-Type', 'Authorization'],
}));
app.use(express.json()); // Парсинг JSON

// Подключение к базе данных
const sequelize = new Sequelize({
  dialect: 'mysql',
  host: DB_HOST,
  username: DB_USER,
  password: DB_PASSWORD,
  database: DB_NAME,
  port: 3306,
  dialectModule: mysql, // Используем mysql вместо mysql2
  logging: (msg) => logger.debug(msg),
  pool: {
    max: 2, // Максимум 2 соединения
    min: 0,
    acquire: 30000,
    idle: 10000,
  },
});

// Механизм повторного подключения к базе данных
async function connectWithRetry(maxRetries = 5, retryDelay = 20000) {
  logger.info('Начало попыток подключения к MySQL');
  for (let attempt = 1; attempt <= maxRetries; attempt++) {
    try {
      await sequelize.authenticate();
      logger.info('Подключение к базе данных успешно');
      return;
    } catch (error) {
      logger.error(`Попытка ${attempt} не удалась: ${error.message}`);
      if (error.message.includes('Host') && error.message.includes('blocked')) {
        logger.error('Хост заблокирован MySQL. Выполните "mysqladmin flush-hosts" на сервере.');
      }
      if (attempt === maxRetries) {
        logger.error('Не удалось подключиться к базе данных после всех попыток');
        throw new Error('Не удалось подключиться к базе данных');
      }
      logger.info(`Повторная попытка через ${retryDelay / 1000} секунд...`);
      await new Promise(resolve => setTimeout(resolve, retryDelay));
    }
  }
}

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

// Модель предварительной регистрации
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

// Модель соответствия Telegram
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
}, {
  timestamps: true,
  tableName: 'Apps',
});

// Настройка загрузки файлов
const upload = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: 10 * 1024 * 1024 }, // Максимум 10 МБ
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
      cb(new Error('Разрешены только файлы PDF, JPG, JPEG и PNG для документов!'));
    } else if (file.fieldname === 'icon') {
      const validMimeTypes = ['image/jpeg', 'image/png', 'image/jpg'];
      const validExtensions = /\.(jpg|jpeg|png)$/i;
      const extname = validExtensions.test(path.extname(file.originalname).toLowerCase());
      const mimetype = validMimeTypes.includes(file.mimetype);
      if (extname && mimetype) {
        return cb(null, true);
      }
     logger.warn(`Недопустимая иконка: имя=${file.originalname}, MIME=${file.mimetype}`);
      cb(new Error('Разрешены только файлы JPG, JPEG и PNG для иконок!'));
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
        logger.info(`APK принят: имя=${file.originalname}, MIME=${file.mimetype}`);
        return cb(null, true);
      }
      logger.warn(`Недопустимый APK: имя=${file.originalname}, MIME=${file.mimetype}`);
      cb(new Error('Разрешены только файлы APK!'));
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

// Функция загрузки в S3
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
    logger.error(`Ошибка загрузки в S3 для ${key}: ${error.message}`);
    throw new Error(`Ошибка загрузки в S3: ${error.message}`);
  }
}

// Настройка Telegram-бота
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

  bot.on('polling_error', (error) => {
    logger.error(`Ошибка опроса Telegram: ${error.message}`);
    if (error.message.includes('409 Conflict')) {
      logger.error('Обнаружен конфликт: другой экземпляр бота запущен. Остановка опроса.');
      bot.stopPolling();
    }
  });
} catch (error) {
  logger.error(`Ошибка инициализации Telegram-бота: ${error.message}`);
}

// Команда /start для Telegram
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
      `🌟 Добро пожаловать в PlayEvit!\nВаш Telegram chat ID: ${chatId}\nИспользуйте этот ID или имя пользователя (@${username}) при регистрации.\nУведомления будут приходить сюда!`
    );
    logger.info(`Захвачен chat ID ${chatId} для имени @${username}`);
  } catch (error) {
    logger.error(`Ошибка сохранения соответствия Telegram для chat ID ${chatId}: ${error.message}`);
    await bot.sendMessage(chatId, 'Ошибка сохранения вашего chat ID. Попробуйте снова или обратитесь в поддержку.');
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
    throw new Error(`Имя пользователя ${telegramId} не найдено. Отправьте /start боту.`);
  }
  return mapping.chatId;
}

// Отправка сообщения в Telegram
async function sendTelegramMessage(telegramId, message) {
  if (!bot) {
    logger.warn('Telegram-бот не инициализирован, отправка сообщения пропущена');
    return;
  }
  try {
    const chatId = await resolveTelegramId(telegramId);
    await bot.sendMessage(chatId, message);
    logger.info(`Сообщение отправлено в chat ID ${chatId}`);
  } catch (error) {
    logger.error(`Ошибка отправки сообщения в Telegram ID ${telegramId}: ${error.message}`);
  }
}

// Отправка сообщения для верификации
async function sendVerificationTelegram(telegramId, email, token) {
  if (!bot) {
    logger.warn('Telegram-бот не инициализирован, отправка верификационного сообщения пропущена');
    return;
  }
  try {
    const chatId = await resolveTelegramId(telegramId);
    const verificationUrl = `https://vasyaproger-my-backend-9f42.twc1.net/api/auth/verify/${token}`;
    const message = `
🌟 Добро пожаловать в PlayEvit, ${telegramId}! 🌟
Подтвердите ваш email (${email}) по ссылке:
${verificationUrl}
Или используйте токен в форме верификации на сайте:
Токен: ${token}
🔗 Токен действителен 100 лет.
`;
    await bot.sendMessage(chatId, message);
    logger.info(`Верификационное сообщение отправлено в chat ID ${chatId}`);
  } catch (error) {
    logger.error(`Ошибка отправки верификационного сообщения в Telegram ID ${telegramId}: ${error.message}`);
  }
}

// Отправка сообщения для сброса пароля
async function sendPasswordResetTelegram(telegramId, token) {
  if (!bot) {
    logger.warn('Telegram-бот не инициализирован, отправка сообщения о сбросе пароля пропущена');
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
Если вы не запрашивали сброс, проигнорируйте это сообщение.
`;
    await bot.sendMessage(chatId, message);
    logger.info(`Сообщение о сбросе пароля отправлено в chat ID ${chatId}`);
  } catch (error) {
    logger.error(`Ошибка отправки сообщения о сбросе пароля в Telegram ID ${telegramId}: ${error.message}`);
  }
}

// Промежуточный слой для аутентификации JWT
const authenticateToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];
  if (!token) {
    logger.warn('Токен авторизации отсутствует');
    return res.status(401).json({ message: 'Требуется токен авторизации' });
  }
  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    req.user = decoded;
    next();
  } catch (error) {
    logger.error(`Недействительный токен: ${error.message}`);
    return res.status(403).json({ message: 'Недействительный или истёкший токен' });
  }
};

// Синхронизация базы данных
async function syncDatabase() {
  try {
    logger.info('Начало синхронизации базы данных');
    await sequelize.sync({ force: false }); // Безопасное создание таблиц
    logger.info('База данных успешно синхронизирована');

    const tablesToCheck = ['Users', 'PreRegisters', 'TelegramMappings', 'Apps'];
    for (const table of tablesToCheck) {
      const [results] = await sequelize.query(`SHOW TABLES LIKE '${table}'`);
      if (results.length > 0) {
        logger.info(`Таблица ${table} существует`);
      } else {
        logger.error(`Таблица ${table} не создана`);
        throw new Error(`Не удалось создать таблицу ${table}`);
      }
    }
  } catch (error) {
    logger.error(`Ошибка синхронизации базы данных: ${error.message}`);
    throw error;
  }
}

// Инициализация приложения
async function initializeApp() {
  logger.info('Инициализация приложения');
  try {
    await connectWithRetry();
    await syncDatabase();
    logger.info('Приложение успешно инициализировано');
  } catch (error) {
    logger.error(`Критическая ошибка инициализации: ${error.message}`);
    process.exit(1);
  }
}

// Маршруты

// Предварительная регистрация
app.post(
  '/api/pre-register',
  [
    body('email').isEmail().normalizeEmail().withMessage('Требуется действительный email'),
    body('telegramId').optional().trim().custom((value) => {
      if (!value || /^\d+$/.test(value) || /^@/.test(value)) {
        return true;
      }
      throw new Error('Telegram ID должен быть числовым chat ID или именем пользователя с @');
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
        return res.status(400).json({ message: 'Этот email уже в списке ожидания' });
      }

      const preRegister = await PreRegister.create({ email, telegramId });
      let message = `🌟 Спасибо за интерес к PlayEvit!\nВаш email (${email}) добавлен в список ожидания.\nМы уведомим вас о запуске в 2025 году!`;
      if (telegramId) {
        try {
          await sendTelegramMessage(telegramId, message);
        } catch (error) {
          message = 'Не удалось отправить сообщение в Telegram. Убедитесь, что вы отправили /start боту.';
        }
      }

      logger.info(`Предварительная регистрация: ${email}`);
      res.status(201).json({ message });
    } catch (error) {
      logger.error(`Ошибка предварительной регистрации: ${error.message}`);
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
    body('password').isLength({ min: 8 }).withMessage('Пароль должен быть минимум 8 символов'),
    body('accountType').isIn(['individual', 'commercial']).withMessage('Недопустимый тип аккаунта'),
    body('name').notEmpty().trim().withMessage('Требуется имя'),
    body('phone').notEmpty().trim().withMessage('Требуется номер телефона'),
    body('telegramId').notEmpty().trim().custom((value) => {
      if (/^\d+$/.test(value) || /^@/.test(value)) {
        return true;
      }
      throw new Error('Telegram ID должен быть числовым chat ID или именем пользователя с @');
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
        return res.status(400).json({ message: 'Требуется хотя бы один документ' });
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
      const verificationToken = jwt.sign({ email }, JWT_SECRET, { expiresIn: '100y' });
      const authToken = jwt.sign({ email, accountType, name, telegramId }, JWT_SECRET, { expiresIn: '7d' });

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
        logger.info(`Пользователь зарегистрирован: ${email}`);
        res.status(201).json({
          message: `Регистрация успешна! Проверьте ваш Telegram (${telegramId}) для верификации.`,
          token: authToken,
          user: { id: user.id, email, accountType, name, telegramId },
        });
      } catch (telegramError) {
        logger.warn(`Сообщение в Telegram не отправлено для ${email}: ${telegramError.message}`);
        res.status(201).json({
          message: `Регистрация успешна, но сообщение в Telegram не отправлено. Отправьте /start боту с вашим ${telegramId}.`,
          token: authToken,
          user: { id: user.id, email, accountType, name, telegramId },
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
      decoded = jwt.verify(token, JWT_SECRET);
    } catch (error) {
      logger.warn(`Недействительный верификационный токен: ${error.message}`);
      return res.status(400).json({ message: 'Недействительный или истёкший токен' });
    }

    const user = await User.findOne({ where: { email: decoded.email } });
    if (!user) {
      logger.warn(`Пользователь с email ${decoded.email} не найден`);
      return res.status(400).json({ message: 'Пользователь не найден' });
    }

    if (user.verificationToken !== token) {
      logger.warn(`Несоответствие верификационного токена для email ${decoded.email}`);
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
      logger.warn(`Не удалось отправить верификационное сообщение в Telegram для ${user.email}: ${telegramError.message}`);
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
        decoded = jwt.verify(token, JWT_SECRET);
      } catch (error) {
        logger.warn(`Недействительный верификационный токен в форме: ${error.message}`);
        return res.status(400).json({ message: 'Недействительный или истёкший токен' });
      }

      if (decoded.email !== email) {
        logger.warn(`Email ${email} не соответствует токену`);
        return res.status(400).json({ message: 'Токен не соответствует указанному email' });
      }

      const user = await User.findOne({ where: { email } });
      if (!user) {
        logger.warn(`Пользователь с email ${email} не найден`);
        return res.status(400).json({ message: 'Пользователь не найден' });
      }

      if (user.verificationToken !== token) {
        logger.warn(`Несоответствие верификационного токена для email ${email}`);
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
        logger.warn(`Не удалось отправить верификационное сообщение в Telegram для ${user.email}: ${telegramError.message}`);
      }

      logger.info(`Email верифицирован через форму для ${user.email}`);
      res.status(200).json({ message: 'Email успешно верифицирован!' });
    } catch (error) {
      logger.error(`Ошибка верификации через форму: ${error.message}`);
      res.status(500).json({ message: 'Ошибка сервера', error: error.message });
    }
  }
);

// Вход пользователя
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
        return res.status(400).json({ message: 'Недействительный email или пароль' });
      }

      const isMatch = await bcrypt.compare(password, user.password);
      if (!isMatch) {
        logger.warn(`Неверный пароль для email: ${email}`);
        return res.status(400).json({ message: 'Недействительный email или пароль' });
      }

      let token = user.jwtToken;
      if (!token) {
        token = jwt.sign({ id: user.id, email: user.email }, JWT_SECRET, { expiresIn: '7d' });
        user.jwtToken = token;
        await user.save();
      }

      try {
        await sendTelegramMessage(user.telegramId, `🔐 Вы вошли в PlayEvit с email: ${user.email}`);
      } catch (telegramError) {
        logger.warn(`Не удалось отправить сообщение о входе в Telegram для ${user.email}: ${telegramError.message}`);
      }

      logger.info(`Пользователь вошёл: ${user.email}`);
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

      const resetToken = jwt.sign({ email }, JWT_SECRET, { expiresIn: '1h' });
      user.resetPasswordToken = resetToken;
      user.resetPasswordExpires = new Date(Date.now() + 3600000);
      await user.save();

      try {
        await sendPasswordResetTelegram(user.telegramId, resetToken);
        logger.info(`Запрос сброса пароля для ${user.email}`);
        res.status(200).json({ message: 'Ссылка для сброса пароля отправлена в Telegram' });
      } catch (telegramError) {
        logger.warn(`Сообщение о сбросе пароля не отправлено в Telegram для ${user.email}: ${telegramError.message}`);
        res.status(200).json({
          message: 'Ссылка для сброса пароля не отправлена в Telegram. Убедитесь, что вы отправили /start боту.',
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
    body('password').isLength({ min: 8 }).withMessage('Пароль должен быть минимум 8 символов'),
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
        decoded = jwt.verify(token, JWT_SECRET);
      } catch (error) {
        logger.warn(`Недействительный токен сброса: ${error.message}`);
        return res.status(400).json({ message: 'Недействительный или истёкший токен' });
      }

      const user = await User.findOne({
        where: {
          email: decoded.email,
          resetPasswordToken: token,
          resetPasswordExpires: { [Sequelize.Op.gt]: new Date() },
        },
      });
      if (!user) {
        logger.warn(`Недействительный или истёкший токен сброса для email: ${decoded.email}`);
        return res.status(400).json({ message: 'Недействительный токен или истёк' });
      }

      const salt = await bcrypt.genSalt(10);
      user.password = await bcrypt.hash(password, salt);
      user.resetPasswordToken = null;
      user.resetPasswordExpires = null;
      user.jwtToken = null;
      await user.save();

      try {
        await sendTelegramMessage(user.telegramId, `🔑 Ваш пароль сброшен для email: ${user.email}`);
      } catch (telegramError) {
        logger.warn(`Не удалось отправить сообщение о сбросе пароля в Telegram для ${user.email}: ${telegramError.message}`);
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
        return res.status(400).json({ message: 'Требуется хотя бы один документ' });
      }

      const newDocuments = await Promise.all(
        req.files.documents.map(file => uploadToS3(file, 'documents'))
      );

      user.documents = [...user.documents, ...newDocuments].slice(0, 3);
      user.isVerified = true;
      await user.save();

      try {
        await sendTelegramMessage(user.telegramId, `📄 Ваши документы обновлены для email: ${user.email}`);
      } catch (telegramError) {
        logger.warn(`Не удалось отправить сообщение об обновлении документов в Telegram для ${user.email}: ${telegramError.message}`);
      }

      logger.info(`Документы обновлены для пользователя ${user.email}`);
      res.status(200).json({ message: 'Документы успешно обновлены', documents: user.documents });
    } catch (error) {
      logger.error(`Ошибка обновления документов: ${error.message}`);
      res.status(500).json({ message: 'Ошибка сервера', error: error.message });
    }
  }
);

// Создание нового приложения
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
        return res.status(403).json({ message: 'Аккаунт должен быть верифицирован для отправки приложений' });
      }

      const { name, description, category } = req.body;
      const files = req.files;

      if (!files || !files.icon || !files.icon[0]) {
        logger.warn('Файл иконки отсутствует');
        return res.status(400).json({ message: 'Требуется файл иконки (JPG, JPEG или PNG)' });
      }
      if (!files.apk || !files.apk[0]) {
        logger.warn('Файл APK отсутствует');
        return res.status(400).json({ message: 'Требуется файл APK' });
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
          `🚀 Ваше приложение "${name}" отправлено на проверку! Мы уведомим вас после обработки.`
        );
      } catch (telegramError) {
        logger.warn(`Не удалось отправить сообщение о подаче приложения в Telegram для ${user.email}: ${telegramError.message}`);
      }

      logger.info(`Приложение создано пользователем ${user.email}: ${name}`);
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
  if (err.message.includes('Разрешены только')) {
    logger.warn(`Ошибка типа файла: ${err.message}`);
    return res.status(400).json({ message: err.message });
  }
  res.status(500).json({ message: 'Ошибка сервера', error: err.message });
});

// Запуск сервера после инициализации
const PORT = process.env.PORT || 5000;
async function startServer() {
  await initializeApp();
  app.listen(PORT, () => {
    logger.info(`Сервер запущен на порту ${PORT}`);
  });
}

startServer();