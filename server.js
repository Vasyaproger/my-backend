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
const rateLimit = require('express-rate-limit');

const app = express();

// Конфигурация
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
const WEBSITE_URL = 'https://24webstudio.ru/playevit';

// Проверка переменных окружения
const requiredEnvVars = [
  'JWT_SECRET', 'DB_HOST', 'DB_USER', 'DB_PASSWORD', 'DB_NAME',
  'S3_ACCESS_KEY', 'S3_SECRET_KEY', 'BUCKET_NAME', 'TELEGRAM_BOT_TOKEN'
];
for (const envVar of requiredEnvVars) {
  if (!process.env[envVar]) {
    console.error(`Ошибка: ${envVar} не установлен в переменных окружения`);
    process.exit(1);
  }
}

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

// Настройка S3 клиента
const s3Client = new S3Client({
  endpoint: 'https://s3.twcstorage.ru',
  credentials: {
    accessKeyId: S3_ACCESS_KEY,
    secretAccessKey: S3_SECRET_KEY,
  },
  region: 'ru-1',
  forcePathStyle: true,
});

// Проверка соединения с S3
async function checkS3Connection() {
  try {
    await s3Client.send(new ListBucketsCommand({}));
    logger.info('Соединение с S3 успешно');
  } catch (err) {
    logger.error(`Ошибка соединения с S3: ${err.message}, стек: ${err.stack}`);
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

// Rate Limiting
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100, // Limit each IP to 100 requests per windowMs
  message: 'Слишком много запросов с вашего IP, попробуйте снова через 15 минут',
});
app.use(limiter);

// Request Logging Middleware
app.use((req, res, next) => {
  logger.info(`[${req.method}] ${req.originalUrl} - IP: ${req.ip}`);
  next();
});

// Пул соединений с MySQL
const db = mysql.createPool({
  host: DB_HOST,
  user: DB_USER,
  password: DB_PASSWORD,
  database: DB_NAME,
  port: 3306,
  connectionLimit: 20,
  connectTimeout: 30000,
  acquireTimeout: 30000,
  waitForConnections: true,
  queueLimit: 0,
});

// Настройка Multer
const upload = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: 10 * 1024 * 1024 },
  fileFilter: (req, file, cb) => {
    if (file.fieldname === 'icon') {
      const validMimeTypes = ['image/png', 'image/jpeg', 'image/jpg', 'image/webp'];
      const validExtensions = /\.(png|jpg|jpeg|webp)$/i;
      const extname = validExtensions.test(path.extname(file.originalname).toLowerCase());
      const mimetype = validMimeTypes.includes(file.mimetype);
      if (extname && mimetype) return cb(null, true);
      logger.warn(`Недопустимая иконка: имя=${file.originalname}, MIME=${file.mimetype}`);
      cb(new Error('Разрешены только файлы PNG, JPG, JPEG и WebP для иконок!'));
    } else if (file.fieldname === 'apk') {
      const extname = file.originalname.toLowerCase().endsWith('.apk');
      const validMimeTypes = [
        'application/vnd.android.package-archive',
        'application/octet-stream',
        'application/x-apk',
        'application/zip',
      ];
      const mimetype = validMimeTypes.includes(file.mimetype);
      if (extname && mimetype) return cb(null, true);
      logger.warn(`Недопустимый APK: имя=${file.originalname}, MIME=${file.mimetype}`);
      cb(new Error('Разрешены только файлы APK!'));
    } else if (file.fieldname === 'documents') {
      const validMimeTypes = ['application/pdf', 'image/jpeg', 'image/png', 'image/jpg', 'image/webp'];
      const validExtensions = /\.(pdf|jpg|jpeg|png|webp)$/i;
      const extname = validExtensions.test(path.extname(file.originalname).toLowerCase());
      const mimetype = validMimeTypes.includes(file.mimetype);
      if (extname && mimetype) return cb(null, true);
      logger.warn(`Недопустимый документ: имя=${file.originalname}, MIME=${file.mimetype}`);
      cb(new Error('Разрешены только файлы PDF, JPG, JPEG, PNG и WebP для документов!'));
    } else if (file.fieldname === 'advertisementImage') {
      const validMimeTypes = ['image/png', 'image/jpeg', 'image/jpg', 'image/webp'];
      const validExtensions = /\.(png|jpg|jpeg|webp)$/i;
      const extname = validExtensions.test(path.extname(file.originalname).toLowerCase());
      const mimetype = validMimeTypes.includes(file.mimetype);
      if (extname && mimetype) return cb(null, true);
      logger.warn(`Недопустимое изображение рекламы: имя=${file.originalname}, MIME=${file.mimetype}`);
      cb(new Error('Разрешены только файлы PNG, JPG, JPEG и WebP для изображений рекламы!'));
    } else {
      logger.warn(`Недопустимое имя поля: ${file.fieldname}`);
      cb(new Error('Недопустимое имя поля!'));
    }
  },
}).fields([
  { name: 'icon', maxCount: 1 },
  { name: 'apk', maxCount: 1 },
  { name: 'documents', maxCount: 3 },
  { name: 'advertisementImage', maxCount: 1 },
]);

// Функции для работы с S3
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
    const upload = new Upload({ client: s3Client, params });
    await upload.done();
    const location = `https://s3.twcstorage.ru/${BUCKET_NAME}/${key}`;
    logger.info(`Файл загружен в S3: ${key}, URL: ${location}`);
    return location;
  } catch (error) {
    logger.error(`Ошибка загрузки в S3 для ${key}: ${error.message}, стек: ${error.stack}`);
    throw new Error(`Ошибка загрузки в S3: ${error.message}`);
  }
}

async function deleteFromS3(key) {
  const params = { Bucket: BUCKET_NAME, Key: key };
  try {
    await s3Client.send(new DeleteObjectCommand(params));
    logger.info(`Файл удален из S3: ${key}`);
  } catch (err) {
    logger.error(`Ошибка удаления из S3: ${err.message}, стек: ${err.stack}`);
    throw err;
  }
}

async function getFromS3(key) {
  const params = { Bucket: BUCKET_NAME, Key: key };
  try {
    const command = new GetObjectCommand(params);
    const data = await s3Client.send(command);
    return data;
  } catch (err) {
    logger.error(`Ошибка получения из S3: ${err.message}, стек: ${err.stack}`);
    throw err;
  }
}

// Middleware для проверки JWT
const authenticateToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];
  if (!token) {
    logger.warn(`Отсутствует токен авторизации для маршрута: ${req.originalUrl}`);
    return res.status(401).json({ message: 'Требуется токен авторизации' });
  }
  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    if (!decoded.id || !decoded.email) {
      logger.warn(`Токен не содержит id или email: ${JSON.stringify(decoded)}`);
      return res.status(403).json({ message: 'Недействительный токен: отсутствуют необходимые данные' });
    }
    req.user = decoded;
    logger.info(`Токен проверен: id=${decoded.id}, email=${decoded.email}, маршрут: ${req.originalUrl}`);
    next();
  } catch (error) {
    logger.error(`Ошибка проверки токена для маршрута ${req.originalUrl}: ${error.message}, стек: ${error.stack}`);
    return res.status(403).json({ message: 'Недействительный или истекший токен', error: error.message });
  }
};

// Middleware для опциональной аутентификации
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

// Настройка очереди для Telegram-уведомлений
const telegramQueue = new Queue('telegram-notifications', REDIS_URL, {
  limiter: { max: 30, duration: 1000 },
});

// Обработка задач в очереди
telegramQueue.process(async (job) => {
  const { chatId, text } = job.data;
  try {
    await axios.post(
      `https://api.telegram.org/bot${TELEGRAM_BOT_TOKEN}/sendMessage`,
      { chat_id: chatId, text, parse_mode: 'Markdown' }
    );
    logger.info(`Уведомление отправлено на Telegram ${chatId}: ${text}`);
  } catch (err) {
    logger.error(`Ошибка отправки уведомления на Telegram ${chatId}: ${err.message}`);
    throw err;
  }
});

// Инициализация базы данных
async function initializeDatabase() {
  try {
    const connection = await db.getConnection();
    logger.info('Подключение к MySQL выполнено');

    // Создание таблицы Users
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
    logger.info('Таблица Users проверена/создана');

    // Добавление индексов
    await connection.query('CREATE INDEX idx_users_email ON Users(email)');
    await connection.query('CREATE INDEX idx_users_telegramId ON Users(telegramId)');

    // Проверка и добавление недостающих столбцов
    const [columns] = await connection.query(`SHOW COLUMNS FROM Users`);
    const columnNames = columns.map(col => col.Field);
    if (!columnNames.includes('telegramId')) {
      await connection.query(`ALTER TABLE Users ADD COLUMN telegramId VARCHAR(255) UNIQUE`);
      logger.info('Столбец telegramId добавлен');
    }
    if (!columnNames.includes('verificationToken')) {
      await connection.query(`ALTER TABLE Users ADD COLUMN verificationToken VARCHAR(500)`);
      logger.info('Столбец verificationToken добавлен');
    }
    if (!columnNames.includes('verificationExpires')) {
      await connection.query(`ALTER TABLE Users ADD COLUMN verificationExpires DATETIME`);
      logger.info('Столбец verificationExpires добавлен');
    }
    if (!columnNames.includes('isBlocked')) {
      await connection.query(`ALTER TABLE Users ADD COLUMN isBlocked BOOLEAN DEFAULT FALSE`);
      logger.info('Столбец isBlocked добавлен');
    }

    // Создание таблицы PreRegisters
    await connection.query(`
      CREATE TABLE IF NOT EXISTS PreRegisters (
        id INT AUTO_INCREMENT PRIMARY KEY,
        email VARCHAR(255) NOT NULL UNIQUE,
        createdAt TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        updatedAt TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
      )
    `);
    logger.info('Таблица PreRegisters проверена/создана');

    // Создание таблицы Apps
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
    logger.info('Таблица Apps проверена/создана');
    await connection.query('CREATE INDEX idx_apps_userId ON Apps(userId)');
    await connection.query('CREATE INDEX idx_apps_status ON Apps(status)');

    // Создание таблицы Advertisements
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
    logger.info('Таблица Advertisements проверена/создана');
    await connection.query('CREATE INDEX idx_advertisements_userId ON Advertisements(userId)');

    // Создание администратора по умолчанию
    const [users] = await connection.query("SELECT * FROM Users WHERE email = ?", ['admin@24webstudio.ru']);
    if (users.length === 0) {
      const hashedPassword = await bcrypt.hash('admin123', 10);
      await connection.query(
        "INSERT INTO Users (email, password, accountType, name, phone, isVerified) VALUES (?, ?, ?, ?, ?, ?)",
        ['admin@24webstudio.ru', hashedPassword, 'commercial', 'Admin', '1234567890', true]
      );
      logger.info('Админ создан: admin@24webstudio.ru / admin123');
    } else {
      logger.info('Админ уже существует: admin@24webstudio.ru');
    }

    connection.release();
  } catch (err) {
    logger.error(`Ошибка инициализации базы данных: ${err.message}, стек: ${err.stack}`);
    throw err;
  }
}

// Инициализация Telegram-бота
const bot = new TelegramBot(TELEGRAM_BOT_TOKEN, { polling: true });
const userState = new Map();

const mainMenu = {
  reply_markup: {
    keyboard: [
      ['/profile', '/status'],
      ['/submitapp', '/support'],
      ['/notifications', '/help'],
    ],
    resize_keyboard: true,
    one_time_keyboard: false,
  },
};

// Обработка команды /start
bot.onText(/\/start/, async (msg) => {
  const chatId = msg.chat.id;
  logger.info(`Получена команда /start от Telegram ID: ${chatId}`);

  const [user] = await db.query('SELECT id, email, name, isVerified, isBlocked FROM Users WHERE telegramId = ?', [chatId]);
  if (user.length > 0) {
    if (user[0].isBlocked) {
      bot.sendMessage(chatId, `Ваш аккаунт заблокирован. Свяжитесь с поддержкой на ${WEBSITE_URL}.`, mainMenu);
      return;
    }
    if (user[0].isVerified) {
      bot.sendMessage(
        chatId,
        `Добро пожаловать, ${user[0].name}! Ваш аккаунт верифицирован. Используйте меню для управления.\nПосетите наш сайт: ${WEBSITE_URL}`,
        mainMenu
      );
    } else {
      bot.sendMessage(
        chatId,
        `Добро пожаловать, ${user[0].name}! Ваш аккаунт связан с email: ${user[0].email}. Ожидайте проверки документов.\nПосетите наш сайт: ${WEBSITE_URL}`,
        mainMenu
      );
    }
  } else {
    bot.sendMessage(
      chatId,
      `Добро пожаловать! Введите email, использованный при регистрации на ${WEBSITE_URL}:`,
      { reply_markup: { remove_keyboard: true } }
    );
    userState.set(chatId, { step: 'awaiting_email' });
  }
});

// Обработка текстовых сообщений
bot.on('message', async (msg) => {
  const chatId = msg.chat.id;
  const text = msg.text.trim();

  if (!userState.has(chatId) || userState.get(chatId).step !== 'awaiting_email') return;

  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(text)) {
    bot.sendMessage(chatId, 'Недействительный email. Попробуйте снова.');
    return;
  }

  try {
    const [existingUser] = await db.query('SELECT id, name, isVerified, isBlocked FROM Users WHERE email = ?', [text]);
    if (!existingUser.length) {
      bot.sendMessage(
        chatId,
        `Email не найден. Зарегистрируйтесь на ${WEBSITE_URL} и повторите попытку.`,
        mainMenu
      );
      userState.delete(chatId);
      return;
    }

    if (existingUser[0].isBlocked) {
      bot.sendMessage(chatId, `Ваш аккаунт заблокирован. Свяжитесь с поддержкой на ${WEBSITE_URL}.`, mainMenu);
      userState.delete(chatId);
      return;
    }

    await db.query('UPDATE Users SET telegramId = ? WHERE email = ?', [chatId, text]);
    bot.sendMessage(
      chatId,
      `Ваш email (${text}) успешно связан, ${existingUser[0].name}! ${
        existingUser[0].isVerified
          ? 'Ваш аккаунт верифицирован. Используйте меню для управления.'
          : 'Ожидайте проверки документов.'
      }\nПосетите наш сайт: ${WEBSITE_URL}`,
      mainMenu
    );
    logger.info(`Telegram ID ${chatId} связан с email: ${text}`);
    userState.delete(chatId);
  } catch (err) {
    logger.error(`Ошибка связывания Telegram ID ${chatId} с email ${text}: ${err.message}`);
    bot.sendMessage(chatId, `Произошла ошибка. Попробуйте снова или свяжитесь с поддержкой на ${WEBSITE_URL}.`, mainMenu);
    userState.delete(chatId);
  }
});

// Обработка команды /profile
bot.onText(/\/profile/, async (msg) => {
  const chatId = msg.chat.id;
  logger.info(`Получена команда /profile от Telegram ID: ${chatId}`);

  try {
    const [user] = await db.query(
      'SELECT id, email, name, phone, accountType, isVerified, isBlocked, createdAt FROM Users WHERE telegramId = ?',
      [chatId]
    );
    if (!user.length) {
      bot.sendMessage(
        chatId,
        `Ваш Telegram ID не связан с аккаунтом. Используйте /start для связывания.`,
        mainMenu
      );
      return;
    }

    if (user[0].isBlocked) {
      bot.sendMessage(chatId, `Ваш аккаунт заблокирован. Свяжитесь с поддержкой на ${WEBSITE_URL}.`, mainMenu);
      return;
    }

    const response = `
*Ваш профиль*
Имя: ${user[0].name}
Email: ${user[0].email}
Телефон: ${user[0].phone || 'Не указан'}
Тип аккаунта: ${user[0].accountType === 'individual' ? 'Физическое лицо' : 'Коммерческий'}
Статус: ${user[0].isVerified ? 'Верифицирован' : 'Ожидает верификации'}
Дата регистрации: ${new Date(user[0].createdAt).toLocaleDateString('ru-RU')}
Посетите наш сайт: ${WEBSITE_URL}
    `;
    bot.sendMessage(chatId, response, { parse_mode: 'Markdown', ...mainMenu });
  } catch (err) {
    logger.error(`Ошибка получения профиля для Telegram ID ${chatId}: ${err.message}`);
    bot.sendMessage(chatId, `Произошла ошибка. Попробуйте снова или свяжитесь с поддержкой на ${WEBSITE_URL}.`, mainMenu);
  }
});

// Обработка команды /submitapp
bot.onText(/\/submitapp/, async (msg) => {
  const chatId = msg.chat.id;
  logger.info(`Получена команда /submitapp от Telegram ID: ${chatId}`);

  try {
    const [user] = await db.query('SELECT isVerified, isBlocked FROM Users WHERE telegramId = ?', [chatId]);
    if (!user.length) {
      bot.sendMessage(
        chatId,
        `Ваш Telegram ID не связан с аккаунтом. Используйте /start для связывания.`,
        mainMenu
      );
      return;
    }

    if (user[0].isBlocked) {
      bot.sendMessage(chatId, `Ваш аккаунт заблокирован. Свяжитесь с поддержкой на ${WEBSITE_URL}.`, mainMenu);
      return;
    }

    if (!user[0].isVerified) {
      bot.sendMessage(
        chatId,
        `Ваш аккаунт должен быть верифицирован для отправки приложений. Загрузите документы на ${WEBSITE_URL}.`,
        mainMenu
      );
      return;
    }

    bot.sendMessage(
      chatId,
      `Чтобы отправить приложение, перейдите на ${WEBSITE_URL}, войдите в аккаунт и используйте форму отправки приложений.`,
      mainMenu
    );
  } catch (err) {
    logger.error(`Ошибка обработки /submitapp для Telegram ID ${chatId}: ${err.message}`);
    bot.sendMessage(chatId, `Произошла ошибка. Попробуйте снова или свяжитесь с поддержкой на ${WEBSITE_URL}.`, mainMenu);
  }
});

// Обработка команды /support
bot.onText(/\/support/, (msg) => {
  const chatId = msg.chat.id;
  logger.info(`Получена команда /support от Telegram ID: ${chatId}`);
  bot.sendMessage(
    chatId,
    `Для получения поддержки свяжитесь с нами:\n📧 Email: support@24webstudio.ru\n🌐 Сайт: ${WEBSITE_URL}\nМы ответим в течение 24 часов!`,
    mainMenu
  );
});

// Обработка команды /notifications
bot.onText(/\/notifications/, (msg) => {
  const chatId = msg.chat.id;
  logger.info(`Получена команда /notifications от Telegram ID: ${chatId}`);
  bot.sendMessage(
    chatId,
    `Настройка уведомлений пока в разработке. Вы будете получать все уведомления по умолчанию.\nПосетите ${WEBSITE_URL} для управления аккаунтом.`,
    mainMenu
  );
});

// Обработка команды /status
bot.onText(/\/status/, async (msg) => {
  const chatId = msg.chat.id;
  logger.info(`Получена команда /status от Telegram ID: ${chatId}`);

  try {
    const [user] = await db.query('SELECT id, email, name, isVerified, isBlocked FROM Users WHERE telegramId = ?', [chatId]);
    if (!user.length) {
      bot.sendMessage(
        chatId,
        `Ваш Telegram ID не связан с аккаунтом. Используйте /start для связывания.`,
        mainMenu
      );
      return;
    }

    if (user[0].isBlocked) {
      bot.sendMessage(chatId, `Ваш аккаунт заблокирован. Свяжитесь с поддержкой на ${WEBSITE_URL}.`, mainMenu);
      return;
    }

    const [apps] = await db.query('SELECT name, status, createdAt FROM Apps WHERE userId = ?', [user[0].id]);
    let response = `
*Статус аккаунта* (${user[0].email})
Имя: ${user[0].name}
Статус: ${user[0].isVerified ? 'Верифицирован' : 'Ожидает верификации'}
Ваши приложения:
    `;
    if (apps.length === 0) {
      response += 'У вас нет приложений.\n';
    } else {
      apps.forEach(app => {
        response += `- ${app.name}: ${app.status} (отправлено ${new Date(app.createdAt).toLocaleDateString('ru-RU')})\n`;
      });
    }
    response += `Управляйте приложениями на ${WEBSITE_URL}`;

    bot.sendMessage(chatId, response, { parse_mode: 'Markdown', ...mainMenu });
  } catch (err) {
    logger.error(`Ошибка обработки /status для Telegram ID ${chatId}: ${err.message}`);
    bot.sendMessage(chatId, `Произошла ошибка. Попробуйте снова или свяжитесь с поддержкой на ${WEBSITE_URL}.`, mainMenu);
  }
});

// Обработка команды /help
bot.onText(/\/help/, (msg) => {
  const chatId = msg.chat.id;
  logger.info(`Получена команда /help от Telegram ID: ${chatId}`);
  bot.sendMessage(
    chatId,
    `
*Доступные команды:*
/start - Связать Telegram с аккаунтом
/profile - Показать информацию о профиле
/status - Проверить статус аккаунта и приложений
/submitapp - Отправить новое приложение
/support - Связаться с поддержкой
/notifications - Настроить уведомления
/help - Показать это сообщение
🌐 Управляйте аккаунтом на ${WEBSITE_URL}
    `,
    { parse_mode: 'Markdown', ...mainMenu }
  );
});

// Обработка ошибок бота
bot.on('polling_error', (err) => {
  logger.error(`Ошибка polling Telegram бота: ${err.message}, стек: ${err.stack}`);
});

// Инициализация сервера
async function initializeServer() {
  try {
    await initializeDatabase();
    await checkS3Connection();
    app.listen(PORT, () => {
      logger.info(`Сервер запущен на порту ${PORT}`);
    });
  } catch (err) {
    logger.error(`Ошибка инициализации сервера: ${err.message}, стек: ${err.stack}`);
    process.exit(1);
  }
}

// Health Check Endpoint
app.get('/api/health', async (req, res) => {
  try {
    await db.query('SELECT 1');
    await s3Client.send(new ListBucketsCommand({}));
    res.status(200).json({ status: 'ok', message: 'Сервер, база данных и S3 работают корректно' });
  } catch (err) {
    logger.error(`Ошибка проверки здоровья: ${err.message}, стек: ${err.stack}`);
    res.status(500).json({ status: 'error', message: 'Ошибка сервера или сервисов' });
  }
});

// Публичные маршруты
app.get('/api/public/apps', async (req, res) => {
  try {
    const page = parseInt(req.query.page) || 1;
    const limit = parseInt(req.query.limit) || 10;
    const offset = (page - 1) * limit;

    const [apps] = await db.query(`
      SELECT id, name, description, category, iconPath, status, createdAt
      FROM Apps
      WHERE status = 'approved'
      ORDER BY createdAt DESC
      LIMIT ? OFFSET ?
    `, [limit, offset]);

    const [total] = await db.query('SELECT COUNT(*) as count FROM Apps WHERE status = "approved"');
    res.json({
      apps,
      pagination: {
        page,
        limit,
        total: total[0].count,
        totalPages: Math.ceil(total[0].count / limit),
      },
    });
  } catch (err) {
    logger.error(`Ошибка получения приложений: ${err.message}, стек: ${err.stack}`);
    res.status(500).json({ message: 'Ошибка сервера', error: err.message });
  }
});

app.get('/api/public/app-image/:key', optionalAuthenticateToken, async (req, res) => {
  const { key } = req.params;
  try {
    const image = await getFromS3(`icons/${key}`);
    res.setHeader('Content-Type', image.ContentType || 'image/png');
    image.Body.pipe(res);
  } catch (err) {
    logger.error(`Ошибка получения изображения: ${err.message}, стек: ${err.stack}`);
    res.status(500).json({ message: 'Ошибка получения изображения', error: err.message });
  }
});

app.post(
  '/api/pre-register',
  [body('email').isEmail().normalizeEmail().withMessage('Требуется действительный email')],
  async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      logger.warn(`Ошибки валидации: ${JSON.stringify(errors.array())}`);
      return res.status(400).json({ message: 'Ошибка валидации', errors: errors.array() });
    }

    try {
      const { email } = req.body;
      const [existing] = await db.query('SELECT email FROM PreRegisters WHERE email = ?', [email]);
      if (existing.length > 0) {
        return res.status(400).json({ message: 'Email уже в списке ожидания' });
      }

      await db.query('INSERT INTO PreRegisters (email) VALUES (?)', [email]);
      logger.info(`Предрегистрация: ${email}`);

      await telegramQueue.add({
        chatId: '-1002311447135',
        text: `Новая предрегистрация: ${email}`,
      });

      res.status(201).json({ message: `Спасибо! Ваш email (${email}) добавлен в список ожидания. Посетите ${WEBSITE_URL} для деталей.` });
    } catch (error) {
      logger.error(`Ошибка предрегистрации: ${error.message}, стек: ${error.stack}`);
      res.status(500).json({ message: 'Ошибка сервера', error: error.message });
    }
  }
);

app.post(
  '/api/auth/register',
  upload,
  [
    body('email').isEmail().normalizeEmail().withMessage('Требуется действительный email'),
    body('password').isLength({ min: 8 }).withMessage('Пароль должен содержать минимум 8 символов'),
    body('accountType').isIn(['individual', 'commercial']).withMessage('Недопустимый тип аккаунта'),
    body('name').notEmpty().trim().withMessage('Требуется имя'),
    body('phone').notEmpty().trim().withMessage('Требуется номер телефона'),
    body('telegramId').optional().matches(/^(@[A-Za-z0-9_]{5,}|[\d]+)$/).withMessage('Недопустимый формат Telegram ID'),
  ],
  async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      logger.warn(`Ошибки валидации: ${JSON.stringify(errors.array())}`);
      return res.status(400).json({ message: 'Ошибка валидации', errors: errors.array() });
    }

    try {
      const { email, password, accountType, name, phone, telegramId, addressStreet, addressCity, addressCountry, addressPostalCode } = req.body;

      const [existingUser] = await db.query('SELECT email FROM Users WHERE email = ?', [email]);
      if (existingUser.length > 0) {
        return res.status(400).json({ message: 'Email уже зарегистрирован' });
      }

      if (telegramId) {
        const [existingTelegram] = await db.query('SELECT telegramId FROM Users WHERE telegramId = ?', [telegramId]);
        if (existingTelegram.length > 0) {
          return res.status(400).json({ message: 'Telegram ID уже используется' });
        }
      }

      if (!req.files || !req.files.documents || req.files.documents.length === 0) {
        logger.warn('Документы не загружены');
        return res.status(400).json({ message: 'Требуется хотя бы один документ' });
      }

      const documentUrls = await Promise.all(req.files.documents.map(file => uploadToS3(file, 'documents')));
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

      await telegramQueue.add({
        chatId: '-1002311447135',
        text: `Новые документы для проверки от пользователя ${email} (регистрация). Количество: ${documentUrls.length}`,
      });

      if (telegramId) {
        await telegramQueue.add({
          chatId: telegramId,
          text: `Добро пожаловать, ${name}! Ваши документы отправлены на проверку. Вы получите уведомление после верификации.\nПосетите ${WEBSITE_URL} для управления аккаунтом.`,
        });
      }

      logger.info(`Пользователь зарегистрирован: ${email}, documents: ${JSON.stringify(documentUrls)}`);
      res.status(201).json({
        message: telegramId 
          ? 'Регистрация успешна. Ваши документы отправлены на проверку.'
          : `Регистрация успешна. Укажите ваш Telegram ID в профиле или через бот для получения уведомлений. Посетите ${WEBSITE_URL}.`,
        token: authToken,
        user: { id: result.insertId, email, accountType, name, phone, telegramId, isVerified: false },
      });
    } catch (error) {
      logger.error(`Ошибка регистрации: ${error.message}, стек: ${error.stack}`);
      res.status(500).json({ message: 'Ошибка сервера', error: error.message });
    }
  }
);

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
      const [user] = await db.query('SELECT * FROM Users WHERE email = ?', [email]);
      if (!user.length) {
        logger.warn(`Попытка входа с несуществующим email: ${email}`);
        return res.status(400).json({ message: 'Неверный email или пароль' });
      }

      if (user[0].isBlocked) {
        logger.warn(`Попытка входа заблокированного пользователя: ${email}`);
        return res.status(403).json({ message: 'Ваш аккаунт заблокирован' });
      }

      const isMatch = await bcrypt.compare(password, user[0].password);
      if (!isMatch) {
        logger.warn(`Неверный пароль для email: ${email}`);
        return res.status(400).json({ message: 'Неверный email или пароль' });
      }

      const token = jwt.sign({ id: user[0].id, email: user[0].email }, JWT_SECRET, { expiresIn: '7d' });
      await db.query('UPDATE Users SET jwtToken = ? WHERE id = ?', [token, user[0].id]);

      logger.info(`Пользователь вошел: ${user[0].email}`);
      res.status(200).json({
        token,
        user: { id: user[0].id, email: user[0].email, accountType: user[0].accountType, name: user[0].name, phone: user[0].phone, telegramId: user[0].telegramId, isVerified: user[0].isVerified },
        message: user[0].isVerified ? 'Вход успешен' : `Вход успешен, но аккаунт ожидает верификации документов. Посетите ${WEBSITE_URL}.`,
      });
    } catch (error) {
      logger.error(`Ошибка входа: ${error.message}, стек: ${error.stack}`);
      res.status(500).json({ message: 'Ошибка сервера', error: error.message });
    }
  }
);

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
      const [user] = await db.query('SELECT id, email, telegramId FROM Users WHERE email = ?', [email]);
      if (!user.length) {
        logger.warn(`Попытка сброса пароля для несуществующего email: ${email}`);
        return res.status(404).json({ message: 'Пользователь с таким email не найден' });
      }

      const resetToken = jwt.sign({ email }, JWT_SECRET, { expiresIn: '1h' });
      await db.query(
        'UPDATE Users SET resetPasswordToken = ?, resetPasswordExpires = ? WHERE email = ?',
        [resetToken, new Date(Date.now() + 3600000), email]
      );

      if (user[0].telegramId) {
        await telegramQueue.add({
          chatId: user[0].telegramId,
          text: `Запрос на сброс пароля. Перейдите по ссылке: ${WEBSITE_URL}/reset-password/${resetToken}`,
        });
      }

      logger.info(`Запрошен сброс пароля для ${user[0].email}`);
      res.status(200).json({ message: `Ссылка для сброса пароля отправлена на ваш Telegram, если он указан. Проверьте ${WEBSITE_URL}.` });
    } catch (error) {
      logger.error(`Ошибка сброса пароля: ${error.message}, стек: ${error.stack}`);
      res.status(500).json({ message: 'Ошибка сервера', error: error.message });
    }
  }
);

app.post(
  '/api/auth/reset-password/:token',
  [
    body('password').isLength({ min: 8 }).withMessage('Пароль должен содержать минимум 8 символов'),
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
        logger.warn(`Недействительный токен сброса: ${error.message}, стек: ${error.stack}`);
        return res.status(400).json({ message: 'Недействительный или истекший токен' });
      }

      const [user] = await db.query(
        'SELECT id, email FROM Users WHERE email = ? AND resetPasswordToken = ? AND resetPasswordExpires > NOW()',
        [decoded.email, token]
      );
      if (!user.length) {
        logger.warn(`Недействительный или истекший токен сброса для email: ${decoded.email}`);
        return res.status(400).json({ message: 'Недействительный или истекший токен' });
      }

      const salt = await bcrypt.genSalt(10);
      const hashedPassword = await bcrypt.hash(password, salt);
      await db.query(
        'UPDATE Users SET password = ?, resetPasswordToken = NULL, resetPasswordExpires = NULL, jwtToken = NULL WHERE email = ?',
        [hashedPassword, decoded.email]
      );

      logger.info(`Пароль сброшен для ${user[0].email}`);
      res.status(200).json({ message: `Пароль успешно сброшен. Войдите на ${WEBSITE_URL}.` });
    } catch (error) {
      logger.error(`Ошибка сброса пароля: ${error.message}, стек: ${error.stack}`);
      res.status(500).json({ message: 'Ошибка сервера', error: error.message });
    }
  }
);

app.get('/api/user/profile', authenticateToken, async (req, res) => {
  try {
    const [user] = await db.query(
      'SELECT id, email, accountType, name, phone, telegramId, addressStreet, addressCity, addressCountry, addressPostalCode, documents, isVerified, createdAt FROM Users WHERE id = ?',
      [req.user.id]
    );
    if (!user.length) {
      logger.warn(`Пользователь не найден для ID: ${req.user.id}`);
      return res.status(404).json({ message: 'Пользователь не найден' });
    }

    let documents = [];
    try {
      if (user[0].documents) {
        documents = typeof user[0].documents === 'string' ? JSON.parse(user[0].documents) : user[0].documents;
        if (!Array.isArray(documents)) documents = [documents];
      }
    } catch (parseError) {
      logger.error(`Ошибка парсинга документов для пользователя ${user[0].email}: ${parseError.message}`);
      documents = [];
    }

    user[0].documents = documents;
    res.status(200).json(user[0]);
  } catch (error) {
    logger.error(`Ошибка получения профиля: ${error.message}, стек: ${error.stack}`);
    res.status(500).json({ message: 'Ошибка сервера', error: error.message });
  }
});

app.put(
  '/api/user/profile',
  authenticateToken,
  [
    body('name').optional().notEmpty().trim().withMessage('Имя не может быть пустым'),
    body('phone').optional().notEmpty().trim().withMessage('Телефон не может быть пустым'),
    body('telegramId').optional().matches(/^(@[A-Za-z0-9_]{5,}|[\d]+)$/).withMessage('Недопустимый формат Telegram ID'),
    body('addressStreet').optional().trim(),
    body('addressCity').optional().trim(),
    body('addressCountry').optional().trim(),
    body('addressPostalCode').optional().trim(),
  ],
  async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      logger.warn(`Ошибки валидации: ${JSON.stringify(errors.array())}`);
      return res.status(400).json({ message: 'Ошибка валидации', errors: errors.array() });
    }

    try {
      const [user] = await db.query('SELECT id, email, telegramId FROM Users WHERE id = ?', [req.user.id]);
      if (!user.length) {
        logger.warn(`Пользователь не найден для ID: ${req.user.id}`);
        return res.status(404).json({ message: 'Пользователь не найден' });
      }

      const { name, phone, telegramId, addressStreet, addressCity, addressCountry, addressPostalCode } = req.body;

      if (telegramId && telegramId !== user[0].telegramId) {
        const [existingTelegram] = await db.query('SELECT telegramId FROM Users WHERE telegramId = ? AND id != ?', [telegramId, req.user.id]);
        if (existingTelegram.length > 0) {
          return res.status(400).json({ message: 'Telegram ID уже используется' });
        }
      }

      await db.query(
        `UPDATE Users SET
          name = COALESCE(?, name),
          phone = COALESCE(?, phone),
          telegramId = COALESCE(?, telegramId),
          addressStreet = COALESCE(?, addressStreet),
          addressCity = COALESCE(?, addressCity),
          addressCountry = COALESCE(?, addressCountry),
          addressPostalCode = COALESCE(?, addressPostalCode)
        WHERE id = ?`,
        [name, phone, telegramId, addressStreet, addressCity, addressCountry, addressPostalCode, req.user.id]
      );

      if (telegramId && telegramId !== user[0].telegramId) {
        await telegramQueue.add({
          chatId: telegramId,
          text: `Ваш Telegram ID успешно обновлен для аккаунта ${user[0].email}. Управляйте профилем на ${WEBSITE_URL}.`,
        });
      }

      logger.info(`Профиль обновлен для пользователя ${user[0].email}`);
      res.status(200).json({ message: `Профиль успешно обновлен. Посетите ${WEBSITE_URL}.` });
    } catch (error) {
      logger.error(`Ошибка обновления профиля: ${error.message}, стек: ${error.stack}`);
      res.status(500).json({ message: 'Ошибка сервера', error: error.message });
    }
  }
);

app.post(
  '/api/user/documents',
  authenticateToken,
  upload,
  async (req, res) => {
    try {
      const [user] = await db.query('SELECT id, email, documents, telegramId FROM Users WHERE id = ?', [req.user.id]);
      if (!user.length) {
        logger.warn(`Пользователь не найден для ID: ${req.user.id}`);
        return res.status(404).json({ message: 'Пользователь не найден' });
      }

      if (!req.files || !req.files.documents || req.files.documents.length === 0) {
        logger.warn('Документы не загружены');
        return res.status(400).json({ message: 'Требуется хотя бы один документ' });
      }

      const newDocuments = await Promise.all(req.files.documents.map(file => uploadToS3(file, 'documents')));
      let currentDocuments = [];
      try {
        currentDocuments = user[0].documents ? JSON.parse(user[0].documents) : [];
        if (!Array.isArray(currentDocuments)) currentDocuments = [currentDocuments];
      } catch (parseError) {
        logger.error(`Ошибка парсинга текущих документов для пользователя ${user[0].email}: ${parseError.message}`);
        currentDocuments = [];
      }

      const updatedDocuments = [...currentDocuments, ...newDocuments].slice(0, 3);
      await db.query('UPDATE Users SET documents = ?, isVerified = ? WHERE id = ?', [
        JSON.stringify(updatedDocuments), false, user[0].id
      ]);

      await telegramQueue.add({
        chatId: '-1002311447135',
        text: `Новые документы для проверки от пользователя ${user[0].email}. Количество: ${newDocuments.length}`,
      });

      if (user[0].telegramId) {
        await telegramQueue.add({
          chatId: user[0].telegramId,
          text: `Ваши новые документы отправлены на проверку. Вы получите уведомление после верификации.\nПосетите ${WEBSITE_URL}.`,
        });
      }

      logger.info(`Документы обновлены для пользователя ${user[0].email}, новые документы: ${JSON.stringify(updatedDocuments)}`);
      res.status(200).json({ 
        message: 'Документы успешно загружены и ожидают проверки администратором', 
        documents: updatedDocuments 
      });
    } catch (error) {
      logger.error(`Ошибка обновления документов: ${error.message}, стек: ${error.stack}`);
      res.status(500).json({ message: 'Ошибка сервера', error: error.message });
    }
  }
);

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
      const [user] = await db.query('SELECT id, email, isVerified FROM Users WHERE id = ?', [req.user.id]);
      if (!user.length) {
        logger.warn(`Пользователь не найден для ID: ${req.user.id}`);
        return res.status(404).json({ message: 'Пользователь не найден' });
      }

      if (!user[0].isVerified) {
        logger.warn(`Пользователь не верифицирован: ${user[0].email}`);
        return res.status(403).json({ message: `Аккаунт должен быть верифицирован для отправки приложений. Загрузите документы на ${WEBSITE_URL}.` });
      }

      const { name, description, category } = req.body;
      const files = req.files;

      if (!files || !files.icon || !files.icon[0]) {
        logger.warn('Файл иконки отсутствует');
        return res.status(400).json({ message: 'Требуется файл иконки (PNG, JPG, JPEG или WebP)' });
      }
      if (!files.apk || !files.apk[0]) {
        logger.warn('Файл APK отсутствует');
        return res.status(400).json({ message: 'Требуется файл APK' });
      }

      const iconUrl = await uploadToS3(files.icon[0], 'icons');
      const apkUrl = await uploadToS3(files.apk[0], 'apks');

      const [result] = await db.query(
        `INSERT INTO Apps (
          name, description, category, iconPath, apkPath, userId, status
        ) VALUES (?, ?, ?, ?, ?, ?, ?)`,
        [name, description, category, iconUrl, apkUrl, user[0].id, 'pending']
      );

      logger.info(`Приложение создано пользователем ${user[0].email}: ${name}`);

      await telegramQueue.add({
        chatId: '-1002311447135',
        text: `Новое приложение отправлено: ${name} от ${user[0].email}`,
      });

      if (user[0].telegramId) {
        await telegramQueue.add({
          chatId: user[0].telegramId,
          text: `Ваше приложение "${name}" отправлено на проверку. Вы получите уведомление после проверки.\nПосетите ${WEBSITE_URL}.`,
        });
      }

      res.status(201).json({
        message: 'Приложение успешно отправлено',
        app: { id: result.insertId, name, description, category, iconPath: iconUrl, apkPath: apkUrl, userId: user[0].id, status: 'pending' },
      });
    } catch (error) {
      logger.error(`Ошибка создания приложения: ${error.message}, стек: ${error.stack}`);
      res.status(500).json({ message: 'Ошибка сервера', error: error.message });
    }
  }
);

app.post(
  '/api/advertisements/create',
  authenticateToken,
  upload,
  [
    body('title').notEmpty().trim().withMessage('Требуется заголовок рекламы'),
    body('description').notEmpty().trim().withMessage('Требуется описание рекламы'),
  ],
  async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      logger.warn(`Ошибки валидации: ${JSON.stringify(errors.array())}`);
      return res.status(400).json({ message: 'Ошибка валидации', errors: errors.array() });
    }

    try {
      const [user] = await db.query('SELECT id, email, isVerified, isBlocked FROM Users WHERE id = ?', [req.user.id]);
      if (!user.length) {
        logger.warn(`Пользователь не найден для ID: ${req.user.id}`);
        return res.status(404).json({ message: 'Пользователь не найден' });
      }

      if (user[0].isBlocked) {
        logger.warn(`Попытка создания рекламы заблокированным пользователем: ${user[0].email}`);
        return res.status(403).json({ message: `Ваш аккаунт заблокирован. Свяжитесь с поддержкой на ${WEBSITE_URL}.` });
      }

      if (!user[0].isVerified) {
        logger.warn(`Пользователь не верифицирован: ${user[0].email}`);
        return res.status(403).json({ message: `Аккаунт должен быть верифицирован для отправки рекламы. Загрузите документы на ${WEBSITE_URL}.` });
      }

      const { title, description } = req.body;
      const files = req.files;
      let imageUrl = null;

      if (files && files.advertisementImage && files.advertisementImage[0]) {
        imageUrl = await uploadToS3(files.advertisementImage[0], 'advertisements');
      }

      const [result] = await db.query(
        `INSERT INTO Advertisements (title, description, imagePath, userId, status) VALUES (?, ?, ?, ?, ?)`,
        [title, description, imageUrl, user[0].id, 'pending']
      );

      logger.info(`Реклама создана пользователем ${user[0].email}: ${title}`);

      await telegramQueue.add({
        chatId: '-1002311447135',
        text: `Новая реклама отправлена: ${title} от ${user[0].email}`,
      });

      if (user[0].telegramId) {
        await telegramQueue.add({
          chatId: user[0].telegramId,
          text: `Ваша реклама "${title}" отправлена на проверку. Вы получите уведомление после проверки.\nПосетите ${WEBSITE_URL}.`,
        });
      }

      res.status(201).json({
        message: 'Реклама успешно отправлена',
        advertisement: { id: result.insertId, title, description, imagePath: imageUrl, userId: user[0].id, status: 'pending' },
      });
    } catch (error) {
      logger.error(`Ошибка создания рекламы: ${error.message}, стек: ${error.stack}`);
      res.status(500).json({ message: 'Ошибка сервера', error: error.message });
    }
  }
);

// Админ-маршруты
app.get('/api/admin/apps', authenticateToken, async (req, res) => {
  try {
    const [user] = await db.query('SELECT email, accountType FROM Users WHERE id = ?', [req.user.id]);
    if (!user.length || user[0].email !== 'admin@24webstudio.ru') {
      return res.status(403).json({ message: 'Требуется доступ администратора' });
    }

    const page = parseInt(req.query.page) || 1;
    const limit = parseInt(req.query.limit) || 10;
    const offset = (page - 1) * limit;

    const [apps] = await db.query(`
      SELECT a.*, u.email as userEmail, u.name as userName
      FROM Apps a
      JOIN Users u ON a.userId = u.id
      ORDER BY a.createdAt DESC
      LIMIT ? OFFSET ?
    `, [limit, offset]);

    const [total] = await db.query('SELECT COUNT(*) as count FROM Apps');
    res.json({
      apps,
      pagination: {
        page,
        limit,
        total: total[0].count,
        totalPages: Math.ceil(total[0].count / limit),
      },
    });
  } catch (err) {
    logger.error(`Ошибка получения приложений для админа: ${err.message}, стек: ${err.stack}`);
    res.status(500).json({ message: 'Ошибка сервера', error: err.message });
  }
});

app.put('/api/admin/apps/:id', authenticateToken, async (req, res) => {
  const { id } = req.params;
  const { status } = req.body;

  try {
    const [user] = await db.query('SELECT email, accountType FROM Users WHERE id = ?', [req.user.id]);
    if (!user.length || user[0].email !== 'admin@24webstudio.ru') {
      return res.status(403).json({ message: 'Требуется доступ администратора' });
    }

    if (!['pending', 'approved', 'rejected'].includes(status)) {
      return res.status(400).json({ message: 'Недопустимый статус' });
    }

    const [app] = await db.query('SELECT * FROM Apps WHERE id = ?', [id]);
    if (!app.length) {
      return res.status(404).json({ message: 'Приложение не найдено' });
    }

    await db.query('UPDATE Apps SET status = ? WHERE id = ?', [status, id]);
    logger.info(`Статус приложения ${id} обновлен на ${status}`);

    if (status !== 'pending') {
      const [appUser] = await db.query('SELECT email, telegramId FROM Users WHERE id = ?', [app[0].userId]);
      if (appUser[0].telegramId) {
        await telegramQueue.add({
          chatId: appUser[0].telegramId,
          text: `Статус приложения "${app[0].name}" обновлен на ${status} для пользователя ${appUser[0].email}.\nПосетите ${WEBSITE_URL}.`,
        });
      }
    }

    res.json({ message: `Статус приложения обновлен на ${status}` });
  } catch (err) {
    logger.error(`Ошибка обновления приложения: ${err.message}, стек: ${err.stack}`);
    res.status(500).json({ message: 'Ошибка сервера', error: err.message });
  }
});

app.delete('/api/admin/apps/:id', authenticateToken, async (req, res) => {
  const { id } = req.params;

  try {
    const [user] = await db.query('SELECT email, accountType FROM Users WHERE id = ?', [req.user.id]);
    if (!user.length || user[0].email !== 'admin@24webstudio.ru') {
      return res.status(403).json({ message: 'Требуется доступ администратора' });
    }

    const [app] = await db.query('SELECT iconPath, apkPath FROM Apps WHERE id = ?', [id]);
    if (!app.length) {
      return res.status(404).json({ message: 'Приложение не найдено' });
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
    logger.info(`Приложение ${id} удалено`);

    res.json({ message: 'Приложение удалено' });
  } catch (err) {
    logger.error(`Ошибка удаления приложения: ${err.message}, стек: ${err.stack}`);
    res.status(500).json({ message: 'Ошибка сервера', error: err.message });
  }
});

app.get('/api/admin/users/documents', authenticateToken, async (req, res) => {
  try {
    const [user] = await db.query('SELECT email, accountType FROM Users WHERE id = ?', [req.user.id]);
    if (!user.length || user[0].email !== 'admin@24webstudio.ru') {
      return res.status(403).json({ message: 'Требуется доступ администратора' });
    }

    const page = parseInt(req.query.page) || 1;
    const limit = parseInt(req.query.limit) || 10;
    const offset = (page - 1) * limit;

    const [users] = await db.query(`
      SELECT id, email, name, accountType, telegramId, documents, isVerified, createdAt
      FROM Users
      WHERE documents IS NOT NULL
      ORDER BY createdAt DESC
      LIMIT ? OFFSET ?
    `, [limit, offset]);

    const [total] = await db.query('SELECT COUNT(*) as count FROM Users WHERE documents IS NOT NULL');
    const usersWithDocuments = users.map(u => {
      let documents = [];
      try {
        documents = u.documents ? JSON.parse(u.documents) : [];
        if (!Array.isArray(documents)) documents = [documents];
      } catch (parseError) {
        logger.error(`Ошибка парсинга документов для пользователя ${u.email}: ${parseError.message}`);
        documents = [];
      }
      return { ...u, documents };
    });

    res.json({
      users: usersWithDocuments,
      pagination: {
        page,
        limit,
        total: total[0].count,
        totalPages: Math.ceil(total[0].count / limit),
      },
    });
  } catch (err) {
    logger.error(`Ошибка получения документов пользователей для админа: ${err.message}, стек: ${err.stack}`);
    res.status(500).json({ message: 'Ошибка сервера', error: err.message });
  }
});

app.put('/api/admin/users/:id/verify', authenticateToken, async (req, res) => {
  const { id } = req.params;
  const { isVerified } = req.body;

  try {
    const [admin] = await db.query('SELECT email, accountType FROM Users WHERE id = ?', [req.user.id]);
    if (!admin.length || admin[0].email !== 'admin@24webstudio.ru') {
      return res.status(403).json({ message: 'Требуется доступ администратора' });
    }

    if (typeof isVerified !== 'boolean') {
      return res.status(400).json({ message: 'Недопустимый статус верификации' });
    }

    const [user] = await db.query('SELECT email, telegramId, name FROM Users WHERE id = ?', [id]);
    if (!user.length) {
      return res.status(404).json({ message: 'Пользователь не найден' });
    }

    await db.query('UPDATE Users SET isVerified = ? WHERE id = ?', [isVerified, id]);
    logger.info(`Статус верификации пользователя ${user[0].email} обновлен на ${isVerified}`);

    if (user[0].telegramId) {
      await telegramQueue.add({
        chatId: user[0].telegramId,
        text: isVerified 
          ? `Поздравляем, ${user[0].name}! Ваш аккаунт успешно верифицирован. Управляйте приложениями на ${WEBSITE_URL}.` 
          : `Уважаемый ${user[0].name}, ваш аккаунт не прошел верификацию. Загрузите корректные документы на ${WEBSITE_URL}.`,
      });
    }

    res.json({ message: `Статус верификации обновлен на ${isVerified ? 'верифицирован' : 'не верифицирован'}` });
  } catch (err) {
    logger.error(`Ошибка верификации пользователя: ${err.message}, стек: ${err.stack}`);
    res.status(500).json({ message: 'Ошибка сервера', error: err.message });
  }
});

app.put('/api/admin/users/:id/block', authenticateToken, async (req, res) => {
  const { id } = req.params;
  const { isBlocked } = req.body;

  try {
    const [admin] = await db.query('SELECT email, accountType FROM Users WHERE id = ?', [req.user.id]);
    if (!admin.length || admin[0].email !== 'admin@24webstudio.ru') {
      return res.status(403).json({ message: 'Требуется доступ администратора' });
    }

    if (typeof isBlocked !== 'boolean') {
      return res.status(400).json({ message: 'Недопустимый статус блокировки' });
    }

    const [user] = await db.query('SELECT email, telegramId FROM Users WHERE id = ?', [id]);
    if (!user.length) {
      return res.status(404).json({ message: 'Пользователь не найден' });
    }

    await db.query('UPDATE Users SET isBlocked = ? WHERE id = ?', [isBlocked, id]);
    logger.info(`Статус блокировки пользователя ${user[0].email} обновлен на ${isBlocked}`);

    if (user[0].telegramId) {
      await telegramQueue.add({
        chatId: user[0].telegramId,
        text: isBlocked 
          ? `Ваш аккаунт был заблокирован. Свяжитесь с поддержкой на ${WEBSITE_URL}.` 
          : `Ваш аккаунт разблокирован. Посетите ${WEBSITE_URL}.`,
      });
    }

    res.json({ message: `Пользователь ${isBlocked ? 'заблокирован' : 'разблокирован'}` });
  } catch (err) {
    logger.error(`Ошибка блокировки пользователя: ${err.message}, стек: ${err.stack}`);
    res.status(500).json({ message: 'Ошибка сервера', error: err.message });
  }
});

app.delete('/api/admin/users/:id', authenticateToken, async (req, res) => {
  const { id } = req.params;

  try {
    const [admin] = await db.query('SELECT email, accountType FROM Users WHERE id = ?', [req.user.id]);
    if (!admin.length || admin[0].email !== 'admin@24webstudio.ru') {
      return res.status(403).json({ message: 'Требуется доступ администратора' });
    }

    const [user] = await db.query('SELECT email, documents, telegramId FROM Users WHERE id = ?', [id]);
    if (!user.length) {
      logger.warn(`Пользователь не найден для ID: ${id}`);
      return res.status(404).json({ message: 'Пользователь не найден' });
    }

    let documents = [];
    try {
      documents = user[0].documents ? JSON.parse(user[0].documents) : [];
      if (!Array.isArray(documents)) documents = [documents];
    } catch (parseError) {
      logger.error(`Ошибка парсинга документов для пользователя ${user[0].email}: ${parseError.message}`);
    }

    for (const docUrl of documents) {
      const docKey = docUrl.split('/').pop();
      if (docKey) await deleteFromS3(`documents/${docKey}`);
    }

    const [apps] = await db.query('SELECT iconPath, apkPath FROM Apps WHERE userId = ?', [id]);
    for (const app of apps) {
      if (app.iconPath) {
        const iconKey = app.iconPath.split('/').pop();
        if (iconKey) await deleteFromS3(`icons/${iconKey}`);
      }
      if (app.apkPath) {
        const apkKey = app.apkPath.split('/').pop();
        if (apkKey) await deleteFromS3(`apks/${apkKey}`);
      }
    }

    const [ads] = await db.query('SELECT imagePath FROM Advertisements WHERE userId = ?', [id]);
    for (const ad of ads) {
      if (ad.imagePath) {
        const imageKey = ad.imagePath.split('/').pop();
        if (imageKey) await deleteFromS3(`advertisements/${imageKey}`);
      }
    }

    await db.query('DELETE FROM Users WHERE id = ?', [id]);

    if (user[0].telegramId) {
      await telegramQueue.add({
        chatId: user[0].telegramId,
        text: `Ваш аккаунт (${user[0].email}) был удален администратором. Свяжитесь с поддержкой на ${WEBSITE_URL} для уточнения деталей.`,
      });
    }

    logger.info(`Пользователь ${user[0].email} удален вместе с связанными данными`);
    res.json({ message: 'Пользователь и связанные данные успешно удалены' });
  } catch (err) {
    logger.error(`Ошибка удаления пользователя: ${err.message}, стек: ${err.stack}`);
    res.status(500).json({ message: 'Ошибка сервера', error: err.message });
  }
});

app.get('/api/admin/advertisements', authenticateToken, async (req, res) => {
  try {
    const [user] = await db.query('SELECT email, accountType FROM Users WHERE id = ?', [req.user.id]);
    if (!user.length || user[0].email !== 'admin@24webstudio.ru') {
      return res.status(403).json({ message: 'Требуется доступ администратора' });
    }

    const page = parseInt(req.query.page) || 1;
    const limit = parseInt(req.query.limit) || 10;
    const offset = (page - 1) * limit;

    const [ads] = await db.query(`
      SELECT a.*, u.email as userEmail, u.name as userName
      FROM Advertisements a
      JOIN Users u ON a.userId = u.id
      ORDER BY a.createdAt DESC
      LIMIT ? OFFSET ?
    `, [limit, offset]);

    const [total] = await db.query('SELECT COUNT(*) as count FROM Advertisements');
    res.json({
      advertisements: ads,
      pagination: {
        page,
        limit,
        total: total[0].count,
        totalPages: Math.ceil(total[0].count / limit),
      },
    });
  } catch (err) {
    logger.error(`Ошибка получения рекламы: ${err.message}, стек: ${err.stack}`);
    res.status(500).json({ message: 'Ошибка сервера', error: err.message });
  }
});

app.put('/api/admin/advertisements/:id', authenticateToken, async (req, res) => {
  const { id } = req.params;
  const { status } = req.body;

  try {
    const [user] = await db.query('SELECT email, accountType FROM Users WHERE id = ?', [req.user.id]);
    if (!user.length || user[0].email !== 'admin@24webstudio.ru') {
      return res.status(403).json({ message: 'Требуется доступ администратора' });
    }

    if (!['pending', 'approved', 'rejected'].includes(status)) {
      return res.status(400).json({ message: 'Недопустимый статус' });
    }

    const [ad] = await db.query('SELECT * FROM Advertisements WHERE id = ?', [id]);
    if (!ad.length) {
      return res.status(404).json({ message: 'Реклама не найдена' });
    }

    await db.query('UPDATE Advertisements SET status = ? WHERE id = ?', [status, id]);
    logger.info(`Статус рекламы ${id} обновлен на ${status}`);

    if (status !== 'pending') {
      const [adUser] = await db.query('SELECT email, telegramId FROM Users WHERE id = ?', [ad[0].userId]);
      if (adUser[0].telegramId) {
        await telegramQueue.add({
          chatId: adUser[0].telegramId,
          text: `Статус вашей рекламы "${ad[0].title}" обновлен на ${status}.\nПосетите ${WEBSITE_URL} для деталей.`,
        });
      }
    }

    res.json({ message: `Статус рекламы обновлен на ${status}` });
  } catch (err) {
    logger.error(`Ошибка обновления рекламы: ${err.message}, стек: ${err.stack}`);
    res.status(500).json({ message: 'Ошибка сервера', error: err.message });
  }
});

app.delete('/api/admin/advertisements/:id', authenticateToken, async (req, res) => {
  const { id } = req.params;

  try {
    const [user] = await db.query('SELECT email, accountType FROM Users WHERE id = ?', [req.user.id]);
    if (!user.length || user[0].email !== 'admin@24webstudio.ru') {
      return res.status(403).json({ message: 'Требуется доступ администратора' });
    }

    const [ad] = await db.query('SELECT imagePath FROM Advertisements WHERE id = ?', [id]);
    if (!ad.length) {
      return res.status(404).json({ message: 'Реклама не найдена' });
    }

    if (ad[0].imagePath) {
      const imageKey = ad[0].imagePath.split('/').pop();
      if (imageKey) await deleteFromS3(`advertisements/${imageKey}`);
    }

    await db.query('DELETE FROM Advertisements WHERE id = ?', [id]);
    logger.info(`Реклама ${id} удалена`);

    res.json({ message: 'Реклама удалена' });
  } catch (err) {
    logger.error(`Ошибка удаления рекламы: ${err.message}, стек: ${err.stack}`);
    res.status(500).json({ message: 'Ошибка сервера', error: err.message });
  }
});

app.post('/api/admin/notify-all', authenticateToken, async (req, res) => {
  const { message } = req.body;

  try {
    const [admin] = await db.query('SELECT email, accountType FROM Users WHERE id = ?', [req.user.id]);
    if (!admin.length || admin[0].email !== 'admin@24webstudio.ru') {
      return res.status(403).json({ message: 'Требуется доступ администратора' });
    }

    if (!message || typeof message !== 'string') {
      return res.status(400).json({ message: 'Требуется текст сообщения' });
    }

    const [users] = await db.query('SELECT telegramId, email FROM Users WHERE telegramId IS NOT NULL AND isBlocked = FALSE');
    let successCount = 0;
    let errorCount = 0;

    for (const user of users) {
      try {
        await telegramQueue.add({
          chatId: user.telegramId,
          text: `${message}\nПосетите ${WEBSITE_URL} для деталей.`,
        }, { attempts: 3, backoff: 5000 });
        successCount++;
      } catch (err) {
        logger.error(`Ошибка добавления уведомления для ${user.email}: ${err.message}`);
        errorCount++;
      }
    }

    logger.info(`Массовая рассылка завершена: успешно запланировано ${successCount}, ошибок ${errorCount}`);
    res.status(200).json({ 
      message: `Уведомления запланированы: ${successCount} пользователей`,
      successCount,
      errorCount
    });
  } catch (err) {
    logger.error(`Ошибка массовой рассылки: ${err.message}, стек: ${err.stack}`);
    res.status(500).json({ message: 'Ошибка сервера', error: err.message });
  }
});

// Обработка ошибок
app.use((err, req, res, next) => {
  logger.error(`Необработанная ошибка: ${err.message}, стек: ${err.stack}, маршрут: ${req.originalUrl}`);
  if (err instanceof multer.MulterError) {
    logger.warn(`Ошибка Multer: ${err.message}`);
    return res.status(400).json({ message: `Ошибка загрузки файла: ${err.message}` });
  }
  if (err.message.includes('Разрешены только')) {
    logger.warn(`Ошибка типа файла: ${err.message}`);
    return res.status(400).json({ message: err.message });
  }
  if (err.code === 'LIMIT_EXCEEDED') {
    logger.warn(`Превышен лимит запросов: ${req.ip}`);
    return res.status(429).json({ message: 'Слишком много запросов, попробуйте снова позже' });
  }
  res.status(500).json({ message: 'Ошибка сервера', error: err.message });
});

// Грациозное завершение работы
async function shutdown() {
  logger.info('Выполняется грациозное завершение работы...');
  try {
    await telegramQueue.close();
    await db.end();
    logger.info('Соединение с базой данных и очередью закрыто');
  } catch (err) {
    logger.error(`Ошибка при завершении работы: ${err.message}, стек: ${err.stack}`);
  }
  process.exit(0);
}

process.on('SIGINT', shutdown);
process.on('SIGTERM', shutdown);

// Запуск сервера
initializeServer();