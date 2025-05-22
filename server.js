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

// Константы для валидации файлов
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
const MAX_IMAGE_SIZE = 10 * 1024 * 1024; // 10 МБ
const MAX_APP_SIZE = 50 * 1024 * 1024; // 50 МБ
const MAX_DOCUMENT_SIZE = 10 * 1024 * 1024; // 10 МБ

// Ключевые слова, связанные с дизайном, для валидации описания
const DESIGN_RELATED_KEYWORDS = [
  'дизайн', 'интерфейс', 'визуал', 'цвет', 'тема', 'макет', 'шрифт', 'графика', 'стиль', 'оформление',
  'layout', 'UI', 'UX', 'interface', 'visual', 'color', 'theme', 'font', 'graphic', 'style', 'design'
];

// Валидация переменных окружения
const requiredEnvVars = ['JWT_SECRET', 'DB_HOST', 'DB_USER', 'DB_PASSWORD', 'DB_NAME', 'S3_ACCESS_KEY', 'S3_SECRET_KEY', 'BUCKET_NAME', 'TELEGRAM_BOT_TOKEN'];
for (const envVar of requiredEnvVars) {
  if (!process.env[envVar]) {
    console.error(`Ошибка: ${envVar} не установлена в переменных окружения`);
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

// Настройка клиента S3
const s3Client = new S3Client({
  endpoint: 'https://s3.twcstorage.ru',
  credentials: {
    accessKeyId: S3_ACCESS_KEY,
    secretAccessKey: S3_SECRET_KEY,
  },
  region: 'ru-1',
  forcePathStyle: true,
});

// Проверка подключения к S3
async function checkS3Connection() {
  try {
    await s3Client.send(new ListBucketsCommand({}));
    logger.info('Подключение к S3 успешно');
  } catch (err) {
    logger.error(`Ошибка подключения к S3: ${err.message}, стек: ${err.stack}`);
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

// Пул подключений к MySQL
const db = mysql.createPool({
  host: DB_HOST,
  user: DB_USER,
  password: DB_PASSWORD,
  database: DB_NAME,
  port: 3306,
  connectionLimit: 10,
  connectTimeout: 10000,
});

// Настройка Multer для загрузки файлов
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
        errorMessage = 'Для иконок разрешены только PNG, JPG, JPEG, GIF, WebP!';
      } else if (file.fieldname === 'apk') {
        validMimeTypes = VALID_APP_MIME_TYPES;
        validExtensions = VALID_APP_EXTENSIONS;
        errorMessage = 'Разрешены только файлы APK и AAB!';
      } else if (file.fieldname === 'documents') {
        validMimeTypes = VALID_DOCUMENT_MIME_TYPES;
        validExtensions = VALID_DOCUMENT_EXTENSIONS;
        errorMessage = 'Для документов разрешены только PDF, PNG, JPG, JPEG, GIF, WebP!';
      } else {
        logger.warn(`Недопустимое имя поля: ${file.fieldname}`);
        return cb(new Error('Недопустимое имя поля!'));
      }

      const extname = validExtensions.test(path.extname(file.originalname).toLowerCase());
      const mimetype = validMimeTypes.includes(file.mimetype);

      if (extname && mimetype) {
        return cb(null, true);
      }

      logger.warn(`Недопустимый файл: поле=${file.fieldname}, имя=${file.originalname}, MIME=${file.mimetype}`);
      cb(new Error(errorMessage));
    } catch (err) {
      logger.error(`Ошибка фильтра Multer: ${err.message}, стек: ${err.stack}`);
      cb(err);
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
    if (file.size > (folder === 'apks' ? MAX_APP_SIZE : MAX_IMAGE_SIZE)) {
      throw new Error(`Файл слишком большой: ${file.originalname}`);
    }

    const upload = new Upload({
      client: s3Client,
      params,
      timeout: 30000,
    });
    const result = await upload.done();
    const location = `https://s3.twcstorage.ru/${BUCKET_NAME}/${key}`;
    logger.info(`Файл загружен в S3: ${key}, URL: ${location}`);
    return location;
  } catch (error) {
    logger.error(`Ошибка загрузки в S3 для ${key}: ${error.message}, стек: ${error.stack}`);
    throw new Error(`Ошибка загрузки в S3: ${error.message}`);
  }
}

// Функция удаления из S3
async function deleteFromS3(key) {
  const params = { Bucket: BUCKET_NAME, Key: key };
  try {
    await s3Client.send(new DeleteObjectCommand(params));
    logger.info(`Файл удалён из S3: ${key}`);
  } catch (err) {
    logger.error(`Ошибка удаления из S3: ${err.message}, стек: ${err.stack}`);
    throw err;
  }
}

// Функция получения из S3
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

// Middleware для аутентификации JWT
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
    return res.status(403).json({ message: 'Недействительный или истёкший токен', error: error.message });
  }
};

// Опциональная аутентификация JWT
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

// Настройка очереди уведомлений Telegram
const telegramQueue = new Queue('telegram-notifications', REDIS_URL, {
  limiter: { max: 30, duration: 1000 },
});

// Обработка задач очереди
telegramQueue.process(async (job) => {
  const { chatId, text } = job.data;
  try {
    await axios.post(
      `https://api.telegram.org/bot${TELEGRAM_BOT_TOKEN}/sendMessage`,
      { chat_id: chatId, text, parse_mode: 'Markdown' },
      { timeout: 10000 }
    );
    logger.info(`Уведомление отправлено в Telegram ${chatId}: ${text}`);
  } catch (err) {
    logger.error(`Ошибка уведомления Telegram ${chatId}: ${err.message}, стек: ${err.stack}`);
    throw err;
  }
});

// Проверка описания на наличие предложений по дизайну
function containsDesignSuggestions(description) {
  const lowerDescription = description.toLowerCase();
  return DESIGN_RELATED_KEYWORDS.some(keyword => lowerDescription.includes(keyword));
}

// Инициализация базы данных
async function initializeDatabase() {
  try {
    const connection = await db.getConnection();
    logger.info('Подключение к MySQL установлено');

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

    // Проверка и добавление отсутствующих столбцов
    const [columns] = await connection.query(`SHOW COLUMNS FROM Users`);
    const columnNames = columns.map(col => col.Field);
    if (!columnNames.includes('telegramId')) {
      await connection.query(`ALTER TABLE Users ADD COLUMN telegramId VARCHAR(255) UNIQUE`);
      logger.info('Добавлен столбец telegramId');
    }
    if (!columnNames.includes('verificationToken')) {
      await connection.query(`ALTER TABLE Users ADD COLUMN verificationToken VARCHAR(500)`);
      logger.info('Добавлен столбец verificationToken');
    }
    if (!columnNames.includes('verificationExpires')) {
      await connection.query(`ALTER TABLE Users ADD COLUMN verificationExpires DATETIME`);
      logger.info('Добавлен столбец verificationExpires');
    }
    if (!columnNames.includes('isBlocked')) {
      await connection.query(`ALTER TABLE Users ADD COLUMN isBlocked BOOLEAN DEFAULT FALSE`);
      logger.info('Добавлен столбец isBlocked');
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
        rejectionReason TEXT,
        isPublished BOOLEAN DEFAULT FALSE,
        createdAt TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        updatedAt TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
        FOREIGN KEY (userId) REFERENCES Users(id) ON DELETE CASCADE
      )
    `);
    logger.info('Таблица Apps проверена/создана');

    // Проверка и добавление столбцов в таблицу Apps
    const [appColumns] = await connection.query(`SHOW COLUMNS FROM Apps`);
    const appColumnNames = appColumns.map(col => col.Field);
    if (!appColumnNames.includes('rejectionReason')) {
      await connection.query(`ALTER TABLE Apps ADD COLUMN rejectionReason TEXT`);
      logger.info('Добавлен столбец rejectionReason в таблицу Apps');
    }
    if (!appColumnNames.includes('isPublished')) {
      await connection.query(`ALTER TABLE Apps ADD COLUMN isPublished BOOLEAN DEFAULT FALSE`);
      logger.info('Добавлен столбец isPublished в таблицу Apps');
    }



    // Создание таблицы Comments
await connection.query(`
  CREATE TABLE IF NOT EXISTS Comments (
    id INT AUTO_INCREMENT PRIMARY KEY,
    appId INT NOT NULL,
    userId INT NOT NULL,
    userName VARCHAR(255) NOT NULL,
    comment TEXT NOT NULL,
    createdAt TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updatedAt TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    FOREIGN KEY (appId) REFERENCES Apps(id) ON DELETE CASCADE,
    FOREIGN KEY (userId) REFERENCES Users(id) ON DELETE CASCADE
  )
`);
logger.info('Таблица Comments проверена/создана');

// Проверка и добавление столбца downloadCount в таблицу Apps
if (!appColumnNames.includes('downloadCount')) {
  await connection.query(`ALTER TABLE Apps ADD COLUMN downloadCount INT DEFAULT 0`);
  logger.info('Добавлен столбец downloadCount в таблицу Apps');
}

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

    // Создание администратора по умолчанию
    const [users] = await connection.query("SELECT * FROM Users WHERE email = ?", ['admin@24webstudio.ru']);
    if (users.length === 0) {
      const hashedPassword = await bcrypt.hash('admin123', 10);
      await connection.query(
        "INSERT INTO Users (email, password, accountType, name, phone, isVerified) VALUES (?, ?, ?, ?, ?, ?)",
        ['admin@24webstudio.ru', hashedPassword, 'commercial', 'Admin', '1234567890', true]
      );
      logger.info('Администратор создан: admin@24webstudio.ru / admin123');
    } else {
      logger.info('Администратор уже существует: admin@24webstudio.ru');
    }

    connection.release();
  } catch (err) {
    logger.error(`Ошибка инициализации базы данных: ${err.message}, стек: ${err.stack}`);
    throw err;
  }
}

// Инициализация Telegram-бота
const bot = new TelegramBot(TELEGRAM_BOT_TOKEN, { polling: true });

// Обработка команды /start
bot.onText(/\/start/, async (msg) => {
  const chatId = msg.chat.id;
  logger.info(`Получена команда /start от Telegram ID: ${chatId}`);

  try {
    const [user] = await db.query('SELECT email, isVerified FROM Users WHERE telegramId = ?', [chatId]);
    if (user.length > 0) {
      if (user[0].isVerified) {
        bot.sendMessage(chatId, 'Ваш аккаунт уже верифицирован.');
      } else {
        bot.sendMessage(chatId, `Ваш аккаунт привязан к email: ${user[0].email}. Ожидается верификация документов администратором.`);
      }
    } else {
      bot.sendMessage(chatId, 'Пожалуйста, введите email, использованный при регистрации:');
      bot.once('message', async (msg) => {
        const email = msg.text.trim();
        if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
          bot.sendMessage(chatId, 'Недействительный email. Попробуйте снова с /start.');
          return;
        }

        const [existingUser] = await db.query('SELECT id, isVerified FROM Users WHERE email = ?', [email]);
        if (!existingUser.length) {
          bot.sendMessage(chatId, 'Email не найден. Пожалуйста, зарегистрируйтесь на сайте.');
          return;
        }

        if (existingUser[0].isVerified) {
          bot.sendMessage(chatId, 'Ваш аккаунт уже верифицирован.');
          return;
        }

        await db.query('UPDATE Users SET telegramId = ? WHERE email = ?', [chatId, email]);
        bot.sendMessage(chatId, 'Ваш email успешно привязан. Ожидается верификация документов администратором.');
        logger.info(`Telegram ID ${chatId} привязан к email: ${email}`);
      });
    }
  } catch (err) {
    logger.error(`Ошибка обработки /start: ${err.message}, стек: ${err.stack}`);
    bot.sendMessage(chatId, 'Произошла ошибка. Попробуйте снова позже.');
  }
});

// Обработка команды /status
bot.onText(/\/status/, async (msg) => {
  const chatId = msg.chat.id;
  logger.info(`Получена команда /status от Telegram ID: ${chatId}`);

  try {
    const [user] = await db.query('SELECT email, isVerified, isBlocked FROM Users WHERE telegramId = ?', [chatId]);
    if (!user.length) {
      bot.sendMessage(chatId, 'Ваш Telegram ID не привязан к аккаунту. Используйте /start для привязки email.');
      return;
    }

    if (user[0].isBlocked) {
      bot.sendMessage(chatId, 'Ваш аккаунт заблокирован. Свяжитесь с администратором.');
      return;
    }

    const [apps] = await db.query('SELECT name, status, isPublished FROM Apps WHERE userId = (SELECT id FROM Users WHERE telegramId = ?)', [chatId]);
    let response = `Статус аккаунта (${user[0].email}): ${user[0].isVerified ? 'Верифицирован' : 'Ожидает верификации'}\n\n`;
    response += 'Ваши приложения:\n';
    if (apps.length === 0) {
      response += 'У вас нет приложений.';
    } else {
      apps.forEach(app => {
        response += `- ${app.name}: ${app.status}, ${app.isPublished ? 'Опубликовано' : 'Не опубликовано'}\n`;
      });
    }

    bot.sendMessage(chatId, response);
  } catch (err) {
    logger.error(`Ошибка обработки /status: ${err.message}, стек: ${err.stack}`);
    bot.sendMessage(chatId, 'Произошла ошибка. Попробуйте снова позже.');
  }
});

// Обработка команды /help
bot.onText(/\/help/, (msg) => {
  const chatId = msg.chat.id;
  logger.info(`Получена команда /help от Telegram ID: ${chatId}`);
  bot.sendMessage(chatId, `Доступные команды:\n/start - Привязать Telegram к аккаунту\n/status - Проверить статус аккаунта и приложений\n/help - Показать это сообщение`);
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

// Публичные маршруты
// Получение одобренных и опубликованных приложений
app.get('/api/public/apps', async (req, res) => {
  try {
    const [apps] = await db.query(`
      SELECT id, name, description, category, iconPath, status, createdAt, isPublished
      FROM Apps
      WHERE status = 'approved' AND isPublished = TRUE
      ORDER BY createdAt DESC
    `);
    res.json(apps);
  } catch (err) {
    logger.error(`Ошибка получения приложений: ${err.message}, стек: ${err.stack}`);
    res.status(500).json({ message: 'Ошибка сервера', error: err.message });
  }
});

// Получение публичной страницы приложения
app.get('/api/public/apps/:id', async (req, res) => {
  const { id } = req.params;

  try {
    const [app] = await db.query(`
      SELECT a.id, a.name, a.description, a.category, a.iconPath, a.apkPath, a.createdAt, a.isPublished, a.status, a.downloadCount,
             u.name AS developerName
      FROM Apps a
      JOIN Users u ON a.userId = u.id
      WHERE a.id = ? AND a.status = 'approved' AND a.isPublished = TRUE
    `, [id]);

    if (!app.length) {
      logger.warn(`Публичное приложение не найдено для ID: ${id}`);
      return res.status(404).json({ message: 'Приложение не найдено или не опубликовано' });
    }

    const [comments] = await db.query(`
      SELECT userName, comment, createdAt
      FROM Comments
      WHERE appId = ?
      ORDER BY createdAt DESC
    `, [id]);

    res.json({
      id: app[0].id,
      name: app[0].name,
      description: app[0].description,
      category: app[0].category,
      iconUrl: app[0].iconPath,
      apkUrl: app[0].apkPath,
      createdAt: app[0].createdAt,
      developerName: app[0].developerName,
      downloadCount: app[0].downloadCount,
      comments: comments.map(comment => ({
        userName: comment.userName,
        comment: comment.comment,
        createdAt: comment.createdAt,
      })),
    });
  } catch (err) {
    logger.error(`Ошибка получения публичного приложения ID: ${id}: ${err.message}, стек: ${err.stack}`);
    res.status(500).json({ message: 'Ошибка сервера', error: err.message });
  }
});
// Получение изображения приложения
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

// Получение конкретного приложения по ID
app.get('/api/apps/:id', authenticateToken, async (req, res) => {
  const { id } = req.params;
  try {
    const [app] = await db.query(`
      SELECT id, name, description, category, iconPath AS iconUrl, apkPath AS apkUrl, status, rejectionReason, createdAt, isPublished
      FROM Apps
      WHERE id = ? AND userId = ?
    `, [id, req.user.id]);

    if (!app.length) {
      logger.warn(`Приложение не найдено для ID: ${id}, пользователь: ${req.user.email}`);
      return res.status(404).json({ message: 'Приложение не найдено' });
    }

    logger.info(`Получено приложение ID: ${id} для пользователя: ${req.user.email}`);
    res.json(app[0]);
  } catch (err) {
    logger.error(`Ошибка получения приложения ID: ${id}: ${err.message}, стек: ${err.stack}`);
    res.status(500).json({ message: 'Ошибка сервера', error: err.message });
  }
});

// Предрегистрация пользователя
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

      res.status(201).json({ message: `Спасибо! Ваш email (${email}) добавлен в список ожидания.` });
    } catch (error) {
      logger.error(`Ошибка предрегистрации: ${error.message}, стек: ${error.stack}`);
      res.status(500).json({ message: 'Ошибка сервера', error: error.message });
    }
  }
);


app.post('/api/public/apps/:id/increment-download', async (req, res) => {
  const { id } = req.params;

  try {
    const [app] = await db.query('SELECT id FROM Apps WHERE id = ? AND status = "approved" AND isPublished = TRUE', [id]);
    if (!app.length) {
      logger.warn(`Приложение не найдено для увеличения скачиваний, ID: ${id}`);
      return res.status(404).json({ message: 'Приложение не найдено или не опубликовано' });
    }

    await db.query('UPDATE Apps SET downloadCount = downloadCount + 1 WHERE id = ?', [id]);
    logger.info(`Счетчик скачиваний увеличен для приложения ID: ${id}`);
    res.status(200).json({ message: 'Счетчик скачиваний увеличен' });
  } catch (err) {
    logger.error(`Ошибка увеличения счетчика скачиваний для ID: ${id}: ${err.message}, стек: ${err.stack}`);
    res.status(500).json({ message: 'Ошибка сервера', error: err.message });
  }
});
// Регистрация пользователя
app.post(
  '/api/auth/register',
  upload,
  [
    body('email').isEmail().normalizeEmail().withMessage('Требуется действительный email'),
    body('password').isLength({ min: 8 }).withMessage('Пароль должен содержать не менее 8 символов'),
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

      const documentUrls = await Promise.all(req.files.documents.map(file =>
        Promise.race([
          uploadToS3(file, 'documents'),
          new Promise((_, reject) => setTimeout(() => reject(new Error('Тайм-аут загрузки документа')), 30000))
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
        text: `Новые документы на проверку от пользователя ${email} (регистрация). Количество: ${documentUrls.length}`,
      }, { attempts: 3, backoff: 5000 });

      if (telegramId) {
        telegramQueue.add({
          chatId: telegramId,
          text: `Добро пожаловать, ${name}! Ваши документы отправлены на проверку. Вы получите уведомление после верификации.`,
        }, { attempts: 3, backoff: 5000 });
      }

      logger.info(`Пользователь зарегистрирован: ${email}, документы: ${JSON.stringify(documentUrls)}`);
      res.status(201).json({
        message: telegramId
          ? 'Регистрация успешна. Ваши документы отправлены на проверку.'
          : 'Регистрация успешна. Пожалуйста, укажите ваш Telegram ID в профиле или через бота для получения уведомлений.',
        token: authToken,
        user: { id: result.insertId, email, accountType, name, phone, telegramId, isVerified: false },
      });
    } catch (error) {
      logger.error(`Ошибка регистрации: ${error.message}, стек: ${error.stack}`);
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
      const [user] = await db.query('SELECT * FROM Users WHERE email = ?', [email]);
      if (!user.length) {
        logger.warn(`Попытка входа с несуществующим email: ${email}`);
        return res.status(400).json({ message: 'Недействительный email или пароль' });
      }

      if (user[0].isBlocked) {
        logger.warn(`Попытка входа заблокированным пользователем: ${email}`);
        return res.status(403).json({ message: 'Ваш аккаунт заблокирован' });
      }

      const isMatch = await bcrypt.compare(password, user[0].password);
      if (!isMatch) {
        logger.warn(`Неверный пароль для email: ${email}`);
        return res.status(400).json({ message: 'Недействительный email или пароль' });
      }

      const token = jwt.sign({ id: user[0].id, email: user[0].email }, JWT_SECRET, { expiresIn: '7d' });
      await db.query('UPDATE Users SET jwtToken = ? WHERE id = ?', [token, user[0].id]);

      logger.info(`Пользователь вошёл: ${user[0].email}`);
      res.status(200).json({
        token,
        user: { id: user[0].id, email: user[0].email, accountType: user[0].accountType, name: user[0].name, phone: user[0].phone, telegramId: user[0].telegramId, isVerified: user[0].isVerified },
        message: user[0].isVerified ? 'Вход успешен' : 'Вход успешен, но аккаунт ожидает верификации документов',
      });
    } catch (error) {
      logger.error(`Ошибка входа: ${error.message}, стек: ${error.stack}`);
      res.status(500).json({ message: 'Ошибка сервера', error: error.message });
    }
  }
);

// Сброс пароля
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
        telegramQueue.add({
          chatId: user[0].telegramId,
          text: `Запрос на сброс пароля. Перейдите по ссылке: https://your-app-domain.com/reset-password/${resetToken}`,
        }, { attempts: 3, backoff: 5000 });
      }

      logger.info(`Запрос на сброс пароля для ${user[0].email}`);
      res.status(200).json({ message: 'Ссылка для сброса пароля отправлена в Telegram, если он привязан' });
    } catch (error) {
      logger.error(`Ошибка сброса пароля: ${error.message}, стек: ${error.stack}`);
      res.status(500).json({ message: 'Ошибка сервера', error: error.message });
    }
  }
);

// Сброс пароля
app.post(
  '/api/auth/reset-password/:token',
  [
    body('password').isLength({ min: 8 }).withMessage('Пароль должен содержать не менее 8 символов'),
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
        return res.status(400).json({ message: 'Недействительный или истёкший токен' });
      }

      const [user] = await db.query(
        'SELECT id, email FROM Users WHERE email = ? AND resetPasswordToken = ? AND resetPasswordExpires > NOW()',
        [decoded.email, token]
      );
      if (!user.length) {
        logger.warn(`Недействительный или истёкший токен сброса для email: ${decoded.email}`);
        return res.status(400).json({ message: 'Недействительный или истёкший токен' });
      }

      const salt = await bcrypt.genSalt(10);
      const hashedPassword = await bcrypt.hash(password, salt);
      await db.query(
        'UPDATE Users SET password = ?, resetPasswordToken = NULL, resetPasswordExpires = NULL, jwtToken = NULL WHERE email = ?',
        [hashedPassword, decoded.email]
      );

      logger.info(`Пароль сброшен для ${user[0].email}`);
      res.status(200).json({ message: 'Пароль успешно сброшен' });
    } catch (error) {
      logger.error(`Ошибка сброса пароля: ${error.message}, стек: ${error.stack}`);
      res.status(500).json({ message: 'Ошибка сервера', error: error.message });
    }
  }
);

// Получение профиля пользователя
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

// Получение приложений пользователя
app.get('/api/apps', authenticateToken, async (req, res) => {
  try {
    const [apps] = await db.query(`
      SELECT id, name, description, category, iconPath AS iconUrl, apkPath AS apkUrl, status, rejectionReason, createdAt, isPublished
      FROM Apps
      WHERE userId = ?
      ORDER BY createdAt DESC
    `, [req.user.id]);

    logger.info(`Получено ${apps.length} приложений для пользователя ${req.user.email}`);
    res.json(apps);
  } catch (err) {
    logger.error(`Ошибка получения приложений пользователя: ${err.message}, стек: ${err.stack}`);
    res.status(500).json({ message: 'Ошибка сервера', error: err.message });
  }
});

// Загрузка документов пользователя
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

      const newDocuments = await Promise.all(req.files.documents.map(file =>
        Promise.race([
          uploadToS3(file, 'documents'),
          new Promise((_, reject) => setTimeout(() => reject(new Error('Тайм-аут загрузки документа')), 30000))
        ])
      ));

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

      telegramQueue.add({
        chatId: '-1002311447135',
        text: `Новые документы на проверку от пользователя ${user[0].email}. Количество: ${newDocuments.length}`,
      }, { attempts: 3, backoff: 5000 });

      if (user[0].telegramId) {
        telegramQueue.add({
          chatId: user[0].telegramId,
          text: `Ваши новые документы отправлены на проверку. Вы получите уведомление после верификации.`,
        }, { attempts: 3, backoff: 5000 });
      }

      logger.info(`Документы обновлены для пользователя ${user[0].email}, новые документы: ${JSON.stringify(updatedDocuments)}`);
      res.status(200).json({
        message: 'Документы успешно загружены и ожидают проверки администратора',
        documents: updatedDocuments
      });
    } catch (error) {
      logger.error(`Ошибка загрузки документов: ${error.message}, стек: ${error.stack}`);
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
      const [user] = await db.query('SELECT id, email, isVerified, telegramId FROM Users WHERE id = ?', [req.user.id]);
      if (!user.length) {
        logger.warn(`Пользователь не найден для ID: ${req.user.id}`);
        return res.status(404).json({ message: 'Пользователь не найден' });
      }

      if (!user[0].isVerified) {
        logger.warn(`Неверифицированный пользователь: ${user[0].email}`);
        return res.status(403).json({ message: 'Аккаунт должен быть верифицирован для отправки приложений' });
      }

      const { name, description, category } = req.body;
      const files = req.files;

      if (containsDesignSuggestions(description)) {
        logger.warn(`Обнаружены предложения по дизайну в описании для приложения: ${name}, пользователь: ${user[0].email}`);
        if (user[0].telegramId) {
          telegramQueue.add({
            chatId: user[0].telegramId,
            text: `Ваше приложение "${name}" было отклонено, так как его описание содержит предложения по дизайну (например, UI, UX, цвет). Пожалуйста, исправьте и отправьте снова.`,
          }, { attempts: 3, backoff: 5000 });
        }
        return res.status(400).json({
          message: 'Описание содержит предложения по дизайну. Пожалуйста, исправьте и отправьте снова.',
        });
      }

      if (!files || !files.icon || !files.icon[0]) {
        logger.warn('Отсутствует файл иконки');
        return res.status(400).json({ message: 'Требуется файл иконки (PNG, JPG, JPEG, GIF, WebP)' });
      }
      if (!files.apk || !files.apk[0]) {
        logger.warn('Отсутствует файл приложения');
        return res.status(400).json({ message: 'Требуется файл приложения (APK или AAB)' });
      }

      const [iconUrl, apkUrl] = await Promise.all([
        Promise.race([
          uploadToS3(files.icon[0], 'icons'),
          new Promise((_, reject) => setTimeout(() => reject(new Error('Тайм-аут загрузки иконки')), 30000))
        ]),
        Promise.race([
          uploadToS3(files.apk[0], 'apks'),
          new Promise((_, reject) => setTimeout(() => reject(new Error('Тайм-аут загрузки приложения')), 30000))
        ])
      ]);

      const [result] = await db.query(
        `INSERT INTO Apps (
          name, description, category, iconPath, apkPath, userId, status, isPublished
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
        [name, description, category, iconUrl, apkUrl, user[0].id, 'pending', false]
      );

      logger.info(`Приложение создано пользователем ${user[0].email}: ${name}`);

      telegramQueue.add({
        chatId: '-1002311447135',
        text: `Новое приложение отправлено: ${name} от ${user[0].email}`,
      }, { attempts: 3, backoff: 5000 });

      res.status(201).json({
        message: 'Приложение успешно отправлено',
        app: { id: result.insertId, name, description, category, iconPath: iconUrl, apkPath: apkUrl, userId: user[0].id, status: 'pending', isPublished: false },
      });
    } catch (error) {
      logger.error(`Ошибка создания приложения: ${error.message}, стек: ${error.stack}`);
      res.status(500).json({ message: 'Ошибка сервера', error: error.message });
    }
  }
);

// Обновление приложения
app.put(
  '/api/apps/:id',
  authenticateToken,
  upload,
  [
    body('name').notEmpty().trim().withMessage('Требуется название приложения'),
    body('description').notEmpty().trim().withMessage('Требуется описание'),
    body('category').isIn(['games', 'productivity', 'education', 'entertainment']).withMessage('Недопустимая категория'),
  ],
  async (req, res) => {
    const { id } = req.params;
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      logger.warn(`Ошибки валидации: ${JSON.stringify(errors.array())}`);
      return res.status(400).json({ message: 'Ошибка валидации', errors: errors.array() });
    }

    try {
      const [user] = await db.query('SELECT id, email, isVerified, telegramId FROM Users WHERE id = ?', [req.user.id]);
      if (!user.length) {
        logger.warn(`Пользователь не найден для ID: ${req.user.id}`);
        return res.status(404).json({ message: 'Пользователь не найден' });
      }

      if (!user[0].isVerified) {
        logger.warn(`Неверифицированный пользователь: ${user[0].email}`);
        return res.status(403).json({ message: 'Аккаунт должен быть верифицирован для обновления приложений' });
      }

      const [app] = await db.query('SELECT * FROM Apps WHERE id = ? AND userId = ?', [id, user[0].id]);
      if (!app.length) {
        logger.warn(`Приложение не найдено для ID: ${id}, пользователь: ${user[0].email}`);
        return res.status(404).json({ message: 'Приложение не найдено' });
      }

      const { name, description, category } = req.body;
      const files = req.files;
      let iconUrl = app[0].iconPath;
      let apkUrl = app[0].apkPath;

      if (containsDesignSuggestions(description)) {
        logger.warn(`Обнаружены предложения по дизайну в описании для приложения ID: ${id}, пользователь: ${user[0].email}`);
        
        if (app[0].iconPath) {
          const iconKey = app[0].iconPath.split('/').pop();
          if (iconKey) await deleteFromS3(`icons/${iconKey}`);
        }
        if (app[0].apkPath) {
          const apkKey = app[0].apkPath.split('/').pop();
          if (apkKey) await deleteFromS3(`apks/${apkKey}`);
        }

        await db.query('DELETE FROM Apps WHERE id = ?', [id]);
        logger.info(`Приложение ID: ${id} удалено из-за предложений по дизайну`);

        if (user[0].telegramId) {
          telegramQueue.add({
            chatId: user[0].telegramId,
            text: `Ваше приложение "${app[0].name}" (ID: ${id}) было удалено, так как обновлённое описание содержит предложения по дизайну (например, UI, UX, цвет). Пожалуйста, исправьте и отправьте снова.`,
          }, { attempts: 3, backoff: 5000 });
        }

        return res.status(400).json({
          message: 'Описание содержит предложения по дизайну. Приложение удалено. Пожалуйста, исправьте и отправьте снова.',
        });
      }

      if (files && files.icon && files.icon[0]) {
        if (app[0].iconPath) {
          const oldIconKey = app[0].iconPath.split('/').pop();
          if (oldIconKey) await deleteFromS3(`icons/${oldIconKey}`);
        }
        iconUrl = await Promise.race([
          uploadToS3(files.icon[0], 'icons'),
          new Promise((_, reject) => setTimeout(() => reject(new Error('Тайм-аут загрузки иконки')), 30000))
        ]);
      }

      if (files && files.apk && files.apk[0]) {
        if (app[0].apkPath) {
          const oldApkKey = app[0].apkPath.split('/').pop();
          if (oldApkKey) await deleteFromS3(`apks/${oldApkKey}`);
        }
        apkUrl = await Promise.race([
          uploadToS3(files.apk[0], 'apks'),
          new Promise((_, reject) => setTimeout(() => reject(new Error('Тайм-аут загрузки приложения')), 30000))
        ]);
      }

      await db.query(
        `UPDATE Apps SET name = ?, description = ?, category = ?, iconPath = ?, apkPath = ?, status = 'pending', isPublished = FALSE WHERE id = ?`,
        [name, description, category, iconUrl, apkUrl, id]
      );

      logger.info(`Приложение ID: ${id} обновлено пользователем ${user[0].email}`);

      telegramQueue.add({
        chatId: '-1002311447135',
        text: `Приложение обновлено: ${name} (ID: ${id}) от ${user[0].email}`,
      }, { attempts: 3, backoff: 5000 });

      if (user[0].telegramId) {
        telegramQueue.add({
          chatId: user[0].telegramId,
          text: `Ваше приложение "${name}" (ID: ${id}) обновлено и ожидает проверки. Статус публикации сброшен.`,
        }, { attempts: 3, backoff: 5000 });
      }

      res.status(200).json({
        message: 'Приложение успешно обновлено',
        app: { id, name, description, category, iconPath: iconUrl, apkPath: apkUrl, userId: user[0].id, status: 'pending', isPublished: false },
      });
    } catch (error) {
      logger.error(`Ошибка обновления приложения для ID: ${id}: ${error.message}, стек: ${error.stack}`);
      res.status(500).json({ message: 'Ошибка сервера', error: error.message });
    }
  }
);

// Удаление приложения (для пользователя)
app.delete('/api/apps/:id', authenticateToken, async (req, res) => {
  const { id } = req.params;

  try {
    const [user] = await db.query('SELECT id, email, telegramId FROM Users WHERE id = ?', [req.user.id]);
    if (!user.length) {
      logger.warn(`Пользователь не найден для ID: ${req.user.id}`);
      return res.status(404).json({ message: 'Пользователь не найден' });
    }

    const [app] = await db.query('SELECT iconPath, apkPath, name FROM Apps WHERE id = ? AND userId = ?', [id, user[0].id]);
    if (!app.length) {
      logger.warn(`Приложение не найдено для ID: ${id}, пользователь: ${user[0].email}`);
      return res.status(404).json({ message: 'Приложение не найдено' });
    }

    // Удаление файлов из S3
    if (app[0].iconPath) {
      const iconKey = app[0].iconPath.split('/').pop();
      if (iconKey) await deleteFromS3(`icons/${iconKey}`);
    }
    if (app[0].apkPath) {
      const apkKey = app[0].apkPath.split('/').pop();
      if (apkKey) await deleteFromS3(`apks/${apkKey}`);
    }

    await db.query('DELETE FROM Apps WHERE id = ?', [id]);
    logger.info(`Приложение ${id} удалено пользователем ${user[0].email}`);

    if (user[0].telegramId) {
      telegramQueue.add({
        chatId: user[0].telegramId,
        text: `Приложение "${app[0].name}" (ID: ${id}) успешно удалено.`,
      }, { attempts: 3, backoff: 5000 });
    }

    res.json({ message: 'Приложение успешно удалено' });
  } catch (err) {
    logger.error(`Ошибка удаления приложения: ${err.message}, стек: ${err.stack}`);
    res.status(500).json({ message: 'Ошибка сервера', error: err.message });
  }
});

// Дублирование приложения
app.post('/api/apps/:id/duplicate', authenticateToken, async (req, res) => {
  const { id } = req.params;

  try {
    const [user] = await db.query('SELECT id, email, telegramId FROM Users WHERE id = ?', [req.user.id]);
    if (!user.length) {
      logger.warn(`Пользователь не найден для ID: ${req.user.id}`);
      return res.status(404).json({ message: 'Пользователь не найден' });
    }

    const [app] = await db.query('SELECT * FROM Apps WHERE id = ? AND userId = ?', [id, user[0].id]);
    if (!app.length) {
      logger.warn(`Приложение не найдено для ID: ${id}, пользователь: ${user[0].email}`);
      return res.status(404).json({ message: 'Приложение не найдено' });
    }

    const duplicatedApp = app[0];
    const newName = `${duplicatedApp.name} (Copy)`;

    // Копирование файлов в S3
    const [newIconUrl, newApkUrl] = await Promise.all([
      (async () => {
        const iconKey = duplicatedApp.iconPath.split('/').pop();
        const iconData = await getFromS3(`icons/${iconKey}`);
        const newIconKey = `icons/${Date.now()}-${iconKey}`;
        await s3Client.send(new PutObjectCommand({
          Bucket: BUCKET_NAME,
          Key: newIconKey,
          Body: iconData.Body,
          ContentType: iconData.ContentType,
          ACL: 'public-read',
        }));
        return `https://s3.twcstorage.ru/${BUCKET_NAME}/${newIconKey}`;
      })(),
      (async () => {
        const apkKey = duplicatedApp.apkPath.split('/').pop();
        const apkData = await getFromS3(`apks/${apkKey}`);
        const newApkKey = `apks/${Date.now()}-${apkKey}`;
        await s3Client.send(new PutObjectCommand({
          Bucket: BUCKET_NAME,
          Key: newApkKey,
          Body: apkData.Body,
          ContentType: apkData.ContentType,
          ACL: 'public-read',
        }));
        return `https://s3.twcstorage.ru/${BUCKET_NAME}/${newApkKey}`;
      })(),
    ]);

    const [result] = await db.query(
      `INSERT INTO Apps (
        name, description, category, iconPath, apkPath, userId, status, isPublished
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
      [
        newName,
        duplicatedApp.description,
        duplicatedApp.category,
        newIconUrl,
        newApkUrl,
        user[0].id,
        'pending',
        false
      ]
    );

    logger.info(`Приложение ${id} дублировано пользователем ${user[0].email}, новый ID: ${result.insertId}`);

    if (user[0].telegramId) {
      telegramQueue.add({
        chatId: user[0].telegramId,
        text: `Приложение "${duplicatedApp.name}" успешно дублировано как "${newName}" (ID: ${result.insertId}).`,
      }, { attempts: 3, backoff: 5000 });
    }

    res.status(201).json({
      message: 'Приложение успешно дублировано',
      app: {
        id: result.insertId,
        name: newName,
        description: duplicatedApp.description,
        category: duplicatedApp.category,
        iconUrl: newIconUrl,
        apkUrl: newApkUrl,
        status: 'pending',
        isPublished: false,
      },
    });
  } catch (err) {
    logger.error(`Ошибка дублирования приложения: ${err.message}, стек: ${err.stack}`);
    res.status(500).json({ message: 'Ошибка сервера', error: err.message });
  }
});

// Публикация/снятие с публикации приложения
app.put('/api/apps/:id/publish', authenticateToken, async (req, res) => {
  const { id } = req.params;
  const { isPublished } = req.body;

  try {
    if (typeof isPublished !== 'boolean') {
      return res.status(400).json({ message: 'Недопустимый статус публикации' });
    }

    const [user] = await db.query('SELECT id, email, telegramId FROM Users WHERE id = ?', [req.user.id]);
    if (!user.length) {
      logger.warn(`Пользователь не найден для ID: ${req.user.id}`);
      return res.status(404).json({ message: 'Пользователь не найден' });
    }

    const [app] = await db.query('SELECT name, status FROM Apps WHERE id = ? AND userId = ?', [id, user[0].id]);
    if (!app.length) {
      logger.warn(`Приложение не найдено для ID: ${id}, пользователь: ${user[0].email}`);
      return res.status(404).json({ message: 'Приложение не найдено' });
    }

    if (isPublished && app[0].status !== 'approved') {
      logger.warn(`Попытка публикации неутверждённого приложения ID: ${id}, пользователь: ${user[0].email}`);
      return res.status(400).json({ message: 'Приложение должно быть одобрено перед публикацией' });
    }

    await db.query('UPDATE Apps SET isPublished = ? WHERE id = ?', [isPublished, id]);
    logger.info(`Статус публикации приложения ${id} обновлён на ${isPublished} пользователем ${user[0].email}`);

    if (user[0].telegramId) {
      telegramQueue.add({
        chatId: user[0].telegramId,
        text: `Приложение "${app[0].name}" (ID: ${id}) ${isPublished ? 'опубликовано' : 'снято с публикации'}.`,
      }, { attempts: 3, backoff: 5000 });
    }

    res.json({ message: `Приложение ${isPublished ? 'опубликовано' : 'снято с публикации'}` });
  } catch (err) {
    logger.error(`Ошибка изменения статуса публикации приложения: ${err.message}, стек: ${err.stack}`);
    res.status(500).json({ message: 'Ошибка сервера', error: err.message });
  }
});

// Маршруты администратора
// Получение всех приложений
app.get('/api/admin/apps', authenticateToken, async (req, res) => {
  try {
    const [user] = await db.query('SELECT email, accountType FROM Users WHERE id = ?', [req.user.id]);
    if (!user.length || user[0].email !== 'admin@24webstudio.ru') {
      return res.status(403).json({ message: 'Требуется доступ администратора' });
    }

    const [apps] = await db.query(`
      SELECT a.*, u.email as userEmail, u.name as userName
      FROM Apps a
      JOIN Users u ON a.userId = u.id
      ORDER BY a.createdAt DESC
    `);
    res.json(apps);
  } catch (err) {
    logger.error(`Ошибка получения приложений администратором: ${err.message}, стек: ${err.stack}`);
    res.status(500).json({ message: 'Ошибка сервера', error: err.message });
  }
});

// Обновление статуса приложения
app.put('/api/admin/apps/:id', authenticateToken, async (req, res) => {
  const { id } = req.params;
  const { status, rejectionReason } = req.body;

  try {
    const [user] = await db.query('SELECT email, accountType FROM Users WHERE id = ?', [req.user.id]);
    if (!user.length || user[0].email !== 'admin@24webstudio.ru') {
      return res.status(403).json({ message: 'Требуется доступ администратора' });
    }

    if (!['pending', 'approved', 'rejected'].includes(status)) {
      return res.status(400).json({ message: 'Недопустимый статус' });
    }

    if (status === 'rejected' && (!rejectionReason || typeof rejectionReason !== 'string')) {
      return res.status(400).json({ message: 'Причина отклонения обязательна при отклонении приложения' });
    }

    const [app] = await db.query('SELECT * FROM Apps WHERE id = ?', [id]);
    if (!app.length) {
      return res.status(404).json({ message: 'Приложение не найдено' });
    }

    await db.query('UPDATE Apps SET status = ?, rejectionReason = ?, isPublished = ? WHERE id = ?', [
      status,
      status === 'rejected' ? rejectionReason : null,
      status === 'approved' ? app[0].isPublished : false,
      id
    ]);
    logger.info(`Статус приложения ${id} обновлён на ${status}`);

    if (status !== 'pending') {
      const [appUser] = await db.query('SELECT email, telegramId, name FROM Users WHERE id = ?', [app[0].userId]);
      if (appUser[0].telegramId) {
        let message;
        if (status === 'approved') {
          message = `Поздравляем, ${appUser[0].name}! Ваше приложение "${app[0].name}" одобрено${app[0].isPublished ? ' и опубликовано' : ''}.`;
        } else {
          message = `Уважаемый ${appUser[0].name}, ваше приложение "${app[0].name}" было отклонено. Причина: ${rejectionReason}. Пожалуйста, исправьте и отправьте снова.`;
        }
        telegramQueue.add({
          chatId: appUser[0].telegramId,
          text: message,
        }, { attempts: 3, backoff: 5000 });
      }
    }

    res.json({ message: `Статус приложения обновлён на ${status}` });
  } catch (err) {
    logger.error(`Ошибка обновления приложения: ${err.message}, стек: ${err.stack}`);
    res.status(500).json({ message: 'Ошибка сервера', error: err.message });
  }
});

// Удаление приложения
app.delete('/api/admin/apps/:id', authenticateToken, async (req, res) => {
  const { id } = req.params;

  try {
    const [user] = await db.query('SELECT email, accountType FROM Users WHERE id = ?', [req.user.id]);
    if (!user.length || user[0].email !== 'admin@24webstudio.ru') {
      return res.status(403).json({ message: 'Требуется доступ администратора' });
    }

    const [app] = await db.query('SELECT iconPath, apkPath, name, userId FROM Apps WHERE id = ?', [id]);
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
    logger.info(`Приложение ${id} удалено администратором`);

    const [appUser] = await db.query('SELECT telegramId FROM Users WHERE id = ?', [app[0].userId]);
    if (appUser[0].telegramId) {
      telegramQueue.add({
        chatId: appUser[0].telegramId,
        text: `Ваше приложение "${app[0].name}" (ID: ${id}) было удалено администратором.`,
      }, { attempts: 3, backoff: 5000 });
    }

    res.json({ message: 'Приложение удалено' });
  } catch (err) {
    logger.error(`Ошибка удаления приложения: ${err.message}, стек: ${err.stack}`);
    res.status(500).json({ message: 'Ошибка сервера', error: err.message });
  }
});

// Получение документов пользователей для администратора
app.get('/api/admin/users/documents', authenticateToken, async (req, res) => {
  try {
    const [user] = await db.query('SELECT email, accountType FROM Users WHERE id = ?', [req.user.id]);
    if (!user.length || user[0].email !== 'admin@24webstudio.ru') {
      return res.status(403).json({ message: 'Требуется доступ администратора' });
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
        logger.error(`Ошибка парсинга документов для пользователя ${u.email}: ${parseError.message}`);
        documents = [];
      }
      return { ...u, documents };
    });

    res.json(usersWithDocuments);
  } catch (err) {
    logger.error(`Ошибка получения документов пользователей для администратора: ${err.message}, стек: ${err.stack}`);
    res.status(500).json({ message: 'Ошибка сервера', error: err.message });
  }
});

// Верификация пользователя
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
    logger.info(`Статус верификации для пользователя ${user[0].email} обновлён на ${isVerified}`);

    if (user[0].telegramId) {
      telegramQueue.add({
        chatId: user[0].telegramId,
        text: isVerified
          ? `Поздравляем, ${user[0].name}! Ваш аккаунт верифицирован.`
          : `Уважаемый ${user[0].name}, верификация вашего аккаунта не была одобрена. Пожалуйста, загрузите действительные документы.`,
      }, { attempts: 3, backoff: 5000 });
    }

    res.json({ message: `Статус верификации обновлён на ${isVerified ? 'верифицирован' : 'не верифицирован'}` });
  } catch (err) {
    logger.error(`Ошибка верификации пользователя: ${err.message}, стек: ${err.stack}`);
    res.status(500).json({ message: 'Ошибка сервера', error: err.message });
  }
});

// Получение рекламы
app.get('/api/admin/advertisements', authenticateToken, async (req, res) => {
  try {
    const [user] = await db.query('SELECT email, accountType FROM Users WHERE id = ?', [req.user.id]);
    if (!user.length || user[0].email !== 'admin@24webstudio.ru') {
      return res.status(403).json({ message: 'Требуется доступ администратора' });
    }

    const [ads] = await db.query(`
      SELECT a.*, u.email as userEmail, u.name as userName
      FROM Advertisements a
      JOIN Users u ON a.userId = u.id
      ORDER BY a.createdAt DESC
    `);
    res.json(ads);
  } catch (err) {
    logger.error(`Ошибка получения рекламы: ${err.message}, стек: ${err.stack}`);
    res.status(500).json({ message: 'Ошибка сервера', error: err.message });
  }
});

// Блокировка/разблокировка пользователя
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
    logger.info(`Статус блокировки для пользователя ${user[0].email} обновлён на ${isBlocked}`);

    if (user[0].telegramId) {
      telegramQueue.add({
        chatId: user[0].telegramId,
        text: isBlocked
          ? 'Ваш аккаунт заблокирован. Свяжитесь с администратором.'
          : 'Ваш аккаунт разблокирован.',
      }, { attempts: 3, backoff: 5000 });
    }

    res.json({ message: `Пользователь ${isBlocked ? 'заблокирован' : 'разблокирован'}` });
  } catch (err) {
    logger.error(`Ошибка блокировки пользователя: ${err.message}, стек: ${err.stack}`);
    res.status(500).json({ message: 'Ошибка сервера', error: err.message });
  }
});

// Массовая рассылка уведомлений
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
          text: message,
        }, { attempts: 3, backoff: 5000 });
        successCount++;
      } catch (err) {
        errorCount++;
        logger.error(`Ошибка отправки уведомления пользователю ${user.email}: ${err.message}`);
      }
    }

    logger.info(`Массовая рассылка завершена: ${successCount} успешно, ${errorCount} ошибок`);
    res.status(200).json({
      message: `Уведомления запланированы для ${successCount} пользователей`,
      successCount,
      errorCount
    });
  } catch (err) {
    logger.error(`Ошибка массовой рассылки: ${err.message}, стек: ${err.stack}`);
    res.status(500).json({ message: 'Ошибка сервера', error: err.message });
  }
});

// Middleware обработки ошибок
app.use((err, req, res, next) => {
  logger.error(`Необработанная ошибка: ${err.message}, стек: ${err.stack}, маршрут: ${req.originalUrl}`);
  if (err instanceof multer.MulterError) {
    logger.warn(`Ошибка Multer: ${err.message}`);
    return res.status(400).json({ message: `Ошибка загрузки файла: ${err.message}` });
  }
  if (err.message.includes('Only allowed') || err.message.includes('upload timeout')) {
    logger.warn(`Ошибка типа файла или тайм-аута: ${err.message}`);
    return res.status(400).json({ message: err.message });
  }
  res.status(500).json({ message: 'Ошибка сервера', error: err.message });
});

// Грациозное завершение работы
async function shutdown() {
  logger.info('Выполняется грациозное завершение работы...');
  try {
    await telegramQueue.close();
    await db.end();
    logger.info('Соединения с базой данных и очередью закрыты');
  } catch (err) {
    logger.error(`Ошибка завершения работы: ${err.message}`);
  }
  process.exit(0);
}

process.on('SIGINT', shutdown);
process.on('SIGTERM', shutdown);

// Запуск сервера
initializeServer();