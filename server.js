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

const app = express();

// Configuration (using environment variables)
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

// Check required environment variables
const requiredEnvVars = ['JWT_SECRET', 'DB_HOST', 'DB_USER', 'DB_PASSWORD', 'DB_NAME', 'S3_ACCESS_KEY', 'S3_SECRET_KEY', 'BUCKET_NAME', 'TELEGRAM_BOT_TOKEN'];
for (const envVar of requiredEnvVars) {
  if (!process.env[envVar]) {
    console.error(`Ошибка: ${envVar} не установлен в переменных окружения`);
    process.exit(1);
  }
}

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

// S3 Client setup
const s3Client = new S3Client({
  endpoint: 'https://s3.twcstorage.ru',
  credentials: {
    accessKeyId: S3_ACCESS_KEY,
    secretAccessKey: S3_SECRET_KEY,
  },
  region: 'ru-1',
  forcePathStyle: true,
});

// Check S3 connection
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

// MySQL connection pool
const db = mysql.createPool({
  host: DB_HOST,
  user: DB_USER,
  password: DB_PASSWORD,
  database: DB_NAME,
  port: 3306,
  connectionLimit: 10,
  connectTimeout: 30000,
});

// Multer setup for file uploads
const upload = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: 10 * 1024 * 1024 },
  fileFilter: (req, file, cb) => {
    if (file.fieldname === 'icon') {
      const validMimeTypes = ['image/png'];
      const validExtensions = /\.png$/i;
      const extname = validExtensions.test(path.extname(file.originalname).toLowerCase());
      const mimetype = validMimeTypes.includes(file.mimetype);
      if (extname && mimetype) {
        return cb(null, true);
      }
      logger.warn(`Недопустимая иконка: имя=${file.originalname}, MIME=${file.mimetype}`);
      cb(new Error('Разрешены только файлы PNG для иконок!'));
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
        return cb(null, true);
      }
      logger.warn(`Недопустимый APK: имя=${file.originalname}, MIME=${file.mimetype}`);
      cb(new Error('Разрешены только файлы APK!'));
    } else if (file.fieldname === 'documents') {
      const validMimeTypes = ['application/pdf', 'image/jpeg', 'image/png', 'image/jpg'];
      const validExtensions = /\.(pdf|jpg|jpeg|png)$/i;
      const extname = validExtensions.test(path.extname(file.originalname).toLowerCase());
      const mimetype = validMimeTypes.includes(file.mimetype);
      if (extname && mimetype) {
        return cb(null, true);
      }
      logger.warn(`Недопустимый документ: имя=${file.originalname}, MIME=${file.mimetype}`);
      cb(new Error('Разрешены только файлы PDF, JPG, JPEG и PNG для документов!'));
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

// Upload file to S3
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
    logger.info(`Файл загружен в S3: ${key}, URL: ${location}`);
    return location;
  } catch (error) {
    logger.error(`Ошибка загрузки в S3 для ${key}: ${error.message}, стек: ${error.stack}`);
    throw new Error(`Ошибка загрузки в S3: ${error.message}`);
  }
}

// Delete file from S3
async function deleteFromS3(key) {
  const params = {
    Bucket: BUCKET_NAME,
    Key: key,
  };

  try {
    await s3Client.send(new DeleteObjectCommand(params));
    logger.info(`Файл удален из S3: ${key}`);
  } catch (err) {
    logger.error(`Ошибка удаления из S3: ${err.message}, стек: ${err.stack}`);
    throw err;
  }
}

// Get file from S3
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
    logger.error(`Ошибка получения из S3: ${err.message}, стек: ${err.stack}`);
    throw err;
  }
}

// JWT authentication middleware
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
    return res.status(403).json({
      message: 'Недействительный или истекший токен',
      error: error.message
    });
  }
};

// Optional JWT authentication middleware
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

// Database initialization
async function initializeDatabase() {
  try {
    const connection = await db.getConnection();
    logger.info('Подключение к MySQL выполнено');

    // Create Users table
    await connection.query(`
      CREATE TABLE IF NOT EXISTS Users (
        id INT AUTO_INCREMENT PRIMARY KEY,
        email VARCHAR(255) NOT NULL UNIQUE,
        password VARCHAR(255) NOT NULL,
        accountType ENUM('individual', 'commercial') NOT NULL,
        name VARCHAR(255) NOT NULL,
        phone VARCHAR(20) NOT NULL,
        telegramUsername VARCHAR(255),
        addressStreet VARCHAR(255),
        addressCity VARCHAR(255),
        addressCountry VARCHAR(255),
        addressPostalCode VARCHAR(20),
        documents JSON,
        isVerified BOOLEAN DEFAULT FALSE,
        isBlocked BOOLEAN DEFAULT FALSE,
        jwtToken VARCHAR(500),
        resetPasswordToken VARCHAR(500),
        resetPasswordExpires DATETIME,
        verificationCode VARCHAR(10),
        createdAt TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        updatedAt TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
      )
    `);
    logger.info('Таблица Users проверена/создана');

    // Create PreRegisters table
    await connection.query(`
      CREATE TABLE IF NOT EXISTS PreRegisters (
        id INT AUTO_INCREMENT PRIMARY KEY,
        email VARCHAR(255) NOT NULL UNIQUE,
        createdAt TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        updatedAt TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
      )
    `);
    logger.info('Таблица PreRegisters проверена/создана');

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
    logger.info('Таблица Apps проверена/создана');

    // Create Advertisements table
    await connection.query(`
      CREATE TABLE IF NOT EXISTS Advertisements (
        id INT AUTO_INCREMENT PRIMARY KEY,
        name VARCHAR(255) NOT NULL,
        description TEXT NOT NULL,
        budget DECIMAL(10,2) NOT NULL,
        status ENUM('active', 'paused', 'completed') DEFAULT 'active',
        impressions INT DEFAULT 0,
        clicks INT DEFAULT 0,
        endDate DATE,
        userId INT NOT NULL,
        createdAt TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        updatedAt TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
        FOREIGN KEY (userId) REFERENCES Users(id) ON DELETE CASCADE
      )
    `);
    logger.info('Таблица Advertisements проверена/создана');

    // Create default admin
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

// Telegram Bot Setup
const TelegramBot = require('node-telegram-bot-api');
const bot = new TelegramBot(TELEGRAM_BOT_TOKEN, { polling: true });

// Function to resolve Telegram username to chat ID
async function resolveTelegramUsername(username) {
  try {
    const response = await axios.get(`https://api.telegram.org/bot${TELEGRAM_BOT_TOKEN}/getChat`, {
      params: { chat_id: username }
    });
    if (response.data.ok) {
      return response.data.result.id;
    }
    return null;
  } catch (error) {
    logger.error(`Ошибка получения chat_id для ${username}: ${error.message}`);
    return null;
  }
}

// Generate random verification code
function generateVerificationCode() {
  return Math.random().toString(36).substr(2, 6).toUpperCase();
}

// Telegram Bot Commands
bot.onText(/\/start/, (msg) => {
  const chatId = msg.chat.id;
  bot.sendMessage(chatId, 'Добро пожаловать! Используйте команды для управления вашим аккаунтом:\n' +
    '/status - Проверить статус верификации\n' +
    '/verify <код> - Подтвердить аккаунт\n' +
    '/delete - Запросить удаление аккаунта\n' +
    '/block - Заблокировать аккаунт\n' +
    '/unblock - Разблокировать аккаунт');
});

bot.onText(/\/status/, async (msg) => {
  const chatId = msg.chat.id;
  const username = `@${msg.from.username}`;
  try {
    const [user] = await db.query('SELECT email, isVerified, isBlocked FROM Users WHERE telegramUsername = ?', [username]);
    if (!user.length) {
      bot.sendMessage(chatId, 'Аккаунт не найден. Пожалуйста, зарегистрируйтесь с этим Telegram username.');
      return;
    }
    const status = user[0].isVerified ? 'Верифицирован' : 'Ожидает верификации';
    const blockStatus = user[0].isBlocked ? 'Заблокирован' : 'Активен';
    bot.sendMessage(chatId, `Ваш аккаунт (${user[0].email}):\nСтатус: ${status}\nБлокировка: ${blockStatus}`);
  } catch (error) {
    logger.error(`Ошибка проверки статуса для ${username}: ${error.message}`);
    bot.sendMessage(chatId, 'Ошибка сервера. Попробуйте позже.');
  }
});

bot.onText(/\/verify (.+)/, async (msg, match) => {
  const chatId = msg.chat.id;
  const username = `@${msg.from.username}`;
  const code = match[1];
  try {
    const [user] = await db.query('SELECT id, email, verificationCode FROM Users WHERE telegramUsername = ? AND verificationCode = ?', [username, code]);
    if (!user.length) {
      bot.sendMessage(chatId, 'Неверный код верификации или аккаунт не найден.');
      return;
    }
    await db.query('UPDATE Users SET isVerified = ?, verificationCode = NULL WHERE id = ?', [true, user[0].id]);
    bot.sendMessage(chatId, `Аккаунт ${user[0].email} успешно верифицирован!`);
    logger.info(`Пользователь ${user[0].email} верифицирован через Telegram`);
  } catch (error) {
    logger.error(`Ошибка верификации через Telegram для ${username}: ${error.message}`);
    bot.sendMessage(chatId, 'Ошибка сервера. Попробуйте позже.');
  }
});

bot.onText(/\/delete/, async (msg) => {
  const chatId = msg.chat.id;
  const username = `@${msg.from.username}`;
  try {
    const [user] = await db.query('SELECT id, email, documents FROM Users WHERE telegramUsername = ?', [username]);
    if (!user.length) {
      bot.sendMessage(chatId, 'Аккаунт не найден.');
      return;
    }
    let documents = [];
    try {
      documents = user[0].documents ? JSON.parse(user[0].documents) : [];
      if (!Array.isArray(documents)) documents = [documents];
    } catch (parseError) {
      logger.error(`Ошибка парсинга документов для ${user[0].email}: ${parseError.message}`);
    }
    for (const doc of documents) {
      const docKey = doc.split('/').pop();
      if (docKey) await deleteFromS3(`documents/${docKey}`);
    }
    await db.query('DELETE FROM Users WHERE id = ?', [user[0].id]);
    bot.sendMessage(chatId, `Аккаунт ${user[0].email} успешно удален.`);
    logger.info(`Аккаунт ${user[0].email} удален через Telegram`);
  } catch (error) {
    logger.error(`Ошибка удаления аккаунта для ${username}: ${error.message}`);
    bot.sendMessage(chatId, 'Ошибка сервера. Попробуйте позже.');
  }
});

bot.onText(/\/block/, async (msg) => {
  const chatId = msg.chat.id;
  const username = `@${msg.from.username}`;
  try {
    const [user] = await db.query('SELECT id, email, isBlocked FROM Users WHERE telegramUsername = ?', [username]);
    if (!user.length) {
      bot.sendMessage(chatId, 'Аккаунт не найден.');
      return;
    }
    if (user[0].isBlocked) {
      bot.sendMessage(chatId, 'Аккаунт уже заблокирован.');
      return;
    }
    await db.query('UPDATE Users SET isBlocked = ? WHERE id = ?', [true, user[0].id]);
    bot.sendMessage(chatId, `Аккаунт ${user[0].email} заблокирован.`);
    logger.info(`Аккаунт ${user[0].email} заблокирован через Telegram`);
  } catch (error) {
    logger.error(`Ошибка блокировки аккаунта для ${username}: ${error.message}`);
    bot.sendMessage(chatId, 'Ошибка сервера. Попробуйте позже.');
  }
});

bot.onText(/\/unblock/, async (msg) => {
  const chatId = msg.chat.id;
  const username = `@${msg.from.username}`;
  try {
    const [user] = await db.query('SELECT id, email, isBlocked FROM Users WHERE telegramUsername = ?', [username]);
    if (!user.length) {
      bot.sendMessage(chatId, 'Аккаунт не найден.');
      return;
    }
    if (!user[0].isBlocked) {
      bot.sendMessage(chatId, 'Аккаунт не заблокирован.');
      return;
    }
    await db.query('UPDATE Users SET isBlocked = ? WHERE id = ?', [false, user[0].id]);
    bot.sendMessage(chatId, `Аккаунт ${user[0].email} разблокирован.`);
    logger.info(`Аккаунт ${user[0].email} разблокирован через Telegram`);
  } catch (error) {
    logger.error(`Ошибка разблокировки аккаунта для ${username}: ${error.message}`);
    bot.sendMessage(chatId, 'Ошибка сервера. Попробуйте позже.');
  }
});

// Server initialization
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

// Public routes
// Get approved apps
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
    logger.error(`Ошибка получения приложений: ${err.message}, стек: ${err.stack}`);
    res.status(500).json({ message: 'Ошибка сервера', error: err.message });
  }
});

// Get app image
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

// User pre-registration
app.post(
  '/api/pre-register',
  [
    body('email').isEmail().normalizeEmail().withMessage('Требуется действительный email'),
    body('telegramUsername').optional().matches(/^@[\w\d_]{5,32}$/).withMessage('Недопустимый Telegram username'),
  ],
  async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      logger.warn(`Ошибки валидации: ${JSON.stringify(errors.array())}`);
      return res.status(400).json({ message: 'Ошибка валидации', errors: errors.array() });
    }

    try {
      const { email, telegramUsername } = req.body;
      const [existing] = await db.query('SELECT email FROM PreRegisters WHERE email = ?', [email]);
      if (existing.length > 0) {
        return res.status(400).json({ message: 'Email уже в списке ожидания' });
      }

      await db.query('INSERT INTO PreRegisters (email) VALUES (?)', [email]);
      logger.info(`Предрегистрация: ${email}`);

      if (telegramUsername) {
        const chatId = await resolveTelegramUsername(telegramUsername);
        if (chatId) {
          try {
            await bot.sendMessage(chatId, `Спасибо за предрегистрацию, ${email}!`);
            logger.info(`Уведомление в Telegram отправлено для ${telegramUsername}`);
          } catch (telegramErr) {
            logger.error(`Ошибка уведомления в Telegram для ${telegramUsername}: ${telegramErr.message}`);
          }
        }
      }

      res.status(201).json({ message: `Спасибо! Ваш email (${email}) добавлен в список ожидания.` });
    } catch (error) {
      logger.error(`Ошибка предрегистрации: ${error.message}, стек: ${error.stack}`);
      res.status(500).json({ message: 'Ошибка сервера', error: error.message });
    }
  }
);

// User registration
app.post(
  '/api/auth/register',
  upload,
  [
    body('email').isEmail().normalizeEmail().withMessage('Требуется действительный email'),
    body('password').isLength({ min: 8 }).withMessage('Пароль должен содержать минимум 8 символов'),
    body('accountType').isIn(['individual', 'commercial']).withMessage('Недопустимый тип аккаунта'),
    body('name').notEmpty().trim().withMessage('Требуется имя'),
    body('phone').notEmpty().trim().withMessage('Требуется номер телефона'),
    body('telegramUsername').matches(/^@[\w\d_]{5,32}$/).withMessage('Недопустимый Telegram username'),
  ],
  async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      logger.warn(`Ошибки валидации: ${JSON.stringify(errors.array())}`);
      return res.status(400).json({ message: 'Ошибка валидации', errors: errors.array() });
    }

    try {
      const { email, password, accountType, name, phone, telegramUsername, addressStreet, addressCity, addressCountry, addressPostalCode } = req.body;
      if (!req.files || !req.files.documents || req.files.documents.length === 0) {
        logger.warn('Документы не загружены');
        return res.status(400).json({ message: 'Требуется хотя бы один документ' });
      }

      const [existingUser] = await db.query('SELECT email FROM Users WHERE email = ?', [email]);
      if (existingUser.length > 0) {
        return res.status(400).json({ message: 'Email уже зарегистрирован' });
      }

      const documentUrls = await Promise.all(req.files.documents.map(file => uploadToS3(file, 'documents')));
      const salt = await bcrypt.genSalt(10);
      const hashedPassword = await bcrypt.hash(password, salt);
      const verificationCode = generateVerificationCode();

      const [result] = await db.query(
        `INSERT INTO Users (
          email, password, accountType, name, phone, telegramUsername, addressStreet, addressCity, addressCountry, addressPostalCode,
          documents, isVerified, verificationCode
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
        [
          email, hashedPassword, accountType, name, phone, telegramUsername, addressStreet || null, addressCity || null, addressCountry || null,
          addressPostalCode || null, JSON.stringify(documentUrls), false, verificationCode
        ]
      );

      const authToken = jwt.sign({ id: result.insertId, email }, JWT_SECRET, { expiresIn: '7d' });
      await db.query('UPDATE Users SET jwtToken = ? WHERE id = ?', [authToken, result.insertId]);

      const chatId = await resolveTelegramUsername(telegramUsername);
      if (chatId) {
        try {
          await bot.sendMessage(
            chatId,
            `Добро пожаловать, ${name}! Вы зарегистрированы с email: ${email}.\n` +
            `Для верификации аккаунта используйте команду: /verify ${verificationCode}`
          );
          logger.info(`Уведомление о регистрации отправлено в Telegram для ${telegramUsername}`);
        } catch (telegramErr) {
          logger.error(`Ошибка уведомления в Telegram для ${telegramUsername}: ${telegramErr.message}`);
        }
      }

      try {
        await bot.sendMessage(
          '-1002311447135',
          `Новые документы для проверки от пользователя ${email} (${telegramUsername}). Количество: ${documentUrls.length}`
        );
        logger.info(`Уведомление в Telegram отправлено для документов пользователя ${email}`);
      } catch (telegramErr) {
        logger.error(`Ошибка уведомления в Telegram для админа: ${telegramErr.message}`);
      }

      logger.info(`Пользователь зарегистрирован: ${email}, documents: ${JSON.stringify(documentUrls)}`);
      res.status(201).json({
        message: 'Регистрация успешна. Проверьте Telegram для верификации аккаунта.',
        token: authToken,
        user: { id: result.insertId, email, accountType, name, phone, telegramUsername, isVerified: false },
      });
    } catch (error) {
      logger.error(`Ошибка регистрации: ${error.message}, стек: ${error.stack}`);
      res.status(500).json({ message: 'Ошибка сервера', error: error.message });
    }
  }
);

// User login
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

      const isMatch = await bcrypt.compare(password, user[0].password);
      if (!isMatch) {
        logger.warn(`Неверный пароль для email: ${email}`);
        return res.status(400).json({ message: 'Неверный email или пароль' });
      }

      const token = jwt.sign({ id: user[0].id, email: user[0].email }, JWT_SECRET, { expiresIn: '7d' });
      await db.query('UPDATE Users SET jwtToken = ? WHERE id = ?', [token, user[0].id]);

      if (user[0].telegramUsername) {
        const chatId = await resolveTelegramUsername(user[0].telegramUsername);
        if (chatId) {
          try {
            await bot.sendMessage(chatId, `Вы успешно вошли в аккаунт ${email}`);
            logger.info(`Уведомление о входе отправлено в Telegram для ${user[0].telegramUsername}`);
          } catch (telegramErr) {
            logger.error(`Ошибка уведомления в Telegram для ${user[0].telegramUsername}: ${telegramErr.message}`);
          }
        }
      }

      logger.info(`Пользователь вошел: ${user[0].email}`);
      res.status(200).json({
        token,
        user: {
          id: user[0].id,
          email: user[0].email,
          accountType: user[0].accountType,
          name: user[0].name,
          phone: user[0].phone,
          telegramUsername: user[0].telegramUsername,
          isVerified: user[0].isVerified
        },
        message: user[0].isVerified ? 'Вход успешен' : 'Вход успешен, но аккаунт ожидает верификации',
      });
    } catch (error) {
      logger.error(`Ошибка входа: ${error.message}, стек: ${error.stack}`);
      res.status(500).json({ message: 'Ошибка сервера', error: error.message });
    }
  }
);

// Forgot password
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
      const [user] = await db.query('SELECT id, email, telegramUsername FROM Users WHERE email = ?', [email]);
      if (!user.length) {
        logger.warn(`Попытка сброса пароля для несуществующего email: ${email}`);
        return res.status(404).json({ message: 'Пользователь с таким email не найден' });
      }

      const resetToken = jwt.sign({ email }, JWT_SECRET, { expiresIn: '1h' });
      await db.query(
        'UPDATE Users SET resetPasswordToken = ?, resetPasswordExpires = ? WHERE email = ?',
        [resetToken, new Date(Date.now() + 3600000), email]
      );

      if (user[0].telegramUsername) {
        const chatId = await resolveTelegramUsername(user[0].telegramUsername);
        if (chatId) {
          try {
            await bot.sendMessage(
              chatId,
              `Запрос на сброс пароля для ${email}. Используйте токен: ${resetToken} для сброса пароля.`
            );
            logger.info(`Уведомление о сбросе пароля отправлено в Telegram для ${user[0].telegramUsername}`);
          } catch (telegramErr) {
            logger.error(`Ошибка уведомления в Telegram для ${user[0].telegramUsername}: ${telegramErr.message}`);
          }
        }
      }

      logger.info(`Запрошен сброс пароля для ${user[0].email}`);
      res.status(200).json({ message: 'Ссылка для сброса пароля отправлена (проверьте Telegram или email)' });
    } catch (error) {
      logger.error(`Ошибка сброса пароля: ${error.message}, стек: ${error.stack}`);
      res.status(500).json({ message: 'Ошибка сервера', error: error.message });
    }
  }
);

// Reset password
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
        'SELECT id, email, telegramUsername FROM Users WHERE email = ? AND resetPasswordToken = ? AND resetPasswordExpires > NOW()',
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

      if (user[0].telegramUsername) {
        const chatId = await resolveTelegramUsername(user[0].telegramUsername);
        if (chatId) {
          try {
            await bot.sendMessage(chatId, `Пароль для ${user[0].email} успешно сброшен.`);
            logger.info(`Уведомление о сбросе пароля отправлено в Telegram для ${user[0].telegramUsername}`);
          } catch (telegramErr) {
            logger.error(`Ошибка уведомления в Telegram для ${user[0].telegramUsername}: ${telegramErr.message}`);
          }
        }
      }

      logger.info(`Пароль сброшен для ${user[0].email}`);
      res.status(200).json({ message: 'Пароль успешно сброшен' });
    } catch (error) {
      logger.error(`Ошибка сброса пароля: ${error.message}, стек: ${error.stack}`);
      res.status(500).json({ message: 'Ошибка сервера', error: error.message });
    }
  }
);

// Get user profile
app.get('/api/user/profile', authenticateToken, async (req, res) => {
  try {
    const [user] = await db.query(
      'SELECT id, email, accountType, name, phone, telegramUsername, addressStreet, addressCity, addressCountry, addressPostalCode, documents, isVerified, isBlocked, createdAt FROM Users WHERE id = ?',
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
        if (!Array.isArray(documents)) {
          documents = [documents];
        }
      }
      logger.info(`Документы пользователя ${user[0].email}: ${JSON.stringify(documents)}`);
    } catch (parseError) {
      logger.error(`Ошибка парсинга документов для пользователя ${user[0].email}: ${parseError.message}, documents: ${user[0].documents}`);
      documents = [];
    }

    user[0].documents = documents;
    res.status(200).json(user[0]);
  } catch (error) {
    logger.error(`Ошибка получения профиля: ${error.message}, стек: ${error.stack}`);
    res.status(500).json({ message: 'Ошибка сервера', error: error.message });
  }
});

// Update user documents
app.post(
  '/api/user/documents',
  authenticateToken,
  upload,
  async (req, res) => {
    try {
      const [user] = await db.query('SELECT id, email, telegramUsername, documents FROM Users WHERE id = ?', [req.user.id]);
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
        if (!Array.isArray(currentDocuments)) {
          currentDocuments = [currentDocuments];
        }
      } catch (parseError) {
        logger.error(`Ошибка парсинга текущих документов для пользователя ${user[0].email}: ${parseError.message}`);
        currentDocuments = [];
      }

      const updatedDocuments = [...currentDocuments, ...newDocuments].slice(0, 3);
      await db.query('UPDATE Users SET documents = ?, isVerified = ? WHERE id = ?', [
        JSON.stringify(updatedDocuments), false, user[0].id
      ]);

      if (user[0].telegramUsername) {
        const chatId = await resolveTelegramUsername(user[0].telegramUsername);
        if (chatId) {
          try {
            await bot.sendMessage(chatId, `Новые документы загружены для ${user[0].email}. Ожидайте проверки администратором.`);
            logger.info(`Уведомление о загрузке документов отправлено в Telegram для ${user[0].telegramUsername}`);
          } catch (telegramErr) {
            logger.error(`Ошибка уведомления в Telegram для ${user[0].telegramUsername}: ${telegramErr.message}`);
          }
        }
      }

      try {
        await bot.sendMessage(
          '-1002311447135',
          `Новые документы для проверки от пользователя ${user[0].email} (${user[0].telegramUsername}). Количество: ${newDocuments.length}`
        );
        logger.info(`Уведомление в Telegram отправлено для документов пользователя ${user[0].email}`);
      } catch (telegramErr) {
        logger.error(`Ошибка уведомления в Telegram для админа: ${telegramErr.message}`);
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

// Create app
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
      const [user] = await db.query('SELECT id, email, telegramUsername, isVerified FROM Users WHERE id = ?', [req.user.id]);
      if (!user.length) {
        logger.warn(`Пользователь не найден для ID: ${req.user.id}`);
        return res.status(404).json({ message: 'Пользователь не найден' });
      }

      if (!user[0].isVerified) {
        logger.warn(`Пользователь не верифицирован: ${user[0].email}`);
        return res.status(403).json({ message: 'Аккаунт должен быть верифицирован для отправки приложений' });
      }

      const { name, description, category } = req.body;
      const files = req.files;

      if (!files || !files.icon || !files.icon[0]) {
        logger.warn('Файл иконки отсутствует');
        return res.status(400).json({ message: 'Требуется файл иконки (только PNG)' });
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

      if (user[0].telegramUsername) {
        const chatId = await resolveTelegramUsername(user[0].telegramUsername);
        if (chatId) {
          try {
            await bot.sendMessage(chatId, `Ваше приложение ${name} отправлено на проверку.`);
            logger.info(`Уведомление о создании приложения отправлено в Telegram для ${user[0].telegramUsername}`);
          } catch (telegramErr) {
            logger.error(`Ошибка уведомления в Telegram для ${user[0].telegramUsername}: ${telegramErr.message}`);
          }
        }
      }

      try {
        await bot.sendMessage(
          '-1002311447135',
          `Новое приложение отправлено: ${name} от ${user[0].email} (${user[0].telegramUsername})`
        );
        logger.info(`Уведомление в Telegram отправлено для приложения ${name}`);
      } catch (telegramErr) {
        logger.error(`Ошибка уведомления в Telegram для админа: ${telegramErr.message}`);
      }

      logger.info(`Приложение создано пользователем ${user[0].email}: ${name}`);
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

// Admin routes
// Get all apps
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
    logger.error(`Ошибка получения приложений для админа: ${err.message}, стек: ${err.stack}`);
    res.status(500).json({ message: 'Ошибка сервера', error: err.message });
  }
});

// Update app status
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

    const [appUser] = await db.query('SELECT email, telegramUsername FROM Users WHERE id = ?', [app[0].userId]);
    if (appUser[0].telegramUsername) {
      const chatId = await resolveTelegramUsername(appUser[0].telegramUsername);
      if (chatId) {
        try {
          await bot.sendMessage(chatId, `Статус вашего приложения ${app[0].name} обновлен на ${status}.`);
          logger.info(`Уведомление об обновлении статуса приложения отправлено в Telegram для ${appUser[0].telegramUsername}`);
        } catch (telegramErr) {
          logger.error(`Ошибка уведомления в Telegram для ${appUser[0].telegramUsername}: ${telegramErr.message}`);
        }
      }
    }

    try {
      await bot.sendMessage(
        '-1002311447135',
        `Статус приложения ${app[0].name} обновлен на ${status} для пользователя ${appUser[0].email} (${appUser[0].telegramUsername})`
      );
      logger.info(`Уведомление в Telegram отправлено для приложения ${app[0].name}`);
    } catch (telegramErr) {
      logger.error(`Ошибка уведомления в Telegram для админа: ${telegramErr.message}`);
    }

    logger.info(`Статус приложения ${id} обновлен на ${status}`);
    res.json({ message: `Статус приложения обновлен на ${status}` });
  } catch (err) {
    logger.error(`Ошибка обновления приложения: ${err.message}, стек: ${err.stack}`);
    res.status(500).json({ message: 'Ошибка сервера', error: err.message });
  }
});

// Delete app
app.delete('/api/admin/apps/:id', authenticateToken, async (req, res) => {
  const { id } = req.params;

  try {
    const [user] = await db.query('SELECT email, accountType FROM Users WHERE id = ?', [req.user.id]);
    if (!user.length || user[0].email !== 'admin@24webstudio.ru') {
      return res.status(403).json({ message: 'Требуется доступ администратора' });
    }

    const [app] = await db.query('SELECT iconPath, apkPath, userId, name FROM Apps WHERE id = ?', [id]);
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

    const [appUser] = await db.query('SELECT email, telegramUsername FROM Users WHERE id = ?', [app[0].userId]);
    await db.query('DELETE FROM Apps WHERE id = ?', [id]);

    if (appUser[0].telegramUsername) {
      const chatId = await resolveTelegramUsername(appUser[0].telegramUsername);
      if (chatId) {
        try {
          await bot.sendMessage(chatId, `Ваше приложение ${app[0].name} было удалено администратором.`);
          logger.info(`Уведомление об удалении приложения отправлено в Telegram для ${appUser[0].telegramUsername}`);
        } catch (telegramErr) {
          logger.error(`Ошибка уведомления в Telegram для ${appUser[0].telegramUsername}: ${telegramErr.message}`);
        }
      }
    }

    logger.info(`Приложение ${id} удалено`);
    res.json({ message: 'Приложение удалено' });
  } catch (err) {
    logger.error(`Ошибка удаления приложения: ${err.message}, стек: ${err.stack}`);
    res.status(500).json({ message: 'Ошибка сервера', error: err.message });
  }
});

// Get all users and their documents
app.get('/api/admin/users/documents', authenticateToken, async (req, res) => {
  try {
    const [user] = await db.query('SELECT email, accountType FROM Users WHERE id = ?', [req.user.id]);
    if (!user.length || user[0].email !== 'admin@24webstudio.ru') {
      return res.status(403).json({ message: 'Требуется доступ администратора' });
    }

    const [users] = await db.query(`
      SELECT id, email, name, accountType, documents, isVerified, isBlocked, telegramUsername, createdAt
      FROM Users
      WHERE documents IS NOT NULL
      ORDER BY createdAt DESC
    `);

    const usersWithDocuments = users.map(u => {
      let documents = [];
      try {
        documents = u.documents ? JSON.parse(u.documents) : [];
        if (!Array.isArray(documents)) {
          documents = [documents];
        }
      } catch (parseError) {
        logger.error(`Ошибка парсинга документов для пользователя ${u.email}: ${parseError.message}`);
        documents = [];
      }
      return { ...u, documents };
    });

    res.json(usersWithDocuments);
  } catch (err) {
    logger.error(`Ошибка получения документов пользователей для админа: ${err.message}, стек: ${err.stack}`);
    res.status(500).json({ message: 'Ошибка сервера', error: err.message });
  }
});

// Verify user documents
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

    const [user] = await db.query('SELECT email, telegramUsername, documents FROM Users WHERE id = ?', [id]);
    if (!user.length) {
      return res.status(404).json({ message: 'Пользователь не найден' });
    }

    await db.query('UPDATE Users SET isVerified = ?, verificationCode = NULL WHERE id = ?', [isVerified, id]);

    if (user[0].telegramUsername) {
      const chatId = await resolveTelegramUsername(user[0].telegramUsername);
      if (chatId) {
        try {
          await bot.sendMessage(chatId, `Ваш аккаунт ${user[0].email} ${isVerified ? 'верифицирован' : 'отклонен'}.`);
          logger.info(`Уведомление о верификации отправлено в Telegram для ${user[0].telegramUsername}`);
        } catch (telegramErr) {
          logger.error(`Ошибка уведомления в Telegram для ${user[0].telegramUsername}: ${telegramErr.message}`);
        }
      }
    }

    try {
      await bot.sendMessage(
        '-1002311447135',
        `Статус верификации пользователя ${user[0].email} (${user[0].telegramUsername}) обновлен на ${isVerified ? 'верифицирован' : 'не верифицирован'}`
      );
      logger.info(`Уведомление в Telegram отправлено для верификации пользователя ${user[0].email}`);
    } catch (telegramErr) {
      logger.error(`Ошибка уведомления в Telegram для админа: ${telegramErr.message}`);
    }

    logger.info(`Статус верификации пользователя ${user[0].email} обновлен на ${isVerified}`);
    res.json({ message: `Статус верификации обновлен на ${isVerified ? 'верифицирован' : 'не верифицирован'}` });
  } catch (err) {
    logger.error(`Ошибка верификации пользователя: ${err.message}, стек: ${err.stack}`);
    res.status(500).json({ message: 'Ошибка сервера', error: err.message });
  }
});

// Block/unblock user
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

    const [user] = await db.query('SELECT email, telegramUsername FROM Users WHERE id = ?', [id]);
    if (!user.length) {
      return res.status(404).json({ message: 'Пользователь не найден' });
    }

    await db.query('UPDATE Users SET isBlocked = ? WHERE id = ?', [isBlocked, id]);

    if (user[0].telegramUsername) {
      const chatId = await resolveTelegramUsername(user[0].telegramUsername);
      if (chatId) {
        try {
          await bot.sendMessage(chatId, `Ваш аккаунт ${user[0].email} ${isBlocked ? 'заблокирован' : 'разблокирован'}.`);
          logger.info(`Уведомление о блокировке отправлено в Telegram для ${user[0].telegramUsername}`);
        } catch (telegramErr) {
          logger.error(`Ошибка уведомления в Telegram для ${user[0].telegramUsername}: ${telegramErr.message}`);
        }
      }
    }

    try {
      await bot.sendMessage(
        '-1002311447135',
        `Пользователь ${user[0].email} (${user[0].telegramUsername}) ${isBlocked ? 'заблокирован' : 'разблокирован'}`
      );
      logger.info(`Уведомление в Telegram отправлено для блокировки пользователя ${user[0].email}`);
    } catch (telegramErr) {
      logger.error(`Ошибка уведомления в Telegram для админа: ${telegramErr.message}`);
    }

    logger.info(`Пользователь ${user[0].email} ${isBlocked ? 'заблокирован' : 'разблокирован'}`);
    res.json({ message: `Пользователь ${isBlocked ? 'заблокирован' : 'разблокирован'}` });
  } catch (err) {
    logger.error(`Ошибка блокировки пользователя: ${err.message}, стек: ${err.stack}`);
    res.status(500).json({ message: 'Ошибка сервера', error: err.message });
  }
});

// Delete user
app.delete('/api/admin/users/:id', authenticateToken, async (req, res) => {
  const { id } = req.params;

  try {
    const [admin] = await db.query('SELECT email, accountType FROM Users WHERE id = ?', [req.user.id]);
    if (!admin.length || admin[0].email !== 'admin@24webstudio.ru') {
      return res.status(403).json({ message: 'Требуется доступ администратора' });
    }

    const [user] = await db.query('SELECT email, telegramUsername, documents FROM Users WHERE id = ?', [id]);
    if (!user.length) {
      return res.status(404).json({ message: 'Пользователь не найден' });
    }

    let documents = [];
    try {
      documents = user[0].documents ? JSON.parse(user[0].documents) : [];
      if (!Array.isArray(documents)) documents = [documents];
    } catch (parseError) {
      logger.error(`Ошибка парсинга документов для ${user[0].email}: ${parseError.message}`);
    }

    for (const doc of documents) {
      const docKey = doc.split('/').pop();
      if (docKey) await deleteFromS3(`documents/${docKey}`);
    }

    await db.query('DELETE FROM Users WHERE id = ?', [id]);

    if (user[0].telegramUsername) {
      const chatId = await resolveTelegramUsername(user[0].telegramUsername);
      if (chatId) {
        try {
          await bot.sendMessage(chatId, `Ваш аккаунт ${user[0].email} был удален администратором.`);
          logger.info(`Уведомление об удалении аккаунта отправлено в Telegram для ${user[0].telegramUsername}`);
        } catch (telegramErr) {
          logger.error(`Ошибка уведомления в Telegram для ${user[0].telegramUsername}: ${telegramErr.message}`);
        }
      }
    }

    try {
      await bot.sendMessage(
        '-1002311447135',
        `Пользователь ${user[0].email} (${user[0].telegramUsername}) удален`
      );
      logger.info(`Уведомление в Telegram отправлено для удаления пользователя ${user[0].email}`);
    } catch (telegramErr) {
      logger.error(`Ошибка уведомления в Telegram для админа: ${telegramErr.message}`);
    }

    logger.info(`Пользователь ${user[0].email} удален`);
    res.json({ message: 'Пользователь удален' });
  } catch (err) {
    logger.error(`Ошибка удаления пользователя: ${err.message}, стек: ${err.stack}`);
    res.status(500).json({ message: 'Ошибка сервера', error: err.message });
  }
});

// Admin routes for advertisements
// Get all advertisements
app.get('/api/admin/advertisements', authenticateToken, async (req, res) => {
  try {
    const [user] = await db.query('SELECT email, accountType FROM Users WHERE id = ?', [req.user.id]);
    if (!user.length || user[0].email !== 'admin@24webstudio.ru') {
      return res.status(403).json({ message: 'Требуется доступ администратора' });
    }

    const [ads] = await db.query(`
      SELECT a.*, u.email as userEmail
      FROM Advertisements a
      JOIN Users u ON a.userId = u.id
      ORDER BY a.createdAt DESC
    `);
    res.json(ads.map(ad => ({
      ...ad,
      ctr: ad.clicks > 0 ? (ad.clicks / ad.impressions * 100) : 0
    })));
  } catch (err) {
    logger.error(`Ошибка получения рекламных кампаний: ${err.message}, стек: ${err.stack}`);
    res.status(500).json({ message: 'Ошибка сервера', error: err.message });
  }
});

// Create advertisement
app.post(
  '/api/admin/advertisements',
  authenticateToken,
  [
    body('name').notEmpty().trim().withMessage('Требуется название кампании'),
    body('description').notEmpty().trim().withMessage('Требуется описание'),
    body('budget').isFloat({ min: 0 }).withMessage('Бюджет должен быть положительным числом'),
    body('status').isIn(['active', 'paused', 'completed']).withMessage('Недопустимый статус'),
    body('endDate').isDate().withMessage('Недопустимая дата окончания'),
    body('userEmail').isEmail().normalizeEmail().withMessage('Требуется действительный email пользователя'),
  ],
  async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      logger.warn(`Ошибки валидации: ${JSON.stringify(errors.array())}`);
      return res.status(400).json({ message: 'Ошибка валидации', errors: errors.array() });
    }

    try {
      const [admin] = await db.query('SELECT email, accountType FROM Users WHERE id = ?', [req.user.id]);
      if (!admin.length || admin[0].email !== 'admin@24webstudio.ru') {
        return res.status(403).json({ message: 'Требуется доступ администратора' });
      }

      const { name, description, budget, status, endDate, userEmail } = req.body;
      const [user] = await db.query('SELECT id, telegramUsername FROM Users WHERE email = ?', [userEmail]);
      if (!user.length) {
        return res.status(404).json({ message: 'Пользователь не найден' });
      }

      const [result] = await db.query(
        `INSERT INTO Advertisements (name, description, budget, status, endDate, userId, impressions, clicks) 
         VALUES (?, ?, ?, ?, ?, ?, 0, 0)`,
        [name, description, budget, status, endDate, user[0].id]
      );

      if (user[0].telegramUsername) {
        const chatId = await resolveTelegramUsername(user[0].telegramUsername);
        if (chatId) {
          try {
            await bot.sendMessage(chatId, `Новая рекламная кампания ${name} создана с бюджетом $${budget}.`);
            logger.info(`Уведомление о создании кампании отправлено в Telegram для ${user[0].telegramUsername}`);
          } catch (telegramErr) {
            logger.error(`Ошибка уведомления в Telegram для ${user[0].telegramUsername}: ${telegramErr.message}`);
          }
        }
      }

      try {
        await bot.sendMessage(
          '-1002311447135',
          `Новая рекламная кампания создана: ${name}, бюджет: ${budget}, статус: ${status}, пользователь: ${userEmail}`
        );
        logger.info(`Уведомление в Telegram отправлено для кампании ${name}`);
      } catch (telegramErr) {
        logger.error(`Ошибка уведомления в Telegram для админа: ${telegramErr.message}`);
      }

      logger.info(`Рекламная кампания создана: ${name}`);
      res.status(201).json({
        message: 'Рекламная кампания успешно создана',
        ad: {
          id: result.insertId,
          name,
          description,
          budget,
          status,
          endDate,
          userEmail,
          impressions: 0,
          clicks: 0,
          createdAt: new Date()
        },
      });
    } catch (error) {
      logger.error(`Ошибка создания рекламной кампании: ${error.message}, стек: ${error.stack}`);
      res.status(500).json({ message: 'Ошибка сервера', error: error.message });
    }
  }
);

// Update advertisement
app.put('/api/admin/advertisements/:id', authenticateToken, async (req, res) => {
  const { id } = req.params;
  const { status, endDate } = req.body;

  try {
    const [user] = await db.query('SELECT email, accountType FROM Users WHERE id = ?', [req.user.id]);
    if (!user.length || user[0].email !== 'admin@24webstudio.ru') {
      return res.status(403).json({ message: 'Требуется доступ администратора' });
    }

    const [ad] = await db.query('SELECT * FROM Advertisements WHERE id = ?', [id]);
    if (!ad.length) {
      return res.status(404).json({ message: 'Кампания не найдена' });
    }

    const updates = {};
    if (status && !['active', 'paused', 'completed'].includes(status)) {
      return res.status(400).json({ message: 'Недопустимый статус' });
    }
    if (status) updates.status = status;
    if (endDate) updates.endDate = endDate;

    await db.query('UPDATE Advertisements SET ? WHERE id = ?', [updates, id]);

    const [adUser] = await db.query('SELECT email, telegramUsername FROM Users WHERE id = ?', [ad[0].userId]);
    if (adUser[0].telegramUsername) {
      const chatId = await resolveTelegramUsername(adUser[0].telegramUsername);
      if (chatId) {
        try {
          await bot.sendMessage(chatId, `Статус вашей кампании ${ad[0].name} обновлен на ${status || ad[0].status}.`);
          logger.info(`Уведомление об обновлении кампании отправлено в Telegram для ${adUser[0].telegramUsername}`);
        } catch (telegramErr) {
          logger.error(`Ошибка уведомления в Telegram для ${adUser[0].telegramUsername}: ${telegramErr.message}`);
        }
      }
    }

    try {
      await bot.sendMessage(
        '-1002311447135',
        `Статус кампании ${ad[0].name} обновлен на ${status || ad[0].status} для пользователя ${adUser[0].email} (${adUser[0].telegramUsername})`
      );
      logger.info(`Уведомление в Telegram отправлено для кампании ${ad[0].name}`);
    } catch (telegramErr) {
      logger.error(`Ошибка уведомления в Telegram для админа: ${telegramErr.message}`);
    }

    logger.info(`Статус кампании ${id} обновлен`);
    res.json({ message: `Кампания обновлена` });
  } catch (err) {
    logger.error(`Ошибка обновления кампании: ${err.message}, стек: ${err.stack}`);
    res.status(500).json({ message: 'Ошибка сервера', error: err.message });
  }
});

// Delete advertisement
app.delete('/api/admin/advertisements/:id', authenticateToken, async (req, res) => {
  const { id } = req.params;

  try {
    const [user] = await db.query('SELECT email, accountType FROM Users WHERE id = ?', [req.user.id]);
    if (!user.length || user[0].email !== 'admin@24webstudio.ru') {
      return res.status(403).json({ message: 'Требуется доступ администратора' });
    }

    const [ad] = await db.query('SELECT name, userId FROM Advertisements WHERE id = ?', [id]);
    if (!ad.length) {
      return res.status(404).json({ message: 'Кампания не найдена' });
    }

    const [adUser] = await db.query('SELECT email, telegramUsername FROM Users WHERE id = ?', [ad[0].userId]);
    await db.query('DELETE FROM Advertisements WHERE id = ?', [id]);

    if (adUser[0].telegramUsername) {
      const chatId = await resolveTelegramUsername(adUser[0].telegramUsername);
      if (chatId) {
        try {
          await bot.sendMessage(chatId, `Ваша кампания ${ad[0].name} была удалена администратором.`);
          logger.info(`Уведомление об удалении кампании отправлено в Telegram для ${adUser[0].telegramUsername}`);
        } catch (telegramErr) {
          logger.error(`Ошибка уведомления в Telegram для ${adUser[0].telegramUsername}: ${telegramErr.message}`);
        }
      }
    }

    try {
      await bot.sendMessage(
        '-1002311447135',
        `Кампания ${ad[0].name} удалена для пользователя ${adUser[0].email} (${adUser[0].telegramUsername})`
      );
      logger.info(`Уведомление в Telegram отправлено для удаления кампании ${ad[0].name}`);
    } catch (telegramErr) {
      logger.error(`Ошибка уведомления в Telegram для админа: ${telegramErr.message}`);
    }

    logger.info(`Кампания ${id} удалена`);
    res.json({ message: 'Кампания удалена' });
  } catch (err) {
    logger.error(`Ошибка удаления кампании: ${err.message}, стек: ${err.stack}`);
    res.status(500).json({ message: 'Ошибка сервера', error: err.message });
  }
});

// Error handling middleware
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
  res.status(500).json({ message: 'Ошибка сервера', error: err.message });
});

// Graceful shutdown
async function shutdown() {
  logger.info('Выполняется грациозное завершение работы...');
  await db.end();
  logger.info('Соединение с базой данных закрыто');
  process.exit(0);
}

process.on('SIGINT', shutdown);
process.on('SIGTERM', shutdown);

// Start server
initializeServer();