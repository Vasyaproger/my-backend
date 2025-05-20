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
const JWT_SECRET = process.env.JWT_SECRET;
const DB_HOST = process.env.DB_HOST;
const DB_USER = process.env.DB_USER;
const DB_PASSWORD = process.env.DB_PASSWORD;
const DB_NAME = process.env.DB_NAME;
const S3_ACCESS_KEY = process.env.S3_ACCESS_KEY;
const S3_SECRET_KEY = process.env.S3_SECRET_KEY;
const BUCKET_NAME = process.env.BUCKET_NAME;
const TELEGRAM_BOT_TOKEN = process.env.TELEGRAM_BOT_TOKEN;
const PORT = process.env.PORT || 5000;
const BASE_URL = process.env.BASE_URL || 'http://localhost:5000'; // Базовый URL для ссылок верификации

// Check required environment variables
const requiredEnvVars = ['JWT_SECRET', 'DB_HOST', 'DB_USER', 'DB_PASSWORD', 'DB_NAME', 'S3_ACCESS_KEY', 'S3_SECRET_KEY', 'BUCKET_NAME', 'TELEGRAM_BOT_TOKEN', 'BASE_URL'];
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
    logger.error(`Ошибка соединения с S3: ${err.message}`);
    throw err;
  }
}

// Middleware
app.use(helmet());
app.use(cors({
  origin: '*',
  methods: ['GET', 'POST', 'PUT', 'DELETE'],
  allowedHeaders: ['Content-Type', 'Authorization'],
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
      if (extname && mimetype) return cb(null, true);
      logger.warn(`Недопустимая иконка: имя=${file.originalname}, MIME=${file.mimetype}`);
      cb(new Error('Разрешены только файлы PNG для иконок!'));
    } else if (file.fieldname === 'apk') {
      const extname = file.originalname.toLowerCase().endsWith('.apk');
      const validMimeTypes = ['application/vnd.android.package-archive', 'application/octet-stream', 'application/x-apk', 'application/zip'];
      const mimetype = validMimeTypes.includes(file.mimetype);
      if (extname && mimetype) return cb(null, true);
      logger.warn(`Недопустимый APK: имя=${file.originalname}, MIME=${file.mimetype}`);
      cb(new Error('Разрешены только файлы APK!'));
    } else if (file.fieldname === 'documents') {
      const validMimeTypes = ['application/pdf', 'image/jpeg', 'image/png', 'image/jpg'];
      const validExtensions = /\.(pdf|jpg|jpeg|png)$/i;
      const extname = validExtensions.test(path.extname(file.originalname).toLowerCase());
      const mimetype = validMimeTypes.includes(file.mimetype);
      if (extname && mimetype) return cb(null, true);
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
    await new Upload({ client: s3Client, params }).done();
    const location = `https://s3.twcstorage.ru/${BUCKET_NAME}/${key}`;
    logger.info(`Файл загружен в S3: ${key}`);
    return location;
  } catch (error) {
    logger.error(`Ошибка загрузки в S3: ${error.message}`);
    throw new Error(`Ошибка загрузки в S3: ${error.message}`);
  }
}

// Delete file from S3
async function deleteFromS3(key) {
  try {
    await s3Client.send(new DeleteObjectCommand({ Bucket: BUCKET_NAME, Key: key }));
    logger.info(`Файл удален из S3: ${key}`);
  } catch (err) {
    logger.error(`Ошибка удаления из S3: ${err.message}`);
    throw err;
  }
}

// Get file from S3
async function getFromS3(key) {
  try {
    const data = await s3Client.send(new GetObjectCommand({ Bucket: BUCKET_NAME, Key: key }));
    return data;
  } catch (err) {
    logger.error(`Ошибка получения из S3: ${err.message}`);
    throw err;
  }
}

// JWT authentication middleware
const authenticateToken = (req, res, next) => {
  const token = req.headers['authorization']?.split(' ')[1];
  if (!token) {
    logger.warn(`Отсутствует токен авторизации для маршрута: ${req.originalUrl}`);
    return res.status(401).json({ message: 'Требуется токен авторизации' });
  }
  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    req.user = decoded;
    logger.info(`Токен проверен: id=${decoded.id}, email=${decoded.email}`);
    next();
  } catch (error) {
    logger.error(`Ошибка проверки токена: ${error.message}`);
    return res.status(403).json({ message: 'Недействительный токен' });
  }
};

// Optional JWT authentication middleware
const optionalAuthenticateToken = (req, res, next) => {
  const token = req.headers['authorization']?.split(' ')[1];
  if (token) {
    jwt.verify(token, JWT_SECRET, (err, user) => {
      if (!err) req.user = user;
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

    // Create Users table with verificationToken
    await connection.query(`
      CREATE TABLE IF NOT EXISTS Users (
        id INT AUTO_INCREMENT PRIMARY KEY,
        email VARCHAR(255) NOT NULL UNIQUE,
        password VARCHAR(255) NOT NULL,
        accountType ENUM('individual', 'commercial') NOT NULL,
        name VARCHAR(255) NOT NULL,
        phone VARCHAR(20) NOT NULL,
        addressStreet VARCHAR(255),
        addressCity VARCHAR(255),
        addressCountry VARCHAR(255),
        addressPostalCode VARCHAR(20),
        documents JSON,
        isVerified BOOLEAN DEFAULT FALSE,
        verificationToken VARCHAR(500),
        jwtToken VARCHAR(500),
        resetPasswordToken VARCHAR(500),
        resetPasswordExpires DATETIME,
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
        createdAt TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        updatedAt TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
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
      logger.info('Админ создан: admin@24webstudio.ru');
    }

    connection.release();
  } catch (err) {
    logger.error(`Ошибка инициализации базы данных: ${err.message}`);
    throw err;
  }
}

// Server initialization
async function initializeServer() {
  try {
    await initializeDatabase();
    await checkS3Connection();
    app.listen(PORT, () => logger.info(`Сервер запущен на порту ${PORT}`));
  } catch (err) {
    logger.error(`Ошибка инициализации сервера: ${err.message}`);
    process.exit(1);
  }
}

// Public routes
app.get('/api/public/apps', async (req, res) => {
  try {
    const [apps] = await db.query("SELECT id, name, description, category, iconPath, status, createdAt FROM Apps WHERE status = 'approved' ORDER BY createdAt DESC");
    res.json(apps);
  } catch (err) {
    logger.error(`Ошибка получения приложений: ${err.message}`);
    res.status(500).json({ message: 'Ошибка сервера' });
  }
});

app.get('/api/public/app-image/:key', optionalAuthenticateToken, async (req, res) => {
  const { key } = req.params;
  try {
    const image = await getFromS3(`icons/${key}`);
    res.setHeader('Content-Type', image.ContentType || 'image/png');
    image.Body.pipe(res);
  } catch (err) {
    logger.error(`Ошибка получения изображения: ${err.message}`);
    res.status(500).json({ message: 'Ошибка получения изображения' });
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
      if (existing.length > 0) return res.status(400).json({ message: 'Email уже в списке ожидания' });

      await db.query('INSERT INTO PreRegisters (email) VALUES (?)', [email]);
      logger.info(`Предрегистрация: ${email}`);

      await axios.post(
        `https://api.telegram.org/bot${TELEGRAM_BOT_TOKEN}/sendMessage`,
        {
          chat_id: '-1002311447135',
          text: `Новая предрегистрация: ${email}`,
          parse_mode: 'Markdown',
        }
      ).catch(err => logger.error(`Ошибка уведомления в Telegram: ${err.message}`));

      res.status(201).json({ message: `Спасибо! Ваш email (${email}) добавлен в список ожидания.` });
    } catch (error) {
      logger.error(`Ошибка предрегистрации: ${error.message}`);
      res.status(500).json({ message: 'Ошибка сервера' });
    }
  }
);

// User registration with Telegram verification
app.post(
  '/api/auth/register',
  upload,
  [
    body('email').isEmail().normalizeEmail().withMessage('Требуется действительный email'),
    body('password').isLength({ min: 8 }).withMessage('Пароль должен содержать минимум 8 символов'),
    body('accountType').isIn(['individual', 'commercial']).withMessage('Недопустимый тип аккаунта'),
    body('name').notEmpty().trim().withMessage('Требуется имя'),
    body('phone').notEmpty().trim().withMessage('Требуется номер телефона'),
  ],
  async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      logger.warn(`Ошибки валидации: ${JSON.stringify(errors.array())}`);
      return res.status(400).json({ message: 'Ошибка валидации', errors: errors.array() });
    }

    try {
      const { email, password, accountType, name, phone, addressStreet, addressCity, addressCountry, addressPostalCode } = req.body;
      if (!req.files?.documents?.length) {
        logger.warn('Документы не загружены');
        return res.status(400).json({ message: 'Требуется хотя бы один документ' });
      }

      const [existingUser] = await db.query('SELECT email FROM Users WHERE email = ?', [email]);
      if (existingUser.length > 0) return res.status(400).json({ message: 'Email уже зарегистрирован' });

      const documentUrls = await Promise.all(req.files.documents.map(file => uploadToS3(file, 'documents')));
      const salt = await bcrypt.genSalt(10);
      const hashedPassword = await bcrypt.hash(password, salt);
      const verificationToken = jwt.sign({ email }, JWT_SECRET, { expiresIn: '24h' });

      const [result] = await db.query(
        `INSERT INTO Users (
          email, password, accountType, name, phone, addressStreet, addressCity, addressCountry, addressPostalCode,
          documents, isVerified, verificationToken
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
        [
          email, hashedPassword, accountType, name, phone, addressStreet || null, addressCity || null, addressCountry || null,
          addressPostalCode || null, JSON.stringify(documentUrls), false, verificationToken
        ]
      );

      const authToken = jwt.sign({ id: result.insertId, email }, JWT_SECRET, { expiresIn: '7d' });
      await db.query('UPDATE Users SET jwtToken = ? WHERE id = ?', [authToken, result.insertId]);

      // Отправка ссылки верификации через Telegram
      const verificationLink = `${BASE_URL}/api/auth/verify/${verificationToken}`;
      await axios.post(
        `https://api.telegram.org/bot${TELEGRAM_BOT_TOKEN}/sendMessage`,
        {
          chat_id: '-1002311447135', // Замените на chat_id пользователя или механизм получения chat_id
          text: `Здравствуйте, ${name}! Пожалуйста, подтвердите ваш email для завершения регистрации: ${verificationLink}`,
          parse_mode: 'Markdown',
        }
      ).catch(err => logger.error(`Ошибка отправки ссылки верификации в Telegram: ${err.message}`));

      // Уведомление админу о новых документах
      await axios.post(
        `https://api.telegram.org/bot${TELEGRAM_BOT_TOKEN}/sendMessage`,
        {
          chat_id: '-1002311447135',
          text: `Новые документы для проверки от пользователя ${email}. Количество: ${documentUrls.length}`,
          parse_mode: 'Markdown',
        }
      ).catch(err => logger.error(`Ошибка уведомления админу в Telegram: ${err.message}`));

      logger.info(`Пользователь зарегистрирован: ${email}`);
      res.status(201).json({
        message: 'Регистрация успешна. Проверьте Telegram для подтверждения email.',
        token: authToken,
        user: { id: result.insertId, email, accountType, name, phone, isVerified: false },
      });
    } catch (error) {
      logger.error(`Ошибка регистрации: ${error.message}`);
      res.status(500).json({ message: 'Ошибка сервера' });
    }
  }
);

// Verify email via Telegram link
app.get('/api/auth/verify/:token', async (req, res) => {
  const { token } = req.params;
  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    const [user] = await db.query('SELECT id, email, verificationToken FROM Users WHERE email = ? AND verificationToken = ?', [decoded.email, token]);
    if (!user.length) {
      logger.warn(`Недействительный токен верификации для email: ${decoded.email}`);
      return res.status(400).json({ message: 'Недействительный или истекший токен верификации' });
    }

    await db.query('UPDATE Users SET isVerified = ?, verificationToken = NULL WHERE email = ?', [true, decoded.email]);
    logger.info(`Email верифицирован для ${decoded.email}`);

    await axios.post(
      `https://api.telegram.org/bot${TELEGRAM_BOT_TOKEN}/sendMessage`,
      {
        chat_id: '-1002311447135',
        text: `Email ${decoded.email} успешно верифицирован.`,
        parse_mode: 'Markdown',
      }
    ).catch(err => logger.error(`Ошибка уведомления о верификации в Telegram: ${err.message}`));

    res.status(200).json({ message: 'Email успешно подтвержден. Ваш аккаунт верифицирован.' });
  } catch (error) {
    logger.error(`Ошибка верификации email: ${error.message}`);
    res.status(400).json({ message: 'Недействительный или истекший токен верификации' });
  }
});

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

      logger.info(`Пользователь вошел: ${user[0].email}`);
      res.status(200).json({
        token,
        user: { id: user[0].id, email: user[0].email, accountType: user[0].accountType, name: user[0].name, phone: user[0].phone, isVerified: user[0].isVerified },
        message: user[0].isVerified ? 'Вход успешен' : 'Вход успешен, но аккаунт ожидает верификации',
      });
    } catch (error) {
      logger.error(`Ошибка входа: ${error.message}`);
      res.status(500).json({ message: 'Ошибка сервера' });
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
      const [user] = await db.query('SELECT id, email FROM Users WHERE email = ?', [email]);
      if (!user.length) {
        logger.warn(`Попытка сброса пароля для несуществующего email: ${email}`);
        return res.status(404).json({ message: 'Пользователь с таким email не найден' });
      }

      const resetToken = jwt.sign({ email }, JWT_SECRET, { expiresIn: '1h' });
      await db.query(
        'UPDATE Users SET resetPasswordToken = ?, resetPasswordExpires = ? WHERE email = ?',
        [resetToken, new Date(Date.now() + 3600000), email]
      );

      logger.info(`Запрошен сброс пароля для ${user[0].email}`);
      res.status(200).json({ message: 'Ссылка для сброса пароля отправлена (реализуйте отправку email)' });
    } catch (error) {
      logger.error(`Ошибка сброса пароля: ${error.message}`);
      res.status(500).json({ message: 'Ошибка сервера' });
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
      const decoded = jwt.verify(token, JWT_SECRET);
      const [user] = await db.query(
        'SELECT id, email FROM Users WHERE email = ? AND resetPasswordToken = ? AND resetPasswordExpires > NOW()',
        [decoded.email, token]
      );
      if (!user.length) {
        logger.warn(`Недействительный токен сброса для email: ${decoded.email}`);
        return res.status(400).json({ message: 'Недействительный или истекший токен' });
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
      logger.error(`Ошибка сброса пароля: ${error.message}`);
      res.status(400).json({ message: 'Недействительный или истекший токен' });
    }
  }
);

// Get user profile
app.get('/api/user/profile', authenticateToken, async (req, res) => {
  try {
    const [user] = await db.query(
      'SELECT id, email, accountType, name, phone, addressStreet, addressCity, addressCountry, addressPostalCode, documents, isVerified, createdAt FROM Users WHERE id = ?',
      [req.user.id]
    );
    if (!user.length) {
      logger.warn(`Пользователь не найден для ID: ${req.user.id}`);
      return res.status(404).json({ message: 'Пользователь не найден' });
    }

    let documents = [];
    try {
      documents = user[0].documents ? JSON.parse(user[0].documents) : [];
      if (!Array.isArray(documents)) documents = [documents];
    } catch (parseError) {
      logger.error(`Ошибка парсинга документов для пользователя ${user[0].email}: ${parseError.message}`);
      documents = [];
    }

    user[0].documents = documents;
    res.status(200).json(user[0]);
  } catch (error) {
    logger.error(`Ошибка получения профиля: ${error.message}`);
    res.status(500).json({ message: 'Ошибка сервера' });
  }
});

// Update user documents
app.post(
  '/api/user/documents',
  authenticateToken,
  upload,
  async (req, res) => {
    try {
      const [user] = await db.query('SELECT id, email, documents FROM Users WHERE id = ?', [req.user.id]);
      if (!user.length) {
        logger.warn(`Пользователь не найден для ID: ${req.user.id}`);
        return res.status(404).json({ message: 'Пользователь не найден' });
      }

      if (!req.files?.documents?.length) {
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

      await axios.post(
        `https://api.telegram.org/bot${TELEGRAM_BOT_TOKEN}/sendMessage`,
        {
          chat_id: '-1002311447135',
          text: `Новые документы для проверки от пользователя ${user[0].email}. Количество: ${newDocuments.length}`,
          parse_mode: 'Markdown',
        }
      ).catch(err => logger.error(`Ошибка уведомления в Telegram: ${err.message}`));

      logger.info(`Документы обновлены для пользователя ${user[0].email}`);
      res.status(200).json({ message: 'Документы успешно загружены и ожидают проверки', documents: updatedDocuments });
    } catch (error) {
      logger.error(`Ошибка обновления документов: ${error.message}`);
      res.status(500).json({ message: 'Ошибка сервера' });
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
      const [user] = await db.query('SELECT id, email, isVerified FROM Users WHERE id = ?', [req.user.id]);
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

      if (!files?.icon?.[0]) {
        logger.warn('Файл иконки отсутствует');
        return res.status(400).json({ message: 'Требуется файл иконки (только PNG)' });
      }
      if (!files?.apk?.[0]) {
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

      await axios.post(
        `https://api.telegram.org/bot${TELEGRAM_BOT_TOKEN}/sendMessage`,
        {
          chat_id: '-1002311447135',
          text: `Новое приложение отправлено: ${name} от ${user[0].email}`,
          parse_mode: 'Markdown',
        }
      ).catch(err => logger.error(`Ошибка уведомления в Telegram: ${err.message}`));

      res.status(201).json({
        message: 'Приложение успешно отправлено',
        app: { id: result.insertId, name, description, category, iconPath: iconUrl, apkPath: apkUrl, userId: user[0].id, status: 'pending' },
      });
    } catch (error) {
      logger.error(`Ошибка создания приложения: ${error.message}`);
      res.status(500).json({ message: 'Ошибка сервера' });
    }
  }
);

// Admin routes
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
    logger.error(`Ошибка получения приложений для админа: ${err.message}`);
    res.status(500).json({ message: 'Ошибка сервера' });
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
      const [appUser] = await db.query('SELECT email FROM Users WHERE id = ?', [app[0].userId]);
      await axios.post(
        `https://api.telegram.org/bot${TELEGRAM_BOT_TOKEN}/sendMessage`,
        {
          chat_id: '-1002311447135',
          text: `Статус приложения ${app[0].name} обновлен на ${status} для пользователя ${appUser[0].email}`,
          parse_mode: 'Markdown',
        }
      ).catch(err => logger.error(`Ошибка уведомления в Telegram: ${err.message}`));
    }

    res.json({ message: `Статус приложения обновлен на ${status}` });
  } catch (err) {
    logger.error(`Ошибка обновления приложения: ${err.message}`);
    res.status(500).json({ message: 'Ошибка сервера' });
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

    if (app[0].iconPath) await deleteFromS3(`icons/${app[0].iconPath.split('/').pop()}`);
    if (app[0].apkPath) await deleteFromS3(`apks/${app[0].apkPath.split('/').pop()}`);

    await db.query('DELETE FROM Apps WHERE id = ?', [id]);
    logger.info(`Приложение ${id} удалено`);

    res.json({ message: 'Приложение удалено' });
  } catch (err) {
    logger.error(`Ошибка удаления приложения: ${err.message}`);
    res.status(500).json({ message: 'Ошибка сервера' });
  }
});

app.get('/api/admin/users/documents', authenticateToken, async (req, res) => {
  try {
    const [user] = await db.query('SELECT email, accountType FROM Users WHERE id = ?', [req.user.id]);
    if (!user.length || user[0].email !== 'admin@24webstudio.ru') {
      return res.status(403).json({ message: 'Требуется доступ администратора' });
    }

    const [users] = await db.query(`
      SELECT id, email, name, accountType, documents, isVerified, createdAt
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
    logger.error(`Ошибка получения документов пользователей: ${err.message}`);
    res.status(500).json({ message: 'Ошибка сервера' });
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

    const [user] = await db.query('SELECT email, documents FROM Users WHERE id = ?', [id]);
    if (!user.length) {
      return res.status(404).json({ message: 'Пользователь не найден' });
    }

    await db.query('UPDATE Users SET isVerified = ? WHERE id = ?', [isVerified, id]);
    logger.info(`Статус верификации пользователя ${user[0].email} обновлен на ${isVerified}`);

    await axios.post(
      `https://api.telegram.org/bot${TELEGRAM_BOT_TOKEN}/sendMessage`,
      {
        chat_id: '-1002311447135',
        text: `Статус верификации пользователя ${user[0].email} обновлен на ${isVerified ? 'верифицирован' : 'не верифицирован'}`,
        parse_mode: 'Markdown',
      }
    ).catch(err => logger.error(`Ошибка уведомления в Telegram: ${err.message}`));

    res.json({ message: `Статус верификации обновлен на ${isVerified ? 'верифицирован' : 'не верифицирован'}` });
  } catch (err) {
    logger.error(`Ошибка верификации пользователя: ${err.message}`);
    res.status(500).json({ message: 'Ошибка сервера' });
  }
});

// Admin routes for advertisements
app.get('/api/admin/advertisements', authenticateToken, async (req, res) => {
  try {
    const [user] = await db.query('SELECT email, accountType FROM Users WHERE id = ?', [req.user.id]);
    if (!user.length || user[0].email !== 'admin@24webstudio.ru') {
      return res.status(403).json({ message: 'Требуется доступ администратора' });
    }

    const [ads] = await db.query('SELECT id, name, description, budget, status, impressions, clicks, createdAt FROM Advertisements ORDER BY createdAt DESC');
    res.json(ads);
  } catch (err) {
    logger.error(`Ошибка получения рекламных кампаний: ${err.message}`);
    res.status(500).json({ message: 'Ошибка сервера' });
  }
});

app.post(
  '/api/admin/advertisements',
  authenticateToken,
  [
    body('name').notEmpty().trim().withMessage('Требуется название кампании'),
    body('description').notEmpty().trim().withMessage('Требуется описание'),
    body('budget').isFloat({ min: 0 }).withMessage('Бюджет должен быть положительным числом'),
    body('status').isIn(['active', 'paused', 'completed']).withMessage('Недопустимый статус'),
  ],
  async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      logger.warn(`Ошибки валидации: ${JSON.stringify(errors.array())}`);
      return res.status(400).json({ message: 'Ошибка валидации', errors: errors.array() });
    }

    try {
      const [user] = await db.query('SELECT email, accountType FROM Users WHERE id = ?', [req.user.id]);
      if (!user.length || user[0].email !== 'admin@24webstudio.ru') {
        return res.status(403).json({ message: 'Требуется доступ администратора' });
      }

      const { name, description, budget, status } = req.body;
      const [result] = await db.query(
        `INSERT INTO Advertisements (name, description, budget, status, impressions, clicks) VALUES (?, ?, ?, ?, 0, 0)`,
        [name, description, budget, status]
      );

      logger.info(`Рекламная кампания создана: ${name}`);

      await axios.post(
        `https://api.telegram.org/bot${TELEGRAM_BOT_TOKEN}/sendMessage`,
        {
          chat_id: '-1002311447135',
          text: `Новая рекламная кампания создана: ${name}, бюджет: ${budget}, статус: ${status}`,
          parse_mode: 'Markdown',
        }
      ).catch(err => logger.error(`Ошибка уведомления в Telegram: ${err.message}`));

      res.status(201).json({
        message: 'Рекламная кампания успешно создана',
        ad: { id: result.insertId, name, description, budget, status, impressions: 0, clicks: 0, createdAt: new Date() },
      });
    } catch (error) {
      logger.error(`Ошибка создания рекламной кампании: ${error.message}`);
      res.status(500).json({ message: 'Ошибка сервера' });
    }
  }
);

app.put('/api/admin/advertisements/:id', authenticateToken, async (req, res) => {
  const { id } = req.params;
  const { status } = req.body;

  try {
    const [user] = await db.query('SELECT email, accountType FROM Users WHERE id = ?', [req.user.id]);
    if (!user.length || user[0].email !== 'admin@24webstudio.ru') {
      return res.status(403).json({ message: 'Требуется доступ администратора' });
    }

    if (!['active', 'paused', 'completed'].includes(status)) {
      return res.status(400).json({ message: 'Недопустимый статус' });
    }

    const [ad] = await db.query('SELECT * FROM Advertisements WHERE id = ?', [id]);
    if (!ad.length) {
      return res.status(404).json({ message: 'Кампания не найдена' });
    }

    await db.query('UPDATE Advertisements SET status = ? WHERE id = ?', [status, id]);
    logger.info(`Статус кампании ${id} обновлен на ${status}`);

    await axios.post(
      `https://api.telegram.org/bot${TELEGRAM_BOT_TOKEN}/sendMessage`,
      {
        chat_id: '-1002311447135',
        text: `Статус кампании ${ad[0].name} обновлен на ${status}`,
        parse_mode: 'Markdown',
      }
    ).catch(err => logger.error(`Ошибка уведомления в Telegram: ${err.message}`));

    res.json({ message: `Статус кампании обновлен на ${status}` });
  } catch (err) {
    logger.error(`Ошибка обновления кампании: ${err.message}`);
    res.status(500).json({ message: 'Ошибка сервера' });
  }
});

app.delete('/api/admin/advertisements/:id', authenticateToken, async (req, res) => {
  const { id } = req.params;

  try {
    const [user] = await db.query('SELECT email, accountType FROM Users WHERE id = ?', [req.user.id]);
    if (!user.length || user[0].email !== 'admin@24webstudio.ru') {
      return res.status(403).json({ message: 'Требуется доступ администратора' });
    }

    const [ad] = await db.query('SELECT * FROM Advertisements WHERE id = ?', [id]);
    if (!ad.length) {
      return res.status(404).json({ message: 'Кампания не найдена' });
    }

    await db.query('DELETE FROM Advertisements WHERE id = ?', [id]);
    logger.info(`Кампания ${id} удалена`);

    res.json({ message: 'Кампания удалена' });
  } catch (err) {
    logger.error(`Ошибка удаления кампании: ${err.message}`);
    res.status(500).json({ message: 'Ошибка сервера' });
  }
});

// Error handling middleware
app.use((err, req, res, next) => {
  logger.error(`Необработанная ошибка: ${err.message}, маршрут: ${req.originalUrl}`);
  if (err instanceof multer.MulterError) {
    logger.warn(`Ошибка Multer: ${err.message}`);
    return res.status(400).json({ message: `Ошибка загрузки файла: ${err.message}` });
  }
  if (err.message.includes('Разрешены только')) {
    logger.warn(`Ошибка типа файла: ${err.message}`);
    return res.status(400).json({ message: err.message });
  }
  res.status(500).json({ message: 'Ошибка сервера' });
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