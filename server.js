const express = require('express');
const mysql = require("mysql2/promise");
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const multer = require('multer');
const path = require('path');
const cors = require('cors');
const helmet = require('helmet');
const { body, validationResult } = require('express-validator');
const winston = require('winston');
const { S3Client, PutObjectCommand, ListBucketsCommand } = require('@aws-sdk/client-s3');

const app = express();

// Конфигурация переменных окружения
const JWT_SECRET = 'x7b9k3m8p2q5w4z6t1r0y9u2j4n6l8h3';
const DB_HOST = '24webstudio.ru';
const DB_USER = 'ch79145_project';
const DB_PASSWORD = 'Vasya11091109';
const DB_NAME = 'ch79145_project';
const S3_ACCESS_KEY = 'DN1NLZTORA2L6NZ529JJ';
const S3_SECRET_KEY = 'iGg3syd3UiWzhoYbYlEEDSVX1HHVmWUptrBt81Y8';
const CORS_ORIGIN = 'https://24webstudio.ru';
const PORT = 5000;
const BUCKET_NAME = '4eeafbc6-4af2cd44-4c23-4530-a2bf-750889dfdf75';

// Проверка обязательных переменных
const requiredEnvVars = [
  'JWT_SECRET',
  'DB_HOST',
  'DB_USER',
  'DB_PASSWORD',
  'DB_NAME',
  'S3_ACCESS_KEY',
  'S3_SECRET_KEY',
];
for (const envVar of requiredEnvVars) {
  const value = eval(envVar);
  if (!value || value === `YOUR_${envVar}`) {
    console.error(`Ошибка: Переменная ${envVar} не задана или имеет значение по умолчанию`);
    process.exit(1);
  }
}

// Логирование
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

// AWS S3 (v3)
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
    logger.error(`Ошибка подключения к S3: ${err.message}, stack: ${err.stack}`);
    throw err;
  }
}

// Middleware
app.use(helmet());
app.use(cors({
  origin: CORS_ORIGIN,
  methods: ['GET', 'POST', 'PUT', 'DELETE'],
  allowedHeaders: ['Content-Type', 'Authorization'],
}));
app.use(express.json());

// Подключение к MySQL (одиночное соединение)
let connection;

async function initializeConnection() {
  try {
    connection = await mysql.createConnection({
      host: DB_HOST,
      user: DB_USER,
      password: DB_PASSWORD,
      database: DB_NAME,
      port: 3306,
      connectTimeout: 30000,
    });
    logger.info('Подключение к базе данных успешно');
  } catch (error) {
    logger.error(`Ошибка подключения к базе данных: ${error.message}, stack: ${error.stack}`);
    throw error;
  }
}

// Функция выполнения запросов
const query = async (sql, params) => {
  try {
    const [results] = await connection.execute(sql, params);
    return results;
  } catch (error) {
    logger.error(`Ошибка выполнения запроса: ${error.message}, stack: ${error.stack}`);
    throw error;
  }
};

// Механизм повторного подключения к базе данных
async function connectWithRetry(maxRetries = 5, retryDelay = 60000) {
  logger.info('Начало попыток подключения к MySQL');
  for (let attempt = 1; attempt <= maxRetries; attempt++) {
    try {
      await initializeConnection();
      await query('SELECT 1');
      logger.info('Подключение к базе данных успешно');
      return;
    } catch (error) {
      logger.error(`Попытка ${attempt} не удалась: ${error.message}, stack: ${error.stack}`);
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

// Настройка загрузки файлов
const upload = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: 10 * 1024 * 1024 },
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
    await s3Client.send(new PutObjectCommand(params));
    const location = `https://s3.twcstorage.ru/${BUCKET_NAME}/${key}`;
    logger.info(`Файл загружен в S3: ${key}`);
    return location;
  } catch (error) {
    logger.error(`Ошибка загрузки в S3 для ${key}: ${error.message}, stack: ${error.stack}`);
    throw new Error(`Ошибка загрузки в S3: ${error.message}`);
  }
}

// Middleware аутентификации JWT
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
    logger.error(`Недействительный токен: ${error.message}, stack: ${error.stack}`);
    return res.status(403).json({ message: 'Недействительный или истёкший токен' });
  }
};

// Проверка структуры базы данных
async function syncDatabase() {
  try {
    logger.info('Начало проверки структуры базы данных');
    const tablesToCheck = ['Users', 'PreRegisters', 'Apps'];
    for (const table of tablesToCheck) {
      const results = await query(`SHOW TABLES LIKE ?`, [table]);
      if (results.length > 0) {
        logger.info(`Таблица ${table} существует`);
      } else {
        logger.error(`Таблица ${table} не найдена`);
        throw new Error(`Таблица ${table} не существует`);
      }
    }
    logger.info('Структура базы данных проверена');
  } catch (error) {
    logger.error(`Ошибка проверки базы данных: ${error.message}, stack: ${error.stack}`);
    throw error;
  }
}

// Инициализация приложения
async function initializeApp() {
  logger.info('Инициализация приложения');
  try {
    logger.info(`DB_HOST: ${DB_HOST}, DB_NAME: ${DB_NAME}, S3_BUCKET: ${BUCKET_NAME}`);
    await connectWithRetry();
    await syncDatabase();
    await checkS3Connection();
    logger.info('Приложение успешно инициализировано');
  } catch (error) {
    logger.error(`Критическая ошибка инициализации: ${error.message}, stack: ${error.stack}`);
    process.exit(1);
  }
}

// Маршруты

// Предварительная регистрация
app.post(
  '/api/pre-register',
  [
    body('email').isEmail().normalizeEmail().withMessage('Требуется действительный email'),
  ],
  async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      logger.warn(`Ошибки валидации: ${JSON.stringify(errors.array())}`);
      return res.status(400).json({ message: 'Ошибка валидации', errors: errors.array() });
    }

    try {
      const { email } = req.body;
      const [existing] = await query('SELECT email FROM PreRegisters WHERE email = ?', [email]);
      if (existing) {
        return res.status(400).json({ message: 'Этот email уже в списке ожидания' });
      }

      await query('INSERT INTO PreRegisters (email, createdAt, updatedAt) VALUES (?, NOW(), NOW())', [email]);
      logger.info(`Предварительная регистрация: ${email}`);
      res.status(201).json({ message: `Спасибо за интерес! Ваш email (${email}) добавлен в список ожидания.` });
    } catch (error) {
      logger.error(`Ошибка предварительной регистрации: ${error.message}, stack: ${error.stack}`);
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
  ],
  async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      logger.warn(`Ошибки валидации: ${JSON.stringify(errors.array())}`);
      return res.status(400).json({ message: 'Ошибка валидации', errors: errors.array() });
    }

    try {
      const {
        email, password, accountType, name, phone,
        addressStreet, addressCity, addressCountry, addressPostalCode,
      } = req.body;

      if (!req.files || !req.files.documents || req.files.documents.length === 0) {
        logger.warn('Документы не загружены при регистрации');
        return res.status(400).json({ message: 'Требуется хотя бы один документ' });
      }

      const [existingUser] = await query('SELECT email FROM Users WHERE email = ?', [email]);
      if (existingUser) {
        return res.status(400).json({ message: 'Email уже зарегистрирован' });
      }

      const documentUrls = await Promise.all(
        req.files.documents.map(file => uploadToS3(file, 'documents'))
      );

      const salt = await bcrypt.genSalt(10);
      const hashedPassword = await bcrypt.hash(password, salt);
      const authToken = jwt.sign({ email, accountType, name }, JWT_SECRET, { expiresIn: '7d' });

      const [result] = await query(
        `INSERT INTO Users (
          email, password, accountType, name, phone,
          addressStreet, addressCity, addressCountry, addressPostalCode,
          documents, isVerified, jwtToken, createdAt, updatedAt
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, NOW(), NOW())`,
        [
          email, hashedPassword, accountType, name, phone,
          addressStreet || null, addressCity || null, addressCountry || null, addressPostalCode || null,
          JSON.stringify(documentUrls), true, authToken,
        ]
      );

      logger.info(`Пользователь зарегистрирован: ${email}`);
      res.status(201).json({
        message: 'Регистрация успешна!',
        token: authToken,
        user: { id: result.insertId, email, accountType, name, phone },
      });
    } catch (error) {
      logger.error(`Ошибка регистрации: ${error.message}, stack: ${error.stack}`);
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
      const [user] = await query('SELECT * FROM Users WHERE email = ?', [email]);
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
        await query('UPDATE Users SET jwtToken = ? WHERE id = ?', [token, user.id]);
      }

      logger.info(`Пользователь вошёл: ${user.email}`);
      res.status(200).json({
        token,
        user: {
          id: user.id,
          email: user.email,
          accountType: user.accountType,
          name: user.name,
          phone: user.phone,
        },
        message: 'Вход успешен',
      });
    } catch (error) {
      logger.error(`Ошибка входа: ${error.message}, stack: ${error.stack}`);
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
      const [user] = await query('SELECT id, email FROM Users WHERE email = ?', [email]);
      if (!user) {
        logger.warn(`Попытка сброса пароля для несуществующего email: ${email}`);
        return res.status(404).json({ message: 'Пользователь с этим email не найден' });
      }

      const resetToken = jwt.sign({ email }, JWT_SECRET, { expiresIn: '1h' });
      await query(
        'UPDATE Users SET resetPasswordToken = ?, resetPasswordExpires = ? WHERE email = ?',
        [resetToken, new Date(Date.now() + 3600000), email]
      );

      logger.info(`Запрос сброса пароля для ${user.email}`);
      res.status(200).json({ message: 'Ссылка для сброса пароля отправлена (реализуйте отправку по email)' });
    } catch (error) {
      logger.error(`Ошибка запроса сброса пароля: ${error.message}, stack: ${error.stack}`);
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
        logger.warn(`Недействительный токен сброса: ${error.message}, stack: ${error.stack}`);
        return res.status(400).json({ message: 'Недействительный или истёкший токен' });
      }

      const [user] = await query(
        'SELECT id, email FROM Users WHERE email = ? AND resetPasswordToken = ? AND resetPasswordExpires > NOW()',
        [decoded.email, token]
      );
      if (!user) {
        logger.warn(`Недействительный или истёкший токен сброса для email: ${decoded.email}`);
        return res.status(400).json({ message: 'Недействительный токен или истёк' });
      }

      const salt = await bcrypt.genSalt(10);
      const hashedPassword = await bcrypt.hash(password, salt);
      await query(
        'UPDATE Users SET password = ?, resetPasswordToken = NULL, resetPasswordExpires = NULL, jwtToken = NULL WHERE email = ?',
        [hashedPassword, decoded.email]
      );

      logger.info(`Пароль сброшен для ${user.email}`);
      res.status(200).json({ message: 'Пароль успешно сброшен' });
    } catch (error) {
      logger.error(`Ошибка сброса пароля: ${error.message}, stack: ${error.stack}`);
      res.status(500).json({ message: 'Ошибка сервера', error: error.message });
    }
  }
);

// Получение профиля пользователя
app.get('/api/user/profile', authenticateToken, async (req, res) => {
  try {
    const [user] = await query(
      'SELECT id, email, accountType, name, phone, addressStreet, addressCity, addressCountry, addressPostalCode, documents, isVerified, createdAt, updatedAt FROM Users WHERE id = ?',
      [req.user.id]
    );
    if (!user) {
      logger.warn(`Пользователь не найден для ID: ${req.user.id}`);
      return res.status(404).json({ message: 'Пользователь не найден' });
    }
    user.documents = JSON.parse(user.documents || '[]');
    res.status(200).json(user);
  } catch (error) {
    logger.error(`Ошибка получения профиля: ${error.message}, stack: ${error.stack}`);
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
      const [user] = await query('SELECT id, email, documents FROM Users WHERE id = ?', [req.user.id]);
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

      const currentDocuments = JSON.parse(user.documents || '[]');
      const updatedDocuments = [...currentDocuments, ...newDocuments].slice(0, 3);
      await query('UPDATE Users SET documents = ?, isVerified = ? WHERE id = ?', [
        JSON.stringify(updatedDocuments), true, user.id
      ]);

      logger.info(`Документы обновлены для пользователя ${user.email}`);
      res.status(200).json({ message: 'Документы успешно обновлены', documents: updatedDocuments });
    } catch (error) {
      logger.error(`Ошибка обновления документов: ${error.message}, stack: ${error.stack}`);
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
      const [user] = await query('SELECT id, email, isVerified FROM Users WHERE id = ?', [req.user.id]);
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

      const [result] = await query(
        `INSERT INTO Apps (
          name, description, category, iconPath, apkPath, userId, status, createdAt, updatedAt
        ) VALUES (?, ?, ?, ?, ?, ?, ?, NOW(), NOW())`,
        [name, description, category, iconUrl, apkUrl, user.id, 'pending']
      );

      logger.info(`Приложение создано пользователем ${user.email}: ${name}`);
      res.status(201).json({
        message: 'Приложение успешно отправлено',
        app: { id: result.insertId, name, description, category, iconPath: iconUrl, apkPath: apkUrl, userId: user.id, status: 'pending' },
      });
    } catch (error) {
      logger.error(`Ошибка создания приложения: ${error.message}, stack: ${error.stack}`);
      res.status(500).json({ message: 'Ошибка сервера', error: error.message });
    }
  }
);

// Обработка ошибок
app.use((err, req, res, next) => {
  logger.error(`Необработанная ошибка: ${err.message}, stack: ${err.stack}`);
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
  logger.info('Выполняется graceful shutdown...');
  if (connection) {
    await connection.end();
    logger.info('Соединение с базой данных закрыто');
  }
  process.exit(0);
}

process.on('SIGINT', shutdown);
process.on('SIGTERM', shutdown);

// Запуск сервера
async function startServer() {
  try {
    await initializeApp();
    app.listen(PORT, () => {
      logger.info(`Сервер запущен на порту ${PORT}`);
    });
  } catch (error) {
    logger.error(`Ошибка запуска сервера: ${error.message}, stack: ${error.stack}`);
    process.exit(1);
  }
}

startServer();