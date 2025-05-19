const express = require('express');
const { Sequelize, DataTypes } = require('sequelize');
const mysql2 = require('mysql2');
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

// Конфигурация переменных окружения (без dotenv)
const JWT_SECRET = 'x7b9k3m8p2q5w4z6t1r0y9u2j4n6l8h3'; // Сгенерированный безопасный ключ221
const DB_HOST = 'vh438.timeweb.ru';
const DB_USER = 'ch79145_project';
const DB_PASSWORD = 'Vasya11091109';
const DB_NAME = 'ch79145_project';
const S3_ACCESS_KEY = 'DN1NLZTORA2L6NZ529JJ';
const S3_SECRET_KEY = 'iGg3syd3UiWzhoYbYlEEDSVX1HHVmWUptrBt81Y8';
const CORS_ORIGIN = 'https://24webstudio.ru';
const PORT = 5000;
const BUCKET_NAME = '4eeafbc6-4af2cd44-4c23-4530-a2bf-750889dfdf75';
const DB_SSL = 'false';

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

// Подключение к базе данных
const sequelize = new Sequelize({
  dialect: 'mysql',
  host: DB_HOST,
  username: DB_USER,
  password: DB_PASSWORD,
  database: DB_NAME,
  port: 3306,
  dialectModule: mysql2,
  logging: (msg) => logger.debug(msg),
  pool: {
    max: 10,
    min: 0,
    acquire: 30000,
    idle: 10000,
  },
  dialectOptions: {
    ssl: {
      require: DB_SSL === 'true',
      rejectUnauthorized: false,
    },
    connectTimeout: 30000,
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
      logger.error(`Попытка ${attempt} не удалась: ${error.message}, stack: ${error.stack}`);
      if (error.message.includes('Host') && error.message.includes('blocked')) {
        logger.error('Хост заблокирован MySQL. Выполните "mysqladmin flush-hosts" на сервере.');
      }
      if (error.message.includes('caching_sha2_password')) {
        logger.error('Ошибка аутентификации. Убедитесь, что пользователь использует caching_sha2_password.');
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

// Модель User
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
    defaultValue: true, // Автоматическая верификация
  },
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

// Модель PreRegister
const PreRegister = sequelize.define('PreRegister', {
  email: {
    type: DataTypes.STRING,
    allowNull: false,
    unique: true,
    validate: { isEmail: true },
  },
}, {
  timestamps: true,
  tableName: 'PreRegisters',
});

// Модель App
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

// Функция загрузки в S3 (v3)
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

// Синхронизация базы данных
async function syncDatabase() {
  try {
    logger.info('Начало синхронизации базы данных');
    await sequelize.sync({ force: false });
    logger.info('База данных успешно синхронизирована');

    const tablesToCheck = ['Users', 'PreRegisters', 'Apps'];
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
    logger.error(`Ошибка синхронизации базы данных: ${error.message}, stack: ${error.stack}`);
    throw error;
  }
}

// Инициализация приложения
async function initializeApp() {
  logger.info('Инициализация приложения');
  try {
    logger.info('Проверка переменных окружения');
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
      const existingPreRegister = await PreRegister.findOne({ where: { email } });
      if (existingPreRegister) {
        return res.status(400).json({ message: 'Этот email уже в списке ожидания' });
      }

      await PreRegister.create({ email });
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

      const existingUser = await User.findOne({ where: { email } });
      if (existingUser) {
        return res.status(400).json({ message: 'Email уже зарегистрирован' });
      }

      const documentUrls = await Promise.all(
        req.files.documents.map(file => uploadToS3(file, 'documents'))
      );

      const salt = await bcrypt.genSalt(10);
      const hashedPassword = await bcrypt.hash(password, salt);
      const authToken = jwt.sign({ email, accountType, name }, JWT_SECRET, { expiresIn: '7d' });

      const user = await User.create({
        email,
        password: hashedPassword,
        accountType,
        name,
        phone,
        addressStreet,
        addressCity,
        addressCountry,
        addressPostalCode,
        documents: documentUrls,
        isVerified: true,
        jwtToken: authToken,
      });

      logger.info(`Пользователь зарегистрирован: ${email}`);
      res.status(201).json({
        message: 'Регистрация успешна!',
        token: authToken,
        user: { id: user.id, email, accountType, name, phone },
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
      const user = await User.findOne({ where: { email } });
      if (!user) {
        logger.warn(`Попытка сброса пароля для несуществующего email: ${email}`);
        return res.status(404).json({ message: 'Пользователь с этим email не найден' });
      }

      const resetToken = jwt.sign({ email }, JWT_SECRET, { expiresIn: '1h' });
      user.resetPasswordToken = resetToken;
      user.resetPasswordExpires = new Date(Date.now() + 3600000);
      await user.save();

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
    const user = await User.findByPk(req.user.id, {
      attributes: { exclude: ['password', 'resetPasswordToken', 'resetPasswordExpires', 'jwtToken'] },
    });
    if (!user) {
      logger.warn(`Пользователь не найден для ID: ${req.user.id}`);
      return res.status(404).json({ message: 'Пользователь не найден' });
    }
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

      logger.info(`Документы обновлены для пользователя ${user.email}`);
      res.status(200).json({ message: 'Документы успешно обновлены', documents: user.documents });
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

      logger.info(`Приложение создано пользователем ${user.email}: ${name}`);
      res.status(201).json({ message: 'Приложение успешно отправлено', app });
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
  await sequelize.close();
  logger.info('Соединение с базой данных закрыто');
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