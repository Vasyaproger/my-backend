const express = require('express');
const { Sequelize, DataTypes } = require('sequelize');
const mysql2 = require('mysql2'); // Добавлен импорт mysql2
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const nodemailer = require('nodemailer');
const multer = require('multer');
const path = require('path');
const cors = require('cors');

const app = express();

// Middleware
app.use(cors());
app.use(express.json());
app.use('/uploads', express.static('uploads'));

// Настройка MySQL
const sequelize = new Sequelize({
  dialect: 'mysql',
  host: 'vh438.timeweb.ru',
  username: 'ch79145_myprojec',
  password: 'Vasya11091109',
  database: 'ch79145_myprojec',
  port: 3306,
  dialectModule: mysql2, // Указываем использование mysql2
});

// Модель пользователя
const User = sequelize.define('User', {
  email: {
    type: DataTypes.STRING,
    allowNull: false,
    unique: true,
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
  addressStreet: {
    type: DataTypes.STRING,
  },
  addressCity: {
    type: DataTypes.STRING,
  },
  addressCountry: {
    type: DataTypes.STRING,
  },
  addressPostalCode: {
    type: DataTypes.STRING,
  },
  documents: {
    type: DataTypes.JSON, // Храним пути к файлам как JSON массив
    allowNull: false,
  },
  isVerified: {
    type: DataTypes.BOOLEAN,
    defaultValue: false,
  },
  verificationToken: {
    type: DataTypes.STRING,
  },
}, {
  timestamps: true,
  tableName: 'Users', // Явно задаем имя таблицы для MySQL
});

// Настройка Multer для загрузки документов
const storage = multer.diskStorage({
  destination: './uploads/documents/',
  filename: (req, file, cb) => {
    cb(null, `${Date.now()}-${file.originalname}`);
  },
});
const upload = multer({
  storage,
  limits: { fileSize: 5 * 1024 * 1024 }, // 5 МБ
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

// Настройка Nodemailer
const transporter = nodemailer.createTransport({
  service: 'gmail',
  auth: {
    user: 'your_email@gmail.com',
    pass: 'your_email_app_password',
  },
});

// Функция отправки email
async function sendVerificationEmail(email, token) {
  const verificationUrl = `http://localhost:3000/api/auth/verify/${token}`;
  const mailOptions = {
    from: 'your_email@gmail.com',
    to: email,
    subject: 'Подтверждение регистрации в PlayEvit',
    html: `
      <h2>Добро пожаловать в PlayEvit!</h2>
      <p>Пожалуйста, подтвердите ваш email, перейдя по ссылке:</p>
      <a href="${verificationUrl}">Подтвердить email</a>
      <p>Ссылка действительна 24 часа.</p>
    `,
  };
  await transporter.sendMail(mailOptions);
}

// Синхронизация базы данных
sequelize.sync({ force: false }).then(() => {
  console.log('База данных синхронизирована');
});

// Маршрут регистрации
app.post('/api/auth/register', upload.array('documents', 3), async (req, res) => {
  try {
    const {
      email,
      password,
      accountType,
      name,
      phone,
      addressStreet,
      addressCity,
      addressCountry,
      addressPostalCode,
    } = req.body;

    // Валидация
    if (!email || !password || !accountType || !name || !phone) {
      return res.status(400).json({ message: 'Все обязательные поля должны быть заполнены' });
    }
    if (!['individual', 'commercial'].includes(accountType)) {
      return res.status(400).json({ message: 'Неверный тип аккаунта' });
    }
    if (!req.files || req.files.length === 0) {
      return res.status(400).json({ message: 'Требуется хотя бы один документ' });
    }

    // Проверка существующего пользователя
    const existingUser = await User.findOne({ where: { email } });
    if (existingUser) {
      return res.status(400).json({ message: 'Email уже зарегистрирован' });
    }

    // Хеширование пароля
    const salt = await bcrypt.genSalt(10);
    const hashedPassword = await bcrypt.hash(password, salt);

    // Создание токена верификации
    const verificationToken = jwt.sign({ email }, 'your_jwt_secret', { expiresIn: '1d' });

    // Сохранение пользователя
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
      documents: req.files.map(file => file.path),
      verificationToken,
    });

    // Отправка email
    await sendVerificationEmail(email, verificationToken);

    res.status(201).json({ message: 'Регистрация успешна! Проверьте email для подтверждения.' });
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: 'Ошибка сервера' });
  }
});

// Маршрут верификации email
app.get('/api/auth/verify/:token', async (req, res) => {
  try {
    const { token } = req.params;
    let decoded;
    try {
      decoded = jwt.verify(token, 'your_jwt_secret');
    } catch (error) {
      return res.status(400).json({ message: 'Недействительный или истекший токен' });
    }

    const user = await User.findOne({ where: { email: decoded.email, verificationToken: token } });
    if (!user) {
      return res.status(400).json({ message: 'Пользователь не найден или токен недействителен' });
    }

    user.isVerified = true;
    user.verificationToken = null;
    await user.save();

    res.status(200).json({ message: 'Email успешно подтвержден!' });
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: 'Ошибка сервера' });
  }
});

// Маршрут входа
app.post('/api/auth/login', async (req, res) => {
  try {
    const { email, password } = req.body;

    // Валидация
    if (!email || !password) {
      return res.status(400).json({ message: 'Email и пароль обязательны' });
    }

    // Проверка пользователя
    const user = await User.findOne({ where: { email } });
    if (!user) {
      return res.status(400).json({ message: 'Неверный email или пароль' });
    }

    // Проверка пароля
    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
      return res.status(400).json({ message: 'Неверный email или пароль' });
    }

    // Проверка верификации
    if (!user.isVerified) {
      return res.status(400).json({ message: 'Подтвердите ваш email перед входом' });
    }

    // Создание JWT
    const token = jwt.sign({ id: user.id, email: user.email }, 'your_jwt_secret', { expiresIn: '7d' });

    res.status(200).json({ token, message: 'Вход успешен' });
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: 'Ошибка сервера' });
  }
});

// Запуск сервера
const PORT = 5000;
app.listen(PORT, () => console.log(`Сервер запущен на порту ${PORT}`));