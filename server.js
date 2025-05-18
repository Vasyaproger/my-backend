const express = require('express');
const { Sequelize, DataTypes } = require('sequelize');
const mysql2 = require('mysql2');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const nodemailer = require('nodemailer');
const multer = require('multer');
const path = require('path');
const cors = require('cors');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const { body, validationResult } = require('express-validator');
const winston = require('winston');

const app = express();

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

// Middleware
app.use(helmet());
app.use(cors());
app.use(express.json());
app.use('/uploads', express.static(path.join(__dirname, 'Uploads')));

// Rate limiter
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100, // Limit each IP to 100 requests
});
app.use(limiter);

// MySQL setup
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

// User model
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
    type: DataTypes.JSON,
    allowNull: false,
    defaultValue: [],
  },
  isVerified: {
    type: DataTypes.BOOLEAN,
    defaultValue: false,
  },
  verificationToken: {
    type: DataTypes.STRING,
  },
  resetPasswordToken: {
    type: DataTypes.STRING,
  },
  resetPasswordExpires: {
    type: DataTypes.DATE,
  },
}, {
  timestamps: true,
  tableName: 'Users',
});

// Multer setup
const storage = multer.diskStorage({
  destination: './Uploads/documents/',
  filename: (req, file, cb) => {
    const sanitizedName = path.basename(file.originalname, path.extname(file.originalname)).replace(/[^a-zA-Z0-9]/g, '_');
    cb(null, `${Date.now()}-${sanitizedName}${path.extname(file.originalname)}`);
  },
});
const upload = multer({
  storage,
  limits: { fileSize: 5 * 1024 * 1024 }, // 5 MB
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

// Nodemailer setup
const transporter = nodemailer.createTransport({
  host: 'smtp.gmail.com',
  port: 587,
  secure: false, // Use TLS
  auth: {
    user: 'your_email@gmail.com', // REPLACE with your Gmail address
    pass: 'your_email_app_password', // REPLACE with your Gmail app-specific password
  },
  tls: {
    rejectUnauthorized: false, // For testing; remove in production
  },
});

// Email functions
async function sendVerificationEmail(email, token) {
  try {
    const verificationUrl = `http://localhost:3000/api/auth/verify/${token}`;
    const mailOptions = {
      from: 'your_email@gmail.com',
      to: email,
      subject: 'Подтверждение регистрации в PlayEvit',
      html: `
        <h2>Добро пожаловать в PlayEvit!</h2>
        <p>Пожалуйста, подтвердите ваш email, перейдя по ссылке:</p>
        <a href="${verificationUrl}" style="padding: 10px 20px; background-color: #2563eb; color: white; text-decoration: none; border-radius: 5px;">Подтвердить email</a>
        <p>Ссылка действительна 24 часа.</p>
      `,
    };
    logger.info(`Attempting to send verification email to ${email}`);
    const info = await transporter.sendMail(mailOptions);
    logger.info(`Verification email sent to ${email}: ${info.messageId}`);
  } catch (error) {
    logger.error(`Failed to send verification email to ${email}: ${error.message}`);
    throw error;
  }
}

async function sendPasswordResetEmail(email, token) {
  try {
    const resetUrl = `http://localhost:3000/reset-password/${token}`;
    const mailOptions = {
      from: 'your_email@gmail.com',
      to: email,
      subject: 'Сброс пароля в PlayEvit',
      html: `
        <h2>Сброс пароля</h2>
        <p>Вы запросили сброс пароля. Перейдите по ссылке, чтобы установить новый пароль:</p>
        <a href="${resetUrl}" style="padding: 10px 20px; background-color: #2563eb; color: white; text-decoration: none; border-radius: 5px;">Сбросить пароль</a>
        <p>Ссылка действительна 1 час.</p>
        <p>Если вы не запрашивали сброс, проигнорируйте это письмо.</p>
      `,
    };
    logger.info(`Attempting to send password reset email to ${email}`);
    const info = await transporter.sendMail(mailOptions);
    logger.info(`Password reset email sent to ${email}: ${info.messageId}`);
  } catch (error) {
    logger.error(`Failed to send password reset email to ${email}: ${error.message}`);
    throw error;
  }
}

// Middleware to authenticate JWT
const authenticateToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];
  if (!token) {
    return res.status(401).json({ message: 'Требуется токен авторизации' });
  }
  try {
    const decoded = jwt.verify(token, 'your_jwt_secret'); // REPLACE with a secure random string in production
    req.user = decoded;
    next();
  } catch (error) {
    logger.error(`Invalid token: ${error.message}`);
    return res.status(403).json({ message: 'Недействительный токен' });
  }
};

// Database sync
sequelize.sync({ force: false }).then(() => {
  logger.info('Database synchronized');
}).catch((error) => {
  logger.error(`Database sync failed: ${error.message}`);
});

// Routes

// Register
app.post('/api/auth/register',
  upload.array('documents', 3),
  [
    body('email').isEmail().normalizeEmail(),
    body('password').isLength({ min: 8 }),
    body('accountType').isIn(['individual', 'commercial']),
    body('name').notEmpty().trim(),
    body('phone').notEmpty().trim(),
  ],
  async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ message: 'Ошибка валидации', errors: errors.array() });
    }

    try {
      const {
        email, password, accountType, name, phone,
        addressStreet, addressCity, addressCountry, addressPostalCode,
      } = req.body;

      if (!req.files || req.files.length === 0) {
        return res.status(400).json({ message: 'Требуется хотя бы один документ' });
      }

      const existingUser = await User.findOne({ where: { email } });
      if (existingUser) {
        return res.status(400).json({ message: 'Email уже зарегистрирован' });
      }

      const salt = await bcrypt.genSalt(10);
      const hashedPassword = await bcrypt.hash(password, salt);
      const verificationToken = jwt.sign({ email }, 'your_jwt_secret', { expiresIn: '1d' });

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

      try {
        await sendVerificationEmail(email, verificationToken);
        logger.info(`User registered: ${email}`);
        res.status(201).json({ message: 'Регистрация успешна! Проверьте email для подтверждения.' });
      } catch (emailError) {
        logger.warn(`User registered but email failed for ${email}: ${emailError.message}`);
        res.status(201).json({
          message: 'Регистрация успешна, но письмо для подтверждения не отправлено. Свяжитесь с поддержкой.',
          email,
        });
      }
    } catch (error) {
      logger.error(`Registration error: ${error.message}`);
      res.status(500).json({ message: 'Ошибка сервера' });
    }
  }
);

// Verify email
app.get('/api/auth/verify/:token', async (req, res) => {
  try {
    const { token } = req.params;
    let decoded;
    try {
      decoded = jwt.verify(token, 'your_jwt_secret');
    } catch (error) {
      logger.warn(`Invalid verification token: ${error.message}`);
      return res.status(400).json({ message: 'Недействительный или истекший токен' });
    }

    const user = await User.findOne({ where: { email: decoded.email, verificationToken: token } });
    if (!user) {
      return res.status(400).json({ message: 'Пользователь не найден или токен недействителен' });
    }

    user.isVerified = true;
    user.verificationToken = null;
    await user.save();

    logger.info(`Email verified for ${user.email}`);
    res.status(200).json({ message: 'Email успешно подтвержден!' });
  } catch (error) {
    logger.error(`Verification error: ${error.message}`);
    res.status(500).json({ message: 'Ошибка сервера' });
  }
});

// Login
app.post('/api/auth/login',
  [
    body('email').isEmail().normalizeEmail(),
    body('password').notEmpty(),
  ],
  async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ message: 'Ошибка валидации', errors: errors.array() });
    }

    try {
      const { email, password } = req.body;

      const user = await User.findOne({ where: { email } });
      if (!user) {
        logger.warn(`Login attempt with non-existent email: ${email}`);
        return res.status(400).json({ message: 'Неверный email или пароль' });
      }

      const isMatch = await bcrypt.compare(password, user.password);
      if (!isMatch) {
        logger.warn(`Invalid password for email: ${email}`);
        return res.status(400).json({ message: 'Неверный email или пароль' });
      }

      if (!user.isVerified) {
        return res.status(400).json({ message: 'Подтвердите ваш email перед входом' });
      }

      const token = jwt.sign(
        { id: user.id, email: user.email },
        'your_jwt_secret',
        { expiresIn: '7d' }
      );

      logger.info(`User logged in: ${email}`);
      res.status(200).json({
        token,
        user: {
          id: user.id,
          email: user.email,
          accountType: user.accountType,
          name: user.name,
        },
        message: 'Вход успешен',
      });
    } catch (error) {
      logger.error(`Login error: ${error.message}`);
      res.status(500).json({ message: 'Ошибка сервера' });
    }
  }
);

// Forgot password
app.post('/api/auth/forgot-password',
  [body('email').isEmail().normalizeEmail()],
  async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
     return res.status(400).json({ message: 'Ошибка валидации', errors: errors.array() });

    }

    try {
      const { email } = req.body;
      const user = await User.findOne({ where: { email } });
      if (!user) {
        return res.status(404).json({ message: 'Пользователь с таким email не найден' });
      }

      const resetToken = jwt.sign({ email }, 'your_jwt_secret', { expiresIn: '1h' });
      user.resetPasswordToken = resetToken;
      user.resetPasswordExpires = new Date(Date.now() + 3600000); // 1 hour
      await user.save();

      try {
        await sendPasswordResetEmail(email, resetToken);
        logger.info(`Password reset requested for ${email}`);
        res.status(200).json({ message: 'Ссылка для сброса пароля отправлена на ваш email' });
      } catch (emailError) {
        logger.warn(`Password reset email failed for ${email}: ${emailError.message}`);
        res.status(200).json({
          message: 'Ссылка для сброса пароля не отправлена. Свяжитесь с поддержкой.',
          email,
        });
      }
    } catch (error) {
      logger.error(`Forgot password error: ${error.message}`);
      res.status(500).json({ message: 'Ошибка сервера' });
    }
  }
);

// Reset password
app.post('/api/auth/reset-password/:token',
  [
    body('password').isLength({ min: 8 }),
    body('confirmPassword').custom((value, { req }) => value === req.body.password),
  ],
  async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ message: 'Ошибка валидации', errors: errors.array() });
    }

    try {
      const { token } = req.params;
      const { password } = req.body;

      let decoded;
      try {
        decoded = jwt.verify(token, 'your_jwt_secret');
      } catch (error) {
        logger.warn(`Invalid reset token: ${error.message}`);
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
        return res.status(400).json({ message: 'Недействительный токен или срок действия истек' });
      }

      const salt = await bcrypt.genSalt(10);
      user.password = await bcrypt.hash(password, salt);
      user.resetPasswordToken = null;
      user.resetPasswordExpires = null;
      await user.save();

      logger.info(`Password reset for ${user.email}`);
      res.status(200).json({ message: 'Пароль успешно сброшен' });
    } catch (error) {
      logger.error(`Reset password error: ${error.message}`);
      res.status(500).json({ message: 'Ошибка сервера' });
    }
  }
);

// Get user profile
app.get('/api/user/profile', authenticateToken, async (req, res) => {
  try {
    const user = await User.findByPk(req.user.id, {
      attributes: { exclude: ['password', 'verificationToken', 'resetPasswordToken', 'resetPasswordExpires'] },
    });
    if (!user) {
      return res.status(404).json({ message: 'Пользователь не найден' });
    }
    res.status(200).json(user);
  } catch (error) {
    logger.error(`Profile error: ${error.message}`);
    res.status(500).json({ message: 'Ошибка сервера' });
  }
});

// Update documents
app.post('/api/user/documents',
  authenticateToken,
  upload.array('documents', 3),
  async (req, res) => {
    try {
      const user = await User.findByPk(req.user.id);
      if (!user) {
        return res.status(404).json({ message: 'Пользователь не найден' });
      }

      if (!req.files || req.files.length === 0) {
        return res.status(400).json({ message: 'Требуется хотя бы один документ' });
      }

      const newDocuments = req.files.map(file => file.path);
      user.documents = [...user.documents, ...newDocuments].slice(0, 3); // Max 3 documents
      await user.save();

      logger.info(`Documents updated for user ${user.email}`);
      res.status(200).json({ message: 'Документы успешно обновлены', documents: user.documents });
    } catch (error) {
      logger.error(`Document update error: ${error.message}`);
      res.status(500).json({ message: 'Ошибка сервера' });
    }
  }
);

// Error handling middleware
app.use((err, req, res, next) => {
  logger.error(`Unhandled error: ${err.message}`);
  if (err instanceof multer.MulterError) {
    return res.status(400).json({ message: 'Ошибка загрузки файла: ' + err.message });
  }
  res.status(500).json({ message: 'Ошибка сервера' });
});

// Start server
const PORT = 5000;
app.listen(PORT, () => {
  logger.info(`Server running on port ${PORT}`);
});