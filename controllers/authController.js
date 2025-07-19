const User = require('../models/User');
const RefreshToken = require('../models/RefreshToken');
const jwt = require('jsonwebtoken');
const crypto = require('crypto'); // Para generar tokens aleatorios

// Función para generar Access Token
const generateAccessToken = (userId) => {
  return jwt.sign({ id: userId }, process.env.JWT_SECRET, {
    expiresIn: process.env.ACCESS_TOKEN_EXPIRATION,
  });
};

// Función para generar Refresh Token
const generateRefreshToken = async (userId) => {
  const token = crypto.randomBytes(64).toString('hex');
  const expiresAt = new Date(Date.now() + parseFloat(process.env.REFRESH_TOKEN_EXPIRATION.slice(0, -1)) * 24 * 60 * 60 * 1000); // Convierte "7d" a milisegundos

  // Guarda el refresh token en la base de datos
  await RefreshToken.create({
    userId,
    token,
    expiresAt,
  });
  return token;
};

// @desc    Registrar un nuevo usuario
// @route   POST /api/auth/register
// @access  Public
exports.registerUser = async (req, res) => {
  const { email, password } = req.body;

  try {
    let user = await User.findOne({ email });

    if (user) {
      return res.status(400).json({ message: 'El usuario ya existe' });
    }

    user = new User({
      email,
      password,
    });

    await user.save();

    res.status(201).json({ message: 'Usuario registrado exitosamente' });
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: 'Error del servidor' });
  }
};

// @desc    Iniciar sesión y obtener tokens
// @route   POST /api/auth/login
// @access  Public
exports.loginUser = async (req, res) => {
  const { email, password } = req.body;

  try {
    const user = await User.findOne({ email });

    if (!user) {
      return res.status(400).json({ message: 'Credenciales inválidas' });
    }

    const isMatch = await user.matchPassword(password);

    if (!isMatch) {
      return res.status(400).json({ message: 'Credenciales inválidas' });
    }

    // Generar Access Token
    const accessToken = generateAccessToken(user._id);

    // Generar y almacenar Refresh Token
    const refreshToken = await generateRefreshToken(user._id);

    // Enviar el refresh token como HttpOnly cookie (más seguro)
    res.cookie('refreshToken', refreshToken, {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production', // Solo HTTPS en producción
      sameSite: 'strict',
      maxAge: parseFloat(process.env.REFRESH_TOKEN_EXPIRATION.slice(0, -1)) * 24 * 60 * 60 * 1000,
    });

    // Enviar el access token como HttpOnly cookie (más seguro)
    res.cookie('theAccessToken', accessToken, {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production', // Solo HTTPS en producción
      sameSite: 'strict',
      maxAge: parseFloat(process.env.REFRESH_TOKEN_EXPIRATION.slice(0, -1)) * 24 * 60 * 60 * 1000,
    });

    res.json({ accessToken: "yea1" });
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: 'Error del servidor' });
  }
};

// @desc    Refrescar Access Token
// @route   POST /api/auth/refresh
// @access  Public (usa el refresh token de la cookie)
exports.refreshAccessToken = async (req, res) => {
  const refreshToken = req.cookies.refreshToken;

  if (!refreshToken) {
    return res.status(401).json({ message: 'No autorizado, no hay refresh token' });
  }

  try {
    const storedRefreshToken = await RefreshToken.findOne({ token: refreshToken });

    if (!storedRefreshToken) {
      return res.status(403).json({ message: 'Refresh token inválido' });
    }

    // Verificar si el refresh token ha expirado (aunque el TTL de MongoDB ya lo maneja, es una doble verificación)
    if (storedRefreshToken.expiresAt < Date.now()) {
        await storedRefreshToken.remove(); // Elimina el token expirado
        return res.status(403).json({ message: 'Refresh token expirado. Por favor, inicie sesión de nuevo.' });
    }

    // Obtiene el user id
    const userId = storedRefreshToken.userId;

    // Crea el accesToken de ese user id
    const newAccessToken = generateAccessToken(userId);

    // Enviar el access token como HttpOnly cookie (más seguro)
    res.cookie('theAccessToken', newAccessToken, {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production', // Solo HTTPS en producción
      sameSite: 'strict',
      maxAge: parseFloat(process.env.REFRESH_TOKEN_EXPIRATION.slice(0, -1)) * 24 * 60 * 60 * 1000,
    });

    res.json({ accessToken: "yea2" });

  } catch (error) {
    console.error(error);
    // Si la verificación del JWT del refresh token falla (ej. secreto incorrecto o token malformado)
    if (error.name === 'JsonWebTokenError' || error.name === 'TokenExpiredError') {
      return res.status(403).json({ message: 'Refresh token inválido o expirado' });
    }
    res.status(500).json({ message: 'Error del servidor' });
  }
};

// @desc    Cerrar sesión (revocar refresh token)
// @route   POST /api/auth/logout
// @access  Private (se puede hacer público o privado dependiendo de la estrategia)
exports.logoutUser = async (req, res) => {
  const refreshToken = req.cookies.refreshToken;

  if (!refreshToken) {
    return res.status(204).send(); // No hay contenido para enviar si no hay refresh token
  }

  try {
    // Eliminar el refresh token de la base de datos
    await RefreshToken.deleteOne({ token: refreshToken });

    // Limpiar la cookie del refresh token
    res.clearCookie('refreshToken', {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'strict',
    });

    // Limpiar la cookie del access token
    res.clearCookie('theAccessToken', {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'strict',
    });

    res.status(200).json({ message: 'Cierre de sesión exitoso' });
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: 'Error del servidor' });
  }
};

// @desc    Obtener perfil de usuario (ejemplo de ruta protegida)
// @route   GET /api/auth/profile
// @access  Private
exports.getProfile = async (req, res) => {
  try {
    const user = await User.findById(req.user.id).select('-password'); // Excluir la contraseña
    if (!user) {
      return res.status(404).json({ message: 'Usuario no encontrado' });
    }
    res.json(user);
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: 'Error del servidor' });
  }
};