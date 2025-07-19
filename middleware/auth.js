const jwt = require('jsonwebtoken');

const protect = (req, res, next) => {
  const token = req.cookies.theAccessToken;

  if (!token) {
    return res.status(401).json({ message: 'No autorizado, no hay token' });
  }

  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    req.user = decoded; // Adjunta el payload del token al objeto req
    next();
  } catch (error) {
    console.log("error", error);
    return res.status(401).json({ message: 'Token inválido o expirado' });
  }
};

module.exports = protect;