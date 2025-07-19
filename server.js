// npm init -y
// npm install express mongoose jsonwebtoken bcryptjs cookie-parser dotenv


require('dotenv').config(); // Cargar variables de entorno al inicio
const express = require('express');
const cookieParser = require('cookie-parser');
const connectDB = require('./config/db');
const authRoutes = require('./routes/authRoutes');

const app = express();

// Conectar a la base de datos
connectDB();

// Middlewares
app.use(express.json()); // Para parsear el body de las peticiones JSON
app.use(cookieParser()); // Para parsear cookies

// Rutas de autenticación
app.use('/api/auth', authRoutes);

// Ruta de ejemplo pública
app.get('/', (req, res) => {
  res.send('API de autenticación con JWT y Refresh Token');
});

const PORT = process.env.PORT || 5000;

app.listen(PORT, () => {
  console.log(`Servidor corriendo en el puerto ${PORT}`);
});