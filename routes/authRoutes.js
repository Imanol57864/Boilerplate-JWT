const express = require('express');
const {
  registerUser,
  loginUser,
  refreshAccessToken,
  logoutUser,
  getProfile,
} = require('../controllers/authController');
const protect = require('../middleware/auth');

const router = express.Router();

router.post('/register', registerUser);
router.post('/login', loginUser);
router.post('/refresh', refreshAccessToken);
router.get('/logout', logoutUser);
router.get('/profile', protect, getProfile);

module.exports = router;