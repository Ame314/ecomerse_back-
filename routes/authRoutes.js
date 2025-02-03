// routes/authRoutes.js
const express = require("express");
const { register, login, requestPasswordReset, resetPassword, me, updateMe } = require("../controllers/authController");

const { verifyToken, checkAdmin } = require("../middleware/authMiddleware");


const router = express.Router();

// Ruta para registrar usuario
router.post("/register", register);

// Ruta para iniciar sesión
router.post("/login", login);

// Ruta para solicitar recuperación de contraseña
router.post("/request-password-reset", requestPasswordReset);

// Ruta para restablecer la contraseña
router.post("/reset-password", resetPassword);

router.get("/me", verifyToken, me);
router.put("/me", verifyToken, updateMe);


module.exports = router;
