// middleware/authMiddleware.js
const jwt = require("jsonwebtoken");
const dotenv = require("dotenv");

dotenv.config();
const JWT_SECRET = process.env.JWT_SECRET || "mi_secreto_jwt";

// Middleware para verificar el token y adjuntar datos del usuario a req.user
const verifyToken = (req, res, next) => {
  try {
    // Tomamos el token del header: Authorization: Bearer <token>
    const authHeader = req.headers.authorization;
    if (!authHeader) {
      return res.status(401).json({ message: "No se proporcionó un token" });
    }

    const token = authHeader.split(" ")[1];
    const decoded = jwt.verify(token, JWT_SECRET);

    // Guardamos info de usuario en la request
    req.user = {
      userId: decoded.userId,
      role: decoded.role,
    };

    next();
  } catch (error) {
    return res.status(401).json({ message: "Token inválido o expirado" });
  }
};

// Middleware para validar si el usuario es admin
const checkAdmin = (req, res, next) => {
  if (req.user.role !== "admin") {
    return res.status(403).json({ message: "Acceso denegado, se requiere rol de administrador" });
  }
  next();
};

module.exports = {
  verifyToken,
  checkAdmin,
};
