const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const pool = require("../config/database");

// Clave secreta para JWT, obtenida de variables de entorno
const JWT_SECRET = process.env.JWT_SECRET || "mi_secreto_jwt";

// Registro de usuario
const register = async (req, res) => {
  try {
    const { username, email, password, role } = req.body;

    // Verificar si el email ya está registrado
    const queryEmail = `SELECT id FROM users WHERE email = ?`;
    const [existingUser] = await pool.query(queryEmail, [email]);

    if (existingUser.length > 0) {
      return res.status(400).json({ message: "El email ya está registrado" });
    }

    // Encriptar la contraseña
    const salt = await bcrypt.genSalt(10);
    const hashedPassword = await bcrypt.hash(password, salt);

    // Insertar el nuevo usuario en la base de datos
    const queryInsert = `
      INSERT INTO users (username, email, password, role) 
      VALUES (?, ?, ?, ?)
    `;
    const [result] = await pool.query(queryInsert, [
      username,
      email,
      hashedPassword,
      role || "user", // Si no se especifica, toma "user" como valor predeterminado
    ]);

    // Retornar la información del usuario creado
    return res.status(201).json({
      id: result.insertId,
      username,
      email,
      role: role || "user",
    });
  } catch (error) {
    console.error("Error al registrar usuario:", error);
    return res.status(500).json({ message: "Error al registrar usuario" });
  }
};

// Inicio de sesión
const login = async (req, res) => {
  try {
    const { email, password } = req.body;

    // Verificar si existe el usuario
    const queryUser = `
      SELECT id, username, email, password, role 
      FROM users 
      WHERE email = ?
    `;
    const [users] = await pool.query(queryUser, [email]);

    if (users.length === 0) {
      return res.status(400).json({ message: "Usuario o contraseña inválida" });
    }

    const user = users[0];

    // Comparar contraseñas
    const esValida = await bcrypt.compare(password, user.password);
    if (!esValida) {
      return res.status(400).json({ message: "Usuario o contraseña inválida" });
    }

    // Crear token
    const token = jwt.sign(
      {
        userId: user.id,
        role: user.role,
      },
      JWT_SECRET,
      { expiresIn: "1d" } // Token válido por 1 día
    );

    // Retornar info del usuario (sin la contraseña) y el token
    return res.json({
      message: "Login exitoso",
      token,
      user: {
        id: user.id,
        username: user.username,
        email: user.email,
        role: user.role,
      },
    });
  } catch (error) {
    console.error("Error al iniciar sesión:", error);
    return res.status(500).json({ message: "Error al iniciar sesión" });
  }
};

const nodemailer = require("nodemailer");

const requestPasswordReset = async (req, res) => {
  try {
    const { email } = req.body;

    // Verificar si el email existe
    const queryUser = `SELECT id, username FROM users WHERE email = ?`;
    const [users] = await pool.query(queryUser, [email]);

    if (users.length === 0) {
      return res.status(404).json({ message: "Correo no registrado" });
    }

    const user = users[0];

    // Crear un token de recuperación
    const resetToken = jwt.sign({ userId: user.id }, JWT_SECRET, {
      expiresIn: "1h", // Token válido por 1 hora
    });

    // Configurar el transporte de Nodemailer
    const transporter = nodemailer.createTransport({
      service: "gmail", // Cambia a tu proveedor de correo si no usas Gmail
      auth: {
        user: process.env.EMAIL_USER, // Tu correo electrónico
        pass: process.env.EMAIL_PASS, // Tu contraseña o app password
      },
    });

    // Crear el enlace de restablecimiento
    const resetLink = `http://localhost:3000/reset-password/reset?token=${resetToken}`;

    // Configurar los detalles del correo
    const mailOptions = {
      from: process.env.EMAIL_USER,
      to: email,
      subject: "Recuperación de contraseña",
      text: `Hola ${user.username},\n\nHas solicitado restablecer tu contraseña. Haz clic en el siguiente enlace para continuar:\n\n${resetLink}\n\nEste enlace será válido por 1 hora.\n\nSi no solicitaste este cambio, puedes ignorar este correo.`,
    };

    // Enviar el correo
    await transporter.sendMail(mailOptions);

    return res.json({
      message: "Correo enviado con éxito. Verifica tu bandeja de entrada.",
    });
  } catch (error) {
    console.error("Error al generar token o enviar correo:", error);
    return res.status(500).json({ message: "Error al enviar el correo" });
  }
};


const resetPassword = async (req, res) => {
  try {
    const { token, newPassword } = req.body;

    // Verificar el token
    const decoded = jwt.verify(token, JWT_SECRET);

    const userId = decoded.userId;

    // Encriptar la nueva contraseña
    const salt = await bcrypt.genSalt(10);
    const hashedPassword = await bcrypt.hash(newPassword, salt);

    // Actualizar la contraseña en la base de datos
    const queryUpdate = `UPDATE users SET password = ? WHERE id = ?`;
    await pool.query(queryUpdate, [hashedPassword, userId]);

    return res.json({ message: "Contraseña actualizada correctamente" });
  } catch (error) {
    console.error("Error al restablecer contraseña:", error);

    if (error.name === "TokenExpiredError") {
      return res.status(400).json({ message: "El token ha expirado" });
    }

    return res.status(500).json({ message: "Error al restablecer contraseña" });
  }
};

// Obtener el perfil del usuario (GET /me)
const me = async (req, res) => {
  try {
    const userId = req.user.userId; // req.user es definido en el verifyToken
    const [rows] = await pool.query(
      "SELECT id, username, email, role FROM users WHERE id = ?",
      [userId]
    );

    if (rows.length === 0) {
      return res.status(404).json({ message: "Usuario no encontrado" });
    }

    return res.json(rows[0]);
  } catch (error) {
    console.error("Error al obtener perfil:", error);
    return res.status(500).json({ message: "Error al obtener perfil" });
  }
};

// Actualizar perfil (PUT /me)
const updateMe = async (req, res) => {
  try {
    const userId = req.user.userId;  // Viene del middleware
    const { username, email } = req.body;

    // Actualizar en la base de datos
    await pool.query(
      "UPDATE users SET username = ?, email = ? WHERE id = ?",
      [username, email, userId]
    );

    // Volver a obtener los datos actualizados y devolverlos
    const [rows] = await pool.query(
      "SELECT id, username, email, role FROM users WHERE id = ?",
      [userId]
    );

    return res.json(rows[0]);
  } catch (error) {
    console.error("Error al actualizar perfil:", error);
    return res.status(500).json({ message: "Error al actualizar perfil" });
  }
};

module.exports = {
  register,
  login,
  requestPasswordReset,
  resetPassword,
  me,
  updateMe

};
