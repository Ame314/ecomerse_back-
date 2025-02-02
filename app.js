const express = require("express");
const cors = require("cors");
const bodyParser = require("body-parser");
const dotenv = require("dotenv");
const pool = require("./config/database"); // Configuración de mysql2
const authRoutes = require("./routes/authRoutes");
const productRoutes = require("./routes/productRoutes");
const orderRoutes = require("./routes/orderRoutes");

dotenv.config(); // Cargar variables de entorno

const app = express();

// Middleware de CORS
app.use(
  cors({
    origin: "*", // Cambiar si necesitas restringir orígenes
    methods: "GET,HEAD,PUT,PATCH,POST,DELETE",
    credentials: true,
  })
);

// Middleware para procesar JSON
app.use(bodyParser.json());

// Servir archivos estáticos (por ejemplo, imágenes subidas)
app.use(express.static("uploads"));

// Verificar la conexión a la base de datos
(async () => {
  try {
    await pool.query("SELECT 1");
    console.log("Conexión exitosa a la base de datos MySQL");
  } catch (err) {
    console.error("Error al conectar a la base de datos:", err);
    process.exit(1); // Salir de la aplicación si no se puede conectar
  }
})();

// Rutas
app.use("/api/auth", authRoutes);
app.use("/api/products", productRoutes);
app.use("/api/orders", orderRoutes);

// Puerto del servidor
const PORT = process.env.PORT || 5000;

// Iniciar el servidor
app.listen(PORT, () => {
  console.log(`Servidor corriendo en http://localhost:${PORT}`);
});

// Ruta raíz para comprobar el estado del servidor
app.get("/", (req, res) => {
  res.send("¡Hola, tu servidor está funcionando!");
});
