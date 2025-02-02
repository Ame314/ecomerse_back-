// routes/productRoutes.js
const express = require("express");
const {
  createProduct,
  getProducts,
  getProductById,
  updateProduct,
  deleteProduct
} = require("../controllers/productController");

const { verifyToken, checkAdmin } = require("../middleware/authMiddleware");

const router = express.Router();

// Rutas abiertas a todos los usuarios logueados o no (tú decides).
// Si quieres que solo usuarios logueados vean productos, agrega verifyToken.
router.get("/", getProducts);
router.get("/:id", getProductById);

// Rutas protegidas para ADMIN:
router.post("/", verifyToken, checkAdmin, createProduct);
router.put("/:id", verifyToken, checkAdmin, updateProduct);
router.delete("/:id", verifyToken, checkAdmin, deleteProduct);

module.exports = router;
