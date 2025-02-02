// routes/orderRoutes.js
const express = require("express");
const {
  createOrder,
  getUserOrders,
  getAllOrders,
  updateOrderStatus
} = require("../controllers/orderController");
const { verifyToken, checkAdmin } = require("../middleware/authMiddleware");

const router = express.Router();

// Crear orden (solo usuarios logueados)
router.post("/create", verifyToken,createOrder);

// Ver órdenes del usuario logueado
router.get("/myorders", verifyToken,getUserOrders);

// Ver todas las órdenes (admin)
//router.get("/", verifyToken, checkAdmin, getAllOrders);
router.get("/", verifyToken,checkAdmin, getAllOrders);
// Actualizar estado de la orden (admin)
//router.put("/:orderId", verifyToken, checkAdmin, updateOrderStatus);
router.put("/:orderId", verifyToken,checkAdmin, updateOrderStatus);

module.exports = router;
