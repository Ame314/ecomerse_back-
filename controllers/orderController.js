const pool = require("../config/database");

// Crear una orden
const createOrder = async (req, res) => {
  try {
    const { cartItems } = req.body;
    const userId = req.user.userId;

    if (!cartItems || !Array.isArray(cartItems) || cartItems.length === 0) {
      return res.status(400).json({ message: "Carrito vacío o inválido" });
    }

    let totalPrice = 0;

    for (const item of cartItems) {
      const queryProduct = `SELECT id, name, price, stock FROM products WHERE id = ?`;
      const [products] = await pool.query(queryProduct, [item.productId]);
      const product = products[0];

      if (!product) {
        return res.status(400).json({ message: `Producto ${item.productId} no existe` });
      }

      if (product.stock < item.quantity) {
        return res.status(400).json({ message: `Stock insuficiente para el producto ${item.productId}` });
      }

      totalPrice += product.price * item.quantity;
    }

    const queryOrder = `
      INSERT INTO orders (user_id, total_price, status, created_at, updated_at)
      VALUES (?, ?, 'pending', NOW(), NOW())
    `;
    const [orderResult] = await pool.query(queryOrder, [userId, totalPrice]);
    const orderId = orderResult.insertId;

    for (const item of cartItems) {
      const queryProduct = `SELECT price FROM products WHERE id = ?`;
      const [products] = await pool.query(queryProduct, [item.productId]);
      const product = products[0];

      const queryOrderItem = `
        INSERT INTO order_items (order_id, product_id, quantity, price)
        VALUES (?, ?, ?, ?)
      `;
      await pool.query(queryOrderItem, [orderId, item.productId, item.quantity, product.price]);

      const queryUpdateStock = `
        UPDATE products SET stock = stock - ? WHERE id = ?
      `;
      await pool.query(queryUpdateStock, [item.quantity, item.productId]);
    }

    return res.status(201).json({
      message: "Orden creada exitosamente",
      orderId,
    });
  } catch (error) {
    console.error("Error al crear la orden:", error);
    return res.status(500).json({ message: "Error al crear la orden." });
  }
};

// Obtener órdenes por usuario
const getUserOrders = async (req, res) => {
  try {
    const userId = req.user.userId;

    const query = `
      SELECT 
        o.id AS order_id,
        o.total_price,
        o.status,
        o.created_at AS order_date,
        oi.id AS order_item_id,
        oi.quantity,
        oi.price AS item_price,
        p.id AS product_id,
        p.name AS product_name,
        p.description AS product_description,
        p.price AS product_price
      FROM 
        orders o
      INNER JOIN 
        order_items oi ON o.id = oi.order_id
      INNER JOIN 
        products p ON oi.product_id = p.id
      WHERE 
        o.user_id = ?
      ORDER BY 
        o.created_at DESC;
    `;

    const [rows] = await pool.query(query, [userId]);

    const orders = {};
    rows.forEach((row) => {
      if (!orders[row.order_id]) {
        orders[row.order_id] = {
          id: row.order_id,
          total_price: row.total_price,
          status: row.status,
          created_at: row.order_date,
          order_items: [],
        };
      }
      orders[row.order_id].order_items.push({
        id: row.order_item_id,
        quantity: row.quantity,
        price: row.item_price,
        product: {
          id: row.product_id,
          name: row.product_name,
          description: row.product_description,
          price: row.product_price,
        },
      });
    });

    return res.status(200).json(Object.values(orders));
  } catch (error) {
    console.error("Error al obtener las órdenes del usuario:", error);
    return res.status(500).json({ message: "Error al obtener las órdenes." });
  }
};

// Obtener todas las órdenes (admin)
const getAllOrders = async (req, res) => {
  try {
    const query = `
      SELECT 
        o.id AS order_id,
        o.total_price,
        o.status,
        o.created_at AS order_date,
        u.id AS user_id,
        u.username AS user_name,
        u.email AS user_email,
        oi.id AS order_item_id,
        oi.quantity,
        oi.price AS item_price,
        p.id AS product_id,
        p.name AS product_name,
        p.description AS product_description,
        p.price AS product_price
      FROM 
        orders o
      INNER JOIN 
        users u ON o.user_id = u.id
      INNER JOIN 
        order_items oi ON o.id = oi.order_id
      INNER JOIN 
        products p ON oi.product_id = p.id
      ORDER BY 
        o.created_at DESC;
    `;

    const [rows] = await pool.query(query);

    const orders = {};
    rows.forEach((row) => {
      if (!orders[row.order_id]) {
        orders[row.order_id] = {
          id: row.order_id,
          total_price: row.total_price,
          status: row.status,
          created_at: row.order_date,
          user: {
            id: row.user_id,
            name: row.user_name,
          },
          order_items: [],
        };
      }
      orders[row.order_id].order_items.push({
        id: row.order_item_id,
        quantity: row.quantity,
        price: row.item_price,
        product: {
          id: row.product_id,
          name: row.product_name,
          description: row.product_description,
          price: row.product_price,
        },
      });
    });

    return res.status(200).json(Object.values(orders));
  } catch (error) {
    console.error("Error al obtener todas las órdenes:", error);
    return res.status(500).json({ message: "Error al obtener todas las órdenes." });
  }
};


// Actualizar el estado de una orden
const updateOrderStatus = async (req, res) => {
  try {
    const { orderId } = req.params;
    const { status } = req.body;

    // Validar que el estado no sea vacío o inválido
    if (!status || !["pending", "picked", "delivered"].includes(status)) {
      return res.status(400).json({ message: "Estado inválido o vacío" });
    }

    console.log(`Actualizando orden ID: ${orderId}, Nuevo estado: ${status}`); // Debug

    // Ejecutar la consulta de actualización
    const query = `UPDATE orders SET status = ? WHERE id = ?`;
    const [result] = await pool.query(query, [status, orderId]);

    if (result.affectedRows === 0) {
      return res.status(404).json({ message: "Orden no encontrada" });
    }

    return res.json({ message: "Estado de orden actualizado", orderId, status });
  } catch (error) {
    console.error("Error al actualizar el estado de la orden:", error);
    return res.status(500).json({ message: "Error al actualizar el estado de la orden." });
  }
};


module.exports = {
  createOrder,
  getUserOrders,
  getAllOrders,
  updateOrderStatus,
};
