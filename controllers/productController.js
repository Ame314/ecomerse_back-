const pool = require("../config/database");

// Crear producto (ADMIN)
const createProduct = async (req, res) => {
  try {
    const { name, description, price, stock, category, image } = req.body;

    const query = `
      INSERT INTO products (name, description, price, stock, category, image, created_at, updated_at)
      VALUES (?, ?, ?, ?, ?, ?, NOW(), NOW())
    `;

    const [result] = await pool.query(query, [name, description, price, stock, category, image]);

    return res.status(201).json({
      id: result.insertId,
      name,
      description,
      price,
      stock,
      category,
      image,
    });
  } catch (error) {
    console.error("Error al crear el producto:", error);
    return res.status(500).json({ message: "Error al crear el producto" });
  }
};

// Obtener todos los productos (USUARIOS/ADMIN)
const getProducts = async (req, res) => {
  try {
    const { category, search } = req.query;

    let query = `SELECT * FROM products`;
    const params = [];

    if (category || search) {
      query += ` WHERE`;
    }

    if (category) {
      query += ` category = ?`;
      params.push(category);
    }

    if (search) {
      if (category) query += ` AND`;
      query += ` name LIKE ?`;
      params.push(`%${search}%`);
    }

    const [products] = await pool.query(query, params);

    return res.json(products);
  } catch (error) {
    console.error("Error al obtener productos:", error);
    return res.status(500).json({ message: "Error al obtener productos" });
  }
};

// Obtener un producto por ID
const getProductById = async (req, res) => {
  try {
    const { id } = req.params;

    const query = `SELECT * FROM products WHERE id = ?`;
    const [products] = await pool.query(query, [id]);

    if (products.length === 0) {
      return res.status(404).json({ message: "Producto no encontrado" });
    }

    return res.json(products[0]);
  } catch (error) {
    console.error("Error al obtener producto:", error);
    return res.status(500).json({ message: "Error al obtener producto" });
  }
};

// Actualizar producto (ADMIN)
const updateProduct = async (req, res) => {
  try {
    const { id } = req.params;
    const { name, description, price, stock, category, image } = req.body;

    const query = `SELECT * FROM products WHERE id = ?`;
    const [products] = await pool.query(query, [id]);

    if (products.length === 0) {
      return res.status(404).json({ message: "Producto no encontrado" });
    }

    const updateQuery = `
      UPDATE products 
      SET name = ?, description = ?, price = ?, stock = ?, category = ?, image = ?, updated_at = NOW()
      WHERE id = ?
    `;
    await pool.query(updateQuery, [name, description, price, stock, category, image, id]);

    return res.json({
      id,
      name,
      description,
      price,
      stock,
      category,
      image,
    });
  } catch (error) {
    console.error("Error al actualizar producto:", error);
    return res.status(500).json({ message: "Error al actualizar producto" });
  }
};

// Eliminar producto (ADMIN)
const deleteProduct = async (req, res) => {
  try {
    const { id } = req.params;

    const query = `SELECT * FROM products WHERE id = ?`;
    const [products] = await pool.query(query, [id]);

    if (products.length === 0) {
      return res.status(404).json({ message: "Producto no encontrado" });
    }

    const deleteQuery = `DELETE FROM products WHERE id = ?`;
    await pool.query(deleteQuery, [id]);

    return res.json({ message: "Producto eliminado exitosamente" });
  } catch (error) {
    console.error("Error al eliminar producto:", error);
    return res.status(500).json({ message: "Error al eliminar producto" });
  }
};

module.exports = {
  createProduct,
  getProducts,
  getProductById,
  updateProduct,
  deleteProduct,
};
