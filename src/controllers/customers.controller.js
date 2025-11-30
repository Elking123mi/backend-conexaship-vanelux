import { getPool } from '../config/database.js';

export async function getSampleCustomers (req, res, next) {
  try {
    const pool = await getPool();
    const result = await pool.request().query(`
      SELECT TOP 5
        id,
        name,
        phone
      FROM customers
      ORDER BY name
    `);

    if (!result.recordset.length) {
      return res.status(404).json({ success: false, message: 'No hay clientes registrados.' });
    }

    return res.json({ success: true, data: result.recordset });
  } catch (error) {
    return next(error);
  }
}
