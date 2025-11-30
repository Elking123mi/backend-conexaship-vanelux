import sql from 'mssql';
import { getPool } from '../config/database.js';

export async function getProfile (req, res, next) {
  try {
    const pool = await getPool();
    const request = pool.request();
    request.input('workerId', sql.VarChar(50), req.user.workerId);
    const result = await request.query(`
      SELECT w.worker_id, w.zone, w.role, w.card_code, u.email, u.name
      FROM workers w
      INNER JOIN users u ON u.id = w.user_id
      WHERE w.worker_id = @workerId
    `);
    if (!result.recordset.length) {
      return res.status(404).json({ success: false, message: 'Trabajador no encontrado' });
    }
    return res.json({ success: true, data: result.recordset[0] });
  } catch (error) {
    return next(error);
  }
}

export async function clockIn (req, res, next) {
  try {
    const { timestamp, location, notes } = req.body;
    const pool = await getPool();
    const request = pool.request();
    request.input('workerId', sql.VarChar(50), req.user.workerId);
    request.input('clockTime', sql.DateTime2, timestamp ? new Date(timestamp) : new Date());
    request.input('latitude', sql.Decimal(9, 6), location?.latitude ?? null);
    request.input('longitude', sql.Decimal(9, 6), location?.longitude ?? null);
    request.input('address', sql.NVarChar(255), location?.address ?? null);
    request.input('notes', sql.NVarChar(sql.MAX), notes ?? null);

    await request.execute('sp_clock_in');
    return res.status(201).json({ success: true });
  } catch (error) {
    return next(error);
  }
}

export async function clockOut (req, res, next) {
  try {
    const { timestamp, location, notes } = req.body;
    const pool = await getPool();
    const request = pool.request();
    request.input('workerId', sql.VarChar(50), req.user.workerId);
    request.input('clockTime', sql.DateTime2, timestamp ? new Date(timestamp) : new Date());
    request.input('latitude', sql.Decimal(9, 6), location?.latitude ?? null);
    request.input('longitude', sql.Decimal(9, 6), location?.longitude ?? null);
    request.input('address', sql.NVarChar(255), location?.address ?? null);
    request.input('notes', sql.NVarChar(sql.MAX), notes ?? null);

    await request.execute('sp_clock_out');
    return res.status(201).json({ success: true });
  } catch (error) {
    return next(error);
  }
}

export async function getTimesheet (req, res, next) {
  try {
    const { from, to } = req.query;
    const pool = await getPool();
    const request = pool.request();
    request.input('workerId', sql.VarChar(50), req.user.workerId);
    request.input('from', sql.Date, from ? new Date(from) : null);
    request.input('to', sql.Date, to ? new Date(to) : null);
    const result = await request.query(`
      SELECT ts.id, ts.worker_id, ts.clock_in_time, ts.clock_out_time,
             ts.total_hours, ts.overtime_hours, ts.status, ts.notes
      FROM timesheets ts
      WHERE ts.worker_id = @workerId
        AND (@from IS NULL OR ts.clock_in_time >= @from)
        AND (@to IS NULL OR ts.clock_in_time <= @to)
      ORDER BY ts.clock_in_time DESC
    `);
    return res.json({ success: true, data: result.recordset });
  } catch (error) {
    return next(error);
  }
}
