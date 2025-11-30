import bcrypt from 'bcryptjs';
import sql from 'mssql';
import { getPool } from '../config/database.js';
import { signAccessToken, signRefreshToken, verifyRefreshToken } from '../utils/token.js';

function buildWorkerPayload (workerRow) {
  return {
    userId: workerRow.user_id,
    workerId: workerRow.worker_id,
    email: workerRow.email,
    role: workerRow.role,
    zone: workerRow.zone
  };
}

function buildCustomerPayload (customerRow) {
  return {
    userId: customerRow.user_id,
    email: customerRow.email,
    role: 'customer'
  };
}

export async function workerLogin (req, res, next) {
  try {
    const { worker_id: workerId, password } = req.body;
    if (!workerId || !password) {
      return res.status(400).json({ success: false, message: 'Credenciales incompletas' });
    }

    const pool = await getPool();
    const request = pool.request();
    request.input('workerId', sql.VarChar(50), workerId);
    const result = await request.query(`
      SELECT worker_id, name, password, role, zone
      FROM workers
      WHERE worker_id = @workerId
    `);

    if (!result.recordset.length) {
      return res.status(401).json({ success: false, message: 'Credenciales inválidas' });
    }

    const row = result.recordset[0];
    // Comparar la contraseña directamente (sin hash, porque en tu tabla workers es texto plano)
    if (row.password !== password) {
      return res.status(401).json({ success: false, message: 'Credenciales inválidas' });
    }

    // Construir el payload manualmente
    const payload = {
      workerId: row.worker_id,
      name: row.name,
      role: row.role,
      zone: row.zone
    };
    const token = signAccessToken(payload);
    const refreshToken = signRefreshToken({ userId: row.worker_id, role: row.role });

    return res.json({ success: true, data: { token, refreshToken, worker: payload } });
  } catch (error) {
    return next(error);
  }
}

export async function customerLogin (req, res, next) {
  try {
    const { email, password } = req.body;
    if (!email || !password) {
      return res.status(400).json({ success: false, message: 'Credenciales incompletas' });
    }

    const pool = await getPool();
    const request = pool.request();
    request.input('email', sql.VarChar(255), email.toLowerCase());
    const result = await request.query(`
      SELECT c.user_id, u.email, u.password_hash
      FROM customers c
      INNER JOIN users u ON u.id = c.user_id
      WHERE u.email = @email AND u.is_active = 1
    `);

    if (!result.recordset.length) {
      return res.status(401).json({ success: false, message: 'Credenciales inválidas' });
    }

    const row = result.recordset[0];
    const isValid = await bcrypt.compare(password, row.password_hash);
    if (!isValid) {
      return res.status(401).json({ success: false, message: 'Credenciales inválidas' });
    }

    const payload = buildCustomerPayload(row);
    const token = signAccessToken(payload);
    const refreshToken = signRefreshToken({ userId: payload.userId, role: payload.role });

    return res.json({ success: true, data: { token, refreshToken, customer: payload } });
  } catch (error) {
    return next(error);
  }
}

export async function customerSignup (req, res, next) {
  try {
    const { email, password, name, phone } = req.body;
    if (!email || !password || !name) {
      return res.status(400).json({ success: false, message: 'Datos incompletos' });
    }

    const pool = await getPool();
    const request = pool.request();
    request.input('email', sql.VarChar(255), email.toLowerCase());
    const existing = await request.query('SELECT 1 FROM users WHERE email = @email');
    if (existing.recordset.length) {
      return res.status(409).json({ success: false, message: 'El correo ya está registrado' });
    }

    const passwordHash = await bcrypt.hash(password, 10);

    const transaction = new sql.Transaction(pool);
    await transaction.begin();
    try {
      const userRequest = transaction.request();
      userRequest.input('email', sql.VarChar(255), email.toLowerCase());
      userRequest.input('passwordHash', sql.VarChar(sql.MAX), passwordHash);
      const userResult = await userRequest.query(`
        INSERT INTO users (email, password_hash, role, is_active)
        OUTPUT INSERTED.id
        VALUES (@email, @passwordHash, 'customer', 1)
      `);

      const userId = userResult.recordset[0].id;
      const customerRequest = transaction.request();
      customerRequest.input('userId', sql.UniqueIdentifier, userId);
      customerRequest.input('name', sql.VarChar(150), name);
      customerRequest.input('phone', sql.VarChar(30), phone || null);
      await customerRequest.query(`
        INSERT INTO customers (user_id, name, phone)
        VALUES (@userId, @name, @phone)
      `);

      await transaction.commit();

      const payload = { userId, email: email.toLowerCase(), role: 'customer' };
      const token = signAccessToken(payload);
      const refreshToken = signRefreshToken({ userId });

      return res.status(201).json({ success: true, data: { token, refreshToken, customer: payload } });
    } catch (error) {
      await transaction.rollback();
      throw error;
    }
  } catch (error) {
    return next(error);
  }
}

export async function refreshTokens (req, res, next) {
  try {
    const { refreshToken } = req.body;
    if (!refreshToken) {
      return res.status(400).json({ success: false, message: 'Refresh token requerido' });
    }

    const payload = verifyRefreshToken(refreshToken);
    const accessToken = signAccessToken({ userId: payload.userId, role: payload.role, email: payload.email });
    const nextRefresh = signRefreshToken({ userId: payload.userId, role: payload.role, email: payload.email });

    return res.json({ success: true, data: { token: accessToken, refreshToken: nextRefresh } });
  } catch (error) {
    return res.status(401).json({ success: false, message: 'Refresh token inválido' });
  }
}
