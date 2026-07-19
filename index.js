// ConexaShip Backend – 100% Supabase Cloud
const express = require('express');
const { createClient } = require('@supabase/supabase-js');
const Mailgun = require('mailgun.js');
const formData = require('form-data');
require('dotenv').config();

const app = express();
app.use(express.json());

// ─── CORS ────────────────────────────────────────────────────────────────────
app.use((req, res, next) => {
  res.header('Access-Control-Allow-Origin', '*');
  res.header('Access-Control-Allow-Methods', 'GET,POST,PUT,PATCH,DELETE,OPTIONS');
  res.header('Access-Control-Allow-Headers', 'Content-Type, Authorization');
  if (req.method === 'OPTIONS') return res.sendStatus(200);
  next();
});

// ─── Supabase client (REST only, no realtime) ───────────────────────────────
const supabase = createClient(
  process.env.SUPABASE_URL,
  process.env.SUPABASE_SERVICE_KEY || process.env.SUPABASE_KEY,
  {
    realtime: { transport: 'websocket', params: {} },
    global: { fetch: fetch },
    auth: { persistSession: false }
  }
);

// ─── Mailgun client ──────────────────────────────────────────────────────────
const mailgun = new Mailgun(formData);
const mg = process.env.CONEXASHIP_MAILGUN_API_KEY
  ? mailgun.client({ username: 'api', key: process.env.CONEXASHIP_MAILGUN_API_KEY })
  : null;

// ─── OTP Storage (in-memory, auto-cleanup after 10 min) ─────────────────────
const otpStore = new Map(); // { email: { code, expiresAt, attempts } }

// Limpiar códigos expirados cada 5 minutos
setInterval(() => {
  const now = Date.now();
  for (const [email, data] of otpStore.entries()) {
    if (data.expiresAt < now) otpStore.delete(email);
  }
}, 5 * 60 * 1000);

// Generar código de 6 dígitos
function generateOTP() {
  return Math.floor(100000 + Math.random() * 900000).toString();
}

// Enviar email con Mailgun
async function sendEmail(to, subject, html) {
  if (!mg) {
    console.warn('⚠️  Mailgun no configurado para ConexaShip — código OTP:', html.match(/\d{6}/)?.[0]);
    return; // En dev sin Mailgun, solo log
  }
  try {
    await mg.messages.create(process.env.CONEXASHIP_MAILGUN_DOMAIN, {
      from: process.env.CONEXASHIP_MAILGUN_FROM || 'ConexaShip <noreply@conexaship.com>',
      to: [to],
      subject,
      html,
    });
  } catch (error) {
    console.error('Error enviando email:', error.message);
    throw new Error('No se pudo enviar el email');
  }
}

// ─── Auth middleware ──────────────────────────────────────────────────────────
async function requireAuth(req, res, next) {
  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return res.status(401).json({ success: false, message: 'Token requerido' });
  }
  const token = authHeader.split(' ')[1];
  const { data: { user }, error } = await supabase.auth.getUser(token);
  if (error || !user) return res.status(401).json({ success: false, message: 'Token inválido' });
  req.user = user;
  next();
}

// ─── Health check ─────────────────────────────────────────────────────────────
app.get('/health', (req, res) => {
  res.json({ status: 'ok', db: 'supabase', version: '2.0.0', service: 'conexaship' });
});

app.get('/', (req, res) => {
  res.json({ name: 'ConexaShip API', version: '2.0.0', status: 'running' });
});

// ─── AUTH ─────────────────────────────────────────────────────────────────────

// Login
app.post('/api/v1/auth/login', async (req, res) => {
  const { email, password } = req.body;
  if (!email || !password)
    return res.status(400).json({ success: false, message: 'Email y contraseña requeridos' });

  const { data, error } = await supabase.auth.signInWithPassword({ email, password });
  if (error) return res.status(401).json({ success: false, message: error.message });

  // Get profile from profiles table
  const { data: profile } = await supabase
    .from('profiles')
    .select('*')
    .eq('id', data.user.id)
    .single();

  // Merge profile data into user object for frontend
  const userWithProfile = {
    ...data.user,
    ...(profile || {}),
    // Sobrescribir con datos del perfil si existen
    full_name: profile?.full_name || data.user.user_metadata?.full_name,
    phone: profile?.phone || data.user.user_metadata?.phone,
    role: profile?.role || 'client',
    allowed_apps: profile?.allowed_apps || [],
    email_confirmed: profile?.email_confirmed || false
  };

  res.json({
    success: true,
    token: data.session.access_token,
    refresh_token: data.session.refresh_token,
    user: userWithProfile
  });
});

// Register
app.post('/api/v1/auth/register', async (req, res) => {
  const { email, password, full_name, phone } = req.body;
  if (!email || !password)
    return res.status(400).json({ success: false, message: 'Email y contraseña requeridos' });

  const { data, error } = await supabase.auth.signUp({
    email,
    password,
    options: { data: { full_name, phone }, emailRedirectTo: undefined }
  });
  if (error) return res.status(400).json({ success: false, message: error.message });

  // ✅ Crear perfil automáticamente con rol "client" y acceso a ConexaShip
  if (data.user) {
    try {
      await supabase.from('profiles').insert({
        id: data.user.id,
        email: data.user.email,
        full_name: full_name || null,
        phone: phone || null,
        role: 'client',
        allowed_apps: ['conexaship'],
        email_confirmed: false,
        created_at: new Date().toISOString()
      });
    } catch (profileError) {
      console.warn('⚠️ Error creando perfil automático:', profileError);
      // No bloqueamos el registro si falla crear el perfil
    }
  }

  // Generar y enviar código OTP
  const code = generateOTP();
  otpStore.set(email, {
    code,
    expiresAt: Date.now() + 10 * 60 * 1000, // 10 minutos
    attempts: 0,
    userId: data.user?.id
  });

  const emailHTML = `
    <div style="font-family: system-ui, sans-serif; max-width: 600px; margin: 0 auto; padding: 40px 20px;">
      <div style="text-align: center; margin-bottom: 32px;">
        <h1 style="color: #0B3D6E; margin: 0;">ConexaShip</h1>
        <p style="color: #6B7280; margin-top: 8px;">Verificación de cuenta</p>
      </div>
      <div style="background: #F8FAFC; border-radius: 16px; padding: 32px; text-align: center;">
        <h2 style="color: #111827; margin: 0 0 16px;">Tu código de verificación</h2>
        <p style="color: #6B7280; margin-bottom: 24px;">Ingresa este código para activar tu cuenta:</p>
        <div style="background: white; border: 2px solid #00C9A7; border-radius: 12px; padding: 20px; font-size: 32px; font-weight: bold; letter-spacing: 8px; color: #0B3D6E;">
          ${code}
        </div>
        <p style="color: #9CA3AF; font-size: 13px; margin-top: 24px;">
          Este código expira en <strong>10 minutos</strong>
        </p>
      </div>
      <p style="color: #6B7280; font-size: 13px; text-align: center; margin-top: 32px;">
        Si no solicitaste esta cuenta, ignora este email.
      </p>
    </div>
  `;

  try {
    await sendEmail(email, '🔐 Código de verificación ConexaShip', emailHTML);
  } catch (emailError) {
    console.error('Error enviando email OTP:', emailError);
    // No bloqueamos el registro si falla el email
  }

  res.status(201).json({
    success: true,
    message: 'Cuenta creada. Revisa tu email para el código de verificación.',
    user: data.user,
    verification_required: true
  });
});

// Send verification code (resend)
app.post('/api/v1/auth/send-verification-code', async (req, res) => {
  const { email } = req.body;
  if (!email) return res.status(400).json({ success: false, message: 'Email requerido' });

  // Verificar si ya existe un código reciente (throttle)
  const existing = otpStore.get(email);
  if (existing && existing.expiresAt > Date.now() + 9 * 60 * 1000) {
    return res.status(429).json({
      success: false,
      message: 'Espera 1 minuto antes de solicitar un nuevo código'
    });
  }

  const code = generateOTP();
  otpStore.set(email, {
    code,
    expiresAt: Date.now() + 10 * 60 * 1000,
    attempts: 0
  });

  const emailHTML = `
    <div style="font-family: system-ui, sans-serif; max-width: 600px; margin: 0 auto; padding: 40px 20px;">
      <div style="text-align: center; margin-bottom: 32px;">
        <h1 style="color: #0B3D6E; margin: 0;">ConexaShip</h1>
        <p style="color: #6B7280; margin-top: 8px;">Nuevo código de verificación</p>
      </div>
      <div style="background: #F8FAFC; border-radius: 16px; padding: 32px; text-align: center;">
        <h2 style="color: #111827; margin: 0 0 16px;">Tu código de verificación</h2>
        <div style="background: white; border: 2px solid #00C9A7; border-radius: 12px; padding: 20px; font-size: 32px; font-weight: bold; letter-spacing: 8px; color: #0B3D6E;">
          ${code}
        </div>
        <p style="color: #9CA3AF; font-size: 13px; margin-top: 24px;">
          Este código expira en <strong>10 minutos</strong>
        </p>
      </div>
    </div>
  `;

  try {
    await sendEmail(email, '🔐 Nuevo código de verificación ConexaShip', emailHTML);
    res.json({ success: true, message: 'Código enviado a tu correo' });
  } catch (error) {
    res.status(500).json({ success: false, message: 'Error al enviar el código' });
  }
});

// Verify code
app.post('/api/v1/auth/verify-code', async (req, res) => {
  const { email, code } = req.body;
  if (!email || !code)
    return res.status(400).json({ success: false, message: 'Email y código requeridos' });

  const stored = otpStore.get(email);
  if (!stored) {
    return res.status(404).json({
      success: false,
      message: 'No hay código pendiente para este email'
    });
  }

  if (stored.expiresAt < Date.now()) {
    otpStore.delete(email);
    return res.status(410).json({ success: false, message: 'Código expirado' });
  }

  if (stored.attempts >= 5) {
    otpStore.delete(email);
    return res.status(429).json({
      success: false,
      message: 'Demasiados intentos fallidos. Solicita un nuevo código'
    });
  }

  if (stored.code !== code) {
    stored.attempts++;
    return res.status(400).json({
      success: false,
      message: 'Código incorrecto',
      attempts_left: 5 - stored.attempts
    });
  }

  // Código correcto — eliminar del store
  otpStore.delete(email);

  // Marcar el email como verificado en Supabase (si existe el usuario)
  if (stored.userId) {
    try {
      await supabase.auth.admin.updateUserById(stored.userId, {
        email_confirm: true
      });
      // También actualizar la tabla profiles
      await supabase
        .from('profiles')
        .update({ email_confirmed: true })
        .eq('id', stored.userId);
    } catch (err) {
      console.warn('No se pudo confirmar email en Supabase:', err.message);
    }
  }

  res.json({ success: true, message: 'Email verificado correctamente' });
});

// Refresh token
app.post('/api/v1/auth/refresh', async (req, res) => {
  const { refresh_token } = req.body;
  if (!refresh_token)
    return res.status(400).json({ success: false, message: 'refresh_token requerido' });

  const { data, error } = await supabase.auth.refreshSession({ refresh_token });
  if (error) return res.status(401).json({ success: false, message: error.message });

  res.json({ success: true, token: data.session.access_token, refresh_token: data.session.refresh_token });
});

// Logout
app.post('/api/v1/auth/logout', requireAuth, async (req, res) => {
  await supabase.auth.signOut();
  res.json({ success: true, message: 'Sesión cerrada' });
});

// Me (current user)
app.get('/api/v1/auth/me', requireAuth, async (req, res) => {
  const { data: profile } = await supabase
    .from('profiles')
    .select('*')
    .eq('id', req.user.id)
    .single();

  res.json({ success: true, user: { ...req.user, profile: profile || {} } });
});

// ─── USERS ────────────────────────────────────────────────────────────────────

app.get('/api/v1/users', requireAuth, async (req, res) => {
  const { data, error } = await supabase.from('profiles').select('*');
  if (error) return res.status(500).json({ success: false, message: error.message });
  res.json({ success: true, data });
});

app.get('/api/v1/users/:id', requireAuth, async (req, res) => {
  const { data, error } = await supabase.from('profiles').select('*').eq('id', req.params.id).single();
  if (error) return res.status(404).json({ success: false, message: 'Usuario no encontrado' });
  res.json({ success: true, data });
});

app.patch('/api/v1/users/:id', requireAuth, async (req, res) => {
  const { data, error } = await supabase.from('profiles').update(req.body).eq('id', req.params.id).select().single();
  if (error) return res.status(400).json({ success: false, message: error.message });
  res.json({ success: true, data });
});

// ─── SHIPMENTS / ORDERS ───────────────────────────────────────────────────────

app.get('/api/v1/shipments', requireAuth, async (req, res) => {
  const { data, error } = await supabase
    .from('shipments')
    .select('*')
    .eq('user_id', req.user.id)
    .order('created_at', { ascending: false });
  if (error) return res.status(500).json({ success: false, message: error.message });
  res.json({ success: true, data });
});

app.post('/api/v1/shipments', requireAuth, async (req, res) => {
  const { data, error } = await supabase
    .from('shipments')
    .insert({ ...req.body, user_id: req.user.id })
    .select()
    .single();
  if (error) return res.status(400).json({ success: false, message: error.message });
  res.status(201).json({ success: true, data });
});

app.get('/api/v1/shipments/:id', requireAuth, async (req, res) => {
  const { data, error } = await supabase.from('shipments').select('*').eq('id', req.params.id).single();
  if (error) return res.status(404).json({ success: false, message: 'Envío no encontrado' });
  res.json({ success: true, data });
});

app.patch('/api/v1/shipments/:id', requireAuth, async (req, res) => {
  const { data, error } = await supabase.from('shipments').update(req.body).eq('id', req.params.id).select().single();
  if (error) return res.status(400).json({ success: false, message: error.message });
  res.json({ success: true, data });
});

// ─── TRIPS ────────────────────────────────────────────────────────────────────

app.get('/api/v1/trips', requireAuth, async (req, res) => {
  const { data, error } = await supabase.from('trips').select('*').order('created_at', { ascending: false });
  if (error) return res.status(500).json({ success: false, message: error.message });
  res.json({ success: true, data });
});

// ─── PAYMENTS ─────────────────────────────────────────────────────────────────

app.get('/api/v1/payments', requireAuth, async (req, res) => {
  const { data, error } = await supabase
    .from('payments')
    .select('*')
    .eq('user_id', req.user.id)
    .order('created_at', { ascending: false });
  if (error) return res.status(500).json({ success: false, message: error.message });
  res.json({ success: true, data });
});

app.post('/api/v1/payments', requireAuth, async (req, res) => {
  const { data, error } = await supabase
    .from('payments')
    .insert({ ...req.body, user_id: req.user.id })
    .select()
    .single();
  if (error) return res.status(400).json({ success: false, message: error.message });
  res.status(201).json({ success: true, data });
});

// ─── TRACKING (público) ───────────────────────────────────────────────────────

app.get('/api/v1/tracking/:code', async (req, res) => {
  const { data, error } = await supabase
    .from('shipments')
    .select('id, tracking_code, status, created_at, updated_at, description')
    .eq('tracking_code', req.params.code)
    .single();
  if (error || !data) return res.status(404).json({ success: false, message: 'Código de rastreo no encontrado' });
  res.json({ success: true, data });
});

// ─── Catch-all 404 ────────────────────────────────────────────────────────────
app.use((req, res) => {
  res.status(404).json({ success: false, message: `Ruta ${req.method} ${req.path} no existe` });
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`✅ ConexaShip API corriendo en puerto ${PORT}`);
  console.log(`🗄️  Base de datos: Supabase Cloud`);
  console.log(`🌐 URL: ${process.env.SUPABASE_URL}`);
});
