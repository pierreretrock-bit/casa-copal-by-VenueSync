import nodemailer from 'nodemailer';

const ALLOWED_ADMIN_EMAILS = new Set([
  'pierreretrock@gmail.com',
  'faviolavizcarratirado@gmail.com'
]);

const EMAIL_PATTERN = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

async function getAuthenticatedFirebaseUser(idToken) {
  const apiKey = process.env.FIREBASE_WEB_API_KEY;
  if (!apiKey) {
    throw new Error('FIREBASE_WEB_API_KEY_NOT_CONFIGURED');
  }

  const response = await fetch(
    `https://identitytoolkit.googleapis.com/v1/accounts:lookup?key=${encodeURIComponent(apiKey)}`,
    {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ idToken })
    }
  );

  if (!response.ok) return null;

  const data = await response.json();
  return data.users?.[0] || null;
}

function getPayload(req) {
  if (!req.body) return {};
  if (typeof req.body === 'object') return req.body;
  if (typeof req.body === 'string') {
    try { return JSON.parse(req.body); } catch (e) { return {}; }
  }
  return {};
}

export default async function handler(req, res) {
  res.setHeader('Cache-Control', 'no-store');

  if (req.method !== 'POST') {
    res.setHeader('Allow', 'POST');
    return res.status(405).json({ error: 'Método no permitido.' });
  }

  try {
    const authorization = String(req.headers.authorization || '');
    if (!authorization.startsWith('Bearer ')) {
      return res.status(401).json({ error: 'Sesión no válida.' });
    }

    const idToken = authorization.slice(7).trim();
    if (!idToken) {
      return res.status(401).json({ error: 'Sesión no válida.' });
    }

    const firebaseUser = await getAuthenticatedFirebaseUser(idToken);
    const authenticatedEmail = String(firebaseUser?.email || '').trim().toLowerCase();

    if (!firebaseUser || !ALLOWED_ADMIN_EMAILS.has(authenticatedEmail)) {
      return res.status(403).json({ error: 'No tienes permiso para enviar correos desde Casa Copal.' });
    }

    const payload = getPayload(req);
    const to = String(payload.to || '').trim();
    const subject = String(payload.subject || '').trim();
    const text = String(payload.text || '').trim();

    if (!EMAIL_PATTERN.test(to) || to.length > 254) {
      return res.status(400).json({ error: 'El correo del cliente no es válido.' });
    }
    if (!subject || subject.length > 200) {
      return res.status(400).json({ error: 'El asunto del correo no es válido.' });
    }
    if (!text || text.length > 15000) {
      return res.status(400).json({ error: 'El contenido del correo no es válido.' });
    }

    const smtpHost = String(process.env.SMTP_HOST || 'smtp.hostinger.com').trim();
    const smtpPort = Number(process.env.SMTP_PORT || 465);
    const smtpUser = String(process.env.SMTP_USER || '').trim();
    const smtpPass = String(process.env.SMTP_PASS || '');

    if (!smtpUser || !smtpPass) {
      console.error('Faltan SMTP_USER o SMTP_PASS en Vercel.');
      return res.status(500).json({ error: 'El correo oficial todavía no está configurado en el servidor.' });
    }

    const transporter = nodemailer.createTransport({
      host: smtpHost,
      port: smtpPort,
      secure: smtpPort === 465,
      auth: {
        user: smtpUser,
        pass: smtpPass
      },
      connectionTimeout: 10000,
      greetingTimeout: 10000,
      socketTimeout: 15000,
      tls: {
        minVersion: 'TLSv1.2'
      }
    });

    await transporter.sendMail({
      from: `Casa Copal <${smtpUser}>`,
      to,
      replyTo: smtpUser,
      subject,
      text
    });

    return res.status(200).json({ ok: true });
  } catch (err) {
    console.error('Error SMTP Casa Copal:', err?.message || err);

    if (err?.message === 'FIREBASE_WEB_API_KEY_NOT_CONFIGURED') {
      return res.status(500).json({ error: 'Falta configurar la validación de Firebase en Vercel.' });
    }

    return res.status(500).json({ error: 'No se pudo enviar el correo desde Casa Copal.' });
  }
}
