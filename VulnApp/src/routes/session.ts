import { Router, Request, Response } from 'express';
import { getDb } from '../db/database';
import { vulns } from '../config/vulns';
import jwt from 'jsonwebtoken';
import crypto from 'crypto';

const router = Router();

const JWT_SECRET = vulns.JWT_WEAK
  ? 'secret'
  : (process.env.JWT_SECRET || crypto.randomBytes(32).toString('hex'));

/**
 * POST /session/login — Login que establece una cookie de sesión.
 * Permite demostrar:
 *   - Cookies sin HttpOnly → robo por XSS (Day 4, T09)
 *   - Cookies sin SameSite → CSRF posible (Day 4, T09)
 *   - Inspección de flags en DevTools → Application → Cookies
 */
router.post('/login', (req: Request, res: Response) => {
  const { username, password } = req.body as { username: string; password: string };

  if (!username || !password) {
    res.status(400).json({ error: 'username y password requeridos' });
    return;
  }

  const db = getDb();
  const user = db.prepare('SELECT * FROM users WHERE username = ? AND password = ?')
    .get(username, password) as { id: number; username: string; role: string } | undefined;

  if (!user) {
    res.status(401).json({ error: 'Credenciales incorrectas' });
    return;
  }

  const token = jwt.sign(
    { userId: user.id, username: user.username, role: user.role },
    JWT_SECRET,
    { expiresIn: '24h' }
  );

  if (vulns.COOKIES) {
    // ⚠️ VULNERABLE: sin HttpOnly, sin Secure, sin SameSite
    // → JS puede leer: document.cookie
    // → Se envía en peticiones cross-origin (CSRF posible)
    res.setHeader('Set-Cookie', `session=${token}; Path=/`);
  } else {
    // ✅ PARCHEADO: todas las flags de seguridad
    res.setHeader('Set-Cookie',
      `session=${token}; Path=/; HttpOnly; Secure; SameSite=Strict`);
  }

  res.json({ message: 'Sesión iniciada', user: { id: user.id, username: user.username, role: user.role } });
});

/**
 * GET /session/me — Devuelve los datos del usuario basado en la cookie.
 * Sin cookie → 401. Permite demostrar:
 *   - Cookie theft via XSS (document.cookie)
 *   - CSRF cuando SameSite=None
 */
router.get('/me', (req: Request, res: Response) => {
  const cookies = req.headers.cookie;
  if (!cookies) {
    res.status(401).json({ error: 'No hay cookie de sesión' });
    return;
  }

  const sessionCookie = cookies.split(';')
    .map(c => c.trim())
    .find(c => c.startsWith('session='));

  if (!sessionCookie) {
    res.status(401).json({ error: 'Cookie session no encontrada' });
    return;
  }

  const token = sessionCookie.split('=')[1];

  try {
    const payload = jwt.verify(token, JWT_SECRET) as {
      userId: number; username: string; role: string;
    };
    res.json({ user: payload });
  } catch {
    res.status(401).json({ error: 'Cookie de sesión inválida' });
  }
});

/**
 * POST /session/transfer — Endpoint sensible autenticado por cookie.
 * Permite demostrar CSRF: un form malicioso puede hacer POST aquí
 * y el navegador adjunta la cookie automáticamente.
 */
router.post('/transfer', (req: Request, res: Response) => {
  const cookies = req.headers.cookie;
  if (!cookies || !cookies.includes('session=')) {
    res.status(401).json({ error: 'Requiere cookie de sesión' });
    return;
  }

  const sessionCookie = cookies.split(';')
    .map(c => c.trim())
    .find(c => c.startsWith('session='));

  if (!sessionCookie) {
    res.status(401).json({ error: 'Cookie session no encontrada' });
    return;
  }

  const token = sessionCookie.split('=')[1];

  try {
    const payload = jwt.verify(token, JWT_SECRET) as {
      userId: number; username: string; role: string;
    };

    const { to, amount } = req.body as { to: string; amount: number };
    // Acción sensible: "transferir" (simulada)
    res.json({
      message: `Transferencia de ${amount}€ a ${to} realizada`,
      from: payload.username,
      to,
      amount
    });
  } catch {
    res.status(401).json({ error: 'Cookie de sesión inválida' });
  }
});

/**
 * POST /session/logout — Elimina la cookie de sesión.
 */
router.post('/logout', (_req: Request, res: Response) => {
  res.setHeader('Set-Cookie', 'session=; Path=/; Max-Age=0');
  res.json({ message: 'Sesión cerrada' });
});

export default router;
