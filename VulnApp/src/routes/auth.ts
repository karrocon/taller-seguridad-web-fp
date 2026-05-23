import { Router, Request, Response } from 'express';
import { getDb } from '../db/database';
import { vulns } from '../config/vulns';
import jwt from 'jsonwebtoken';
import crypto from 'crypto';

const router = Router();

// JWT secret: débil si VULN_JWT_WEAK, fuerte si parcheado
const JWT_SECRET = vulns.JWT_WEAK
  ? 'secret'
  : (process.env.JWT_SECRET || crypto.randomBytes(32).toString('hex'));

router.post('/login', (req: Request, res: Response) => {
  const { username, password } = req.body as { username: string; password: string };

  if (!username || !password) {
    res.status(400).json({ error: 'username y password requeridos' });
    return;
  }

  const db = getDb();

  let user: { id: number; username: string; role: string } | undefined;

  if (vulns.SQLI) {
    // ⚠️ VULNERABLE: SQL Injection — concatenación directa
    // Payload: username = "' OR 1=1 --"
    const query = `SELECT * FROM users WHERE username='${username}' AND password='${password}'`;
    try {
      user = db.prepare(query).get() as typeof user;
    } catch {
      res.status(500).json({ error: 'Error de base de datos' });
      return;
    }
  } else {
    // ✅ PARCHEADO: prepared statement
    user = db.prepare('SELECT * FROM users WHERE username = ? AND password = ?')
      .get(username, password) as typeof user;
  }

  if (!user) {
    res.status(401).json({ error: 'Credenciales incorrectas' });
    return;
  }

  // JWT: sin restricción de algoritmo si VULN_JWT_WEAK
  const token = jwt.sign(
    { userId: user.id, username: user.username, role: user.role },
    JWT_SECRET,
    { expiresIn: '24h' }
  );

  res.json({ token, user: { id: user.id, username: user.username, role: user.role } });
});

router.post('/register', (req: Request, res: Response) => {
  const { username, password, email } = req.body as {
    username: string;
    password: string;
    email?: string;
  };

  if (!username || !password) {
    res.status(400).json({ error: 'username y password requeridos' });
    return;
  }

  const db = getDb();

  // Contraseña: plain text si VULN_PLAINTEXT, hash si parcheado
  let storedPassword = password;
  if (!vulns.PLAINTEXT) {
    // ✅ PARCHEADO: hash simple (en producción real usar bcrypt)
    storedPassword = crypto.createHash('sha256').update(password).digest('hex');
  }

  try {
    db.prepare('INSERT INTO users (username, password, email) VALUES (?, ?, ?)').run(
      username,
      storedPassword,
      email ?? null
    );
  } catch {
    res.status(409).json({ error: 'El usuario ya existe' });
    return;
  }

  res.status(201).json({ message: 'Usuario registrado' });
});

export default router;
