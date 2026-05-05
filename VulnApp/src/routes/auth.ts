import { Router, Request, Response } from 'express';
import { getDb } from '../db/database';

// ⚠️ VULNERABILIDAD T07: clave JWT hardcodeada y débil
// FIX T07: mover a process.env.JWT_SECRET con valor largo y aleatorio
// FIX T02: mover al archivo .env
const JWT_SECRET = 'secret';

import jwt from 'jsonwebtoken';

const router = Router();

// ⚠️ VULNERABILIDAD T04: SQL Injection en el login
// La query concatena directamente el input del usuario sin sanitizar.
// FIX T04: usar prepared statements — db.prepare('... WHERE username = ?').get(username)
router.post('/login', (req: Request, res: Response) => {
  const { username, password } = req.body as { username: string; password: string };

  if (!username || !password) {
    res.status(400).json({ error: 'username y password requeridos' });
    return;
  }

  const db = getDb();

  // ⚠️ SQL INJECTION — VULNERABLE A PROPÓSITO
  // Payload de ejemplo: username = "' OR 1=1 --"
  const query = `SELECT * FROM users WHERE username='${username}' AND password='${password}'`;

  let user: { id: number; username: string; role: string } | undefined;
  try {
    user = db.prepare(query).get() as typeof user;
  } catch {
    res.status(500).json({ error: 'Error de base de datos' });
    return;
  }

  if (!user) {
    res.status(401).json({ error: 'Credenciales incorrectas' });
    return;
  }

  // ⚠️ VULNERABILIDAD T07: algoritmo HS256 con clave débil
  // ⚠️ No se valida el algoritmo en el middleware — acepta alg:none
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

  // ⚠️ VULNERABILIDAD T11: contraseña almacenada en plain text
  // FIX T11: const hash = await bcrypt.hash(password, 12); ... INSERT hash
  try {
    db.prepare('INSERT INTO users (username, password, email) VALUES (?, ?, ?)').run(
      username,
      password, // ← plain text
      email ?? null
    );
  } catch {
    res.status(409).json({ error: 'El usuario ya existe' });
    return;
  }

  res.status(201).json({ message: 'Usuario registrado' });
});

export default router;
