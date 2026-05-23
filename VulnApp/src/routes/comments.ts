import { Router, Request, Response } from 'express';
import { getDb } from '../db/database';
import { vulns } from '../config/vulns';

const router = Router();

// Sanitización básica para cuando XSS está parcheado
function sanitize(input: string): string {
  return input
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#x27;');
}

// GET /comments — devuelve todos los comentarios
router.get('/', (_req: Request, res: Response) => {
  const db = getDb();
  const comments = db.prepare(`
    SELECT c.id, c.content, c.created_at, u.username
    FROM comments c
    JOIN users u ON c.user_id = u.id
    ORDER BY c.created_at DESC
  `).all();

  res.json(comments);
});

// POST /comments — guarda un nuevo comentario
router.post('/', (req: Request, res: Response) => {
  const { user_id, content } = req.body as { user_id: number; content: string };

  if (!user_id || !content) {
    res.status(400).json({ error: 'user_id y content requeridos' });
    return;
  }

  const db = getDb();

  // Si XSS vulnerable: guarda sin sanitizar → <script> se ejecutará en el cliente
  // Si parcheado: escapa HTML antes de guardar
  const safeContent = vulns.XSS ? content : sanitize(content);

  db.prepare('INSERT INTO comments (user_id, content) VALUES (?, ?)').run(user_id, safeContent);

  res.status(201).json({ message: 'Comentario guardado' });
});

export default router;
