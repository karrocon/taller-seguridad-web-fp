import { Router, Request, Response } from 'express';
import { getDb } from '../db/database';

const router = Router();

// GET /comments — devuelve todos los comentarios
router.get('/', (_req: Request, res: Response) => {
  const db = getDb();
  const comments = db.prepare(`
    SELECT c.id, c.content, c.created_at, u.username
    FROM comments c
    JOIN users u ON c.user_id = u.id
    ORDER BY c.created_at DESC
  `).all();

  // ⚠️ VULNERABILIDAD T05: el contenido se devuelve sin sanitizar.
  // Si el cliente renderiza con innerHTML, se ejecutará cualquier <script> almacenado.
  // FIX T05: sanitizar el campo 'content' con DOMPurify (cliente) o sanitize-html (servidor)
  res.json(comments);
});

// POST /comments — guarda un nuevo comentario
router.post('/', (req: Request, res: Response) => {
  // ⚠️ No hay autenticación requerida para publicar comentarios
  const { user_id, content } = req.body as { user_id: number; content: string };

  if (!user_id || !content) {
    res.status(400).json({ error: 'user_id y content requeridos' });
    return;
  }

  const db = getDb();

  // ⚠️ VULNERABILIDAD T05: contenido XSS guardado sin sanitizar
  // FIX T05: const clean = sanitizeHtml(content, { allowedTags: [] });
  //          db.prepare('INSERT INTO comments ...').run(user_id, clean);
  db.prepare('INSERT INTO comments (user_id, content) VALUES (?, ?)').run(user_id, content);

  res.status(201).json({ message: 'Comentario guardado' });
});

export default router;
