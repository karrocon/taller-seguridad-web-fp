import { Router, Request, Response } from 'express';
import { getDb } from '../db/database';
import { AuthRequest, requireAuth } from '../middleware/auth';
import { vulns } from '../config/vulns';

const router = Router();

// GET /users/:id — devuelve el perfil de un usuario (requiere auth)
router.get('/:id', requireAuth as any, (req: AuthRequest, res: Response) => {
  const id = parseInt(req.params.id, 10);

  if (isNaN(id)) {
    res.status(400).json({ error: 'ID inválido' });
    return;
  }

  // Si IDOR parcheado: solo puedes ver tu propio perfil (o admin)
  if (!vulns.IDOR) {
    if (req.user!.userId !== id && req.user!.role !== 'admin') {
      res.status(403).json({ error: 'Acceso denegado: solo puedes ver tu propio perfil' });
      return;
    }
  }

  const db = getDb();
  const user = db
    .prepare('SELECT id, username, email, role FROM users WHERE id = ?')
    .get(id) as { id: number; username: string; email: string; role: string } | undefined;

  if (!user) {
    res.status(404).json({ error: 'Usuario no encontrado' });
    return;
  }

  res.json(user);
});

export default router;
