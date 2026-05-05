import { Request, Response, NextFunction } from 'express';
import jwt from 'jsonwebtoken';

// ⚠️ VULNERABILIDAD T07: clave JWT hardcodeada y débil
// FIX T07: mover a process.env.JWT_SECRET
const JWT_SECRET = 'secret';

export interface AuthRequest extends Request {
  user?: { userId: number; username: string; role: string };
}

export function requireAuth(req: AuthRequest, res: Response, next: NextFunction): void {
  const authHeader = req.headers.authorization;

  if (!authHeader?.startsWith('Bearer ')) {
    res.status(401).json({ error: 'Token de autenticación requerido' });
    return;
  }

  const token = authHeader.slice(7);

  try {
    // ⚠️ VULNERABILIDAD T07: no se especifica algorithms → acepta alg:none
    // FIX T07: jwt.verify(token, JWT_SECRET, { algorithms: ['HS256'] })
    const payload = jwt.verify(token, JWT_SECRET) as {
      userId: number;
      username: string;
      role: string;
    };
    req.user = payload;
    next();
  } catch {
    res.status(401).json({ error: 'Token inválido o expirado' });
  }
}

export function requireAdmin(req: AuthRequest, res: Response, next: NextFunction): void {
  requireAuth(req, res, () => {
    if (req.user?.role !== 'admin') {
      res.status(403).json({ error: 'Acceso restringido a administradores' });
      return;
    }
    next();
  });
}
