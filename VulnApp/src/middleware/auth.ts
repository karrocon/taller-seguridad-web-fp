import { Request, Response, NextFunction } from 'express';
import jwt from 'jsonwebtoken';
import crypto from 'crypto';
import { vulns } from '../config/vulns';

// JWT secret: débil si VULN_JWT_WEAK, fuerte si parcheado
const JWT_SECRET = vulns.JWT_WEAK
  ? 'secret'
  : (process.env.JWT_SECRET || crypto.randomBytes(32).toString('hex'));

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
    // Si JWT_WEAK: no restringe algoritmo → acepta alg:none
    // Si parcheado: solo acepta HS256
    const verifyOptions = vulns.JWT_WEAK ? {} : { algorithms: ['HS256'] as jwt.Algorithm[] };
    const payload = jwt.verify(token, JWT_SECRET, verifyOptions) as {
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
