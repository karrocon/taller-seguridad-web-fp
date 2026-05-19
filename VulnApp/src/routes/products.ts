import { Router, Request, Response } from 'express';
import { getDb } from '../db/database';
import { AuthRequest, requireAuth } from '../middleware/auth';

const router = Router();

// GET /products — lista todos los coches (público)
router.get('/', (_req: Request, res: Response) => {
  const db = getDb();
  const products = db.prepare(`
    SELECT p.id, p.name, p.description, p.image_url, p.price, p.owner_id, p.created_at, u.username as owner
    FROM products p
    JOIN users u ON p.owner_id = u.id
    ORDER BY p.created_at DESC
  `).all();
  res.json(products);
});

// GET /products/:id — detalle de un coche (público)
router.get('/:id', (req: Request, res: Response) => {
  const id = parseInt(req.params.id, 10);
  if (isNaN(id)) { res.status(400).json({ error: 'ID inválido' }); return; }

  const db = getDb();
  const product = db.prepare(`
    SELECT p.*, u.username as owner
    FROM products p
    JOIN users u ON p.owner_id = u.id
    WHERE p.id = ?
  `).get(id);

  if (!product) { res.status(404).json({ error: 'Producto no encontrado' }); return; }
  res.json(product);
});

// POST /products — crear un coche (requiere auth)
router.post('/', requireAuth as any, (req: AuthRequest, res: Response) => {
  const { name, description, image_url, price } = req.body as {
    name: string; description: string; image_url: string; price: number;
  };

  if (!name || !description || !image_url || price == null) {
    res.status(400).json({ error: 'name, description, image_url y price requeridos' });
    return;
  }

  const db = getDb();
  // ⚠️ VULNERABILIDAD T05: description e image_url no se sanitizan → XSS
  const result = db.prepare(
    'INSERT INTO products (name, description, image_url, price, owner_id) VALUES (?, ?, ?, ?, ?)'
  ).run(name, description, image_url, price, req.user!.userId);

  res.status(201).json({ id: result.lastInsertRowid, message: 'Producto creado' });
});

// PUT /products/:id — editar un coche
// ⚠️ VULNERABILIDAD T08: IDOR — cualquier usuario autenticado puede editar cualquier producto
// FIX: verificar que owner_id === req.user.userId o role === 'admin'
router.put('/:id', requireAuth as any, (req: AuthRequest, res: Response) => {
  const id = parseInt(req.params.id, 10);
  if (isNaN(id)) { res.status(400).json({ error: 'ID inválido' }); return; }

  const { name, description, image_url, price } = req.body as {
    name?: string; description?: string; image_url?: string; price?: number;
  };

  const db = getDb();
  const existing = db.prepare('SELECT * FROM products WHERE id = ?').get(id);
  if (!existing) { res.status(404).json({ error: 'Producto no encontrado' }); return; }

  // ⚠️ No se verifica que el usuario sea el propietario
  db.prepare(`
    UPDATE products SET
      name = COALESCE(?, name),
      description = COALESCE(?, description),
      image_url = COALESCE(?, image_url),
      price = COALESCE(?, price)
    WHERE id = ?
  `).run(name || null, description || null, image_url || null, price || null, id);

  res.json({ message: 'Producto actualizado' });
});

// DELETE /products/:id — solo admin
// ⚠️ VULNERABILIDAD T08: el check de admin se hace solo en frontend, no en backend
router.delete('/:id', requireAuth as any, (req: AuthRequest, res: Response) => {
  const id = parseInt(req.params.id, 10);
  if (isNaN(id)) { res.status(400).json({ error: 'ID inválido' }); return; }

  // ⚠️ VULNERABILIDAD: no se verifica role === 'admin' aquí
  // FIX: if (req.user!.role !== 'admin') return res.status(403).json(...)
  const db = getDb();
  db.prepare('DELETE FROM products WHERE id = ?').run(id);
  res.json({ message: 'Producto eliminado' });
});

export default router;
