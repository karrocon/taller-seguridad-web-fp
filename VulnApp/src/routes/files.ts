import { Router, Request, Response } from 'express';
import path from 'path';
import fs from 'fs';
import { vulns } from '../config/vulns';

const router = Router();

// Directorio "público" con archivos descargables
const PUBLIC_DIR = path.join(__dirname, '..', 'public', 'downloads');

// Crear el directorio y unos ficheros de ejemplo si no existen
function ensureDemoFiles() {
  if (!fs.existsSync(PUBLIC_DIR)) {
    fs.mkdirSync(PUBLIC_DIR, { recursive: true });
  }
  const files: Record<string, string> = {
    'catalogo.txt': 'Catálogo de coches 2024\n\n1. Seat León - 18.000€\n2. VW Golf - 22.000€\n3. Ford Focus - 19.500€',
    'precios.csv': 'marca,modelo,precio\nSeat,León,18000\nVW,Golf,22000\nFord,Focus,19500',
    'notas.txt': 'Notas del vendedor:\n- Revisión ITV pasada\n- Neumáticos nuevos\n- Sin accidentes',
  };
  for (const [name, content] of Object.entries(files)) {
    const filepath = path.join(PUBLIC_DIR, name);
    if (!fs.existsSync(filepath)) {
      fs.writeFileSync(filepath, content);
    }
  }
}

ensureDemoFiles();

/**
 * GET /files?path=catalogo.txt — Descarga un archivo.
 * GET /files (sin path) — Lista los archivos disponibles.
 *
 * ⚠️ VULNERABLE (VULN_PATHTRAVERSAL=1): permite ../../../etc/passwd
 * ✅ PARCHEADO (VULN_PATHTRAVERSAL=0): valida que la ruta quede dentro de PUBLIC_DIR
 */
router.get('/', (req: Request, res: Response) => {
  const userPath = req.query.path as string | undefined;

  if (!userPath) {
    // Sin parámetro: listar archivos
    try {
      const files = fs.readdirSync(PUBLIC_DIR);
      res.json({ files, hint: 'Usa GET /files?path=catalogo.txt para descargar' });
    } catch {
      res.json({ files: [], hint: 'Usa GET /files?path=catalogo.txt para descargar' });
    }
    return;
  }

  if (vulns.PATHTRAVERSAL) {
    // ⚠️ VULNERABLE: concatenación directa, permite path traversal
    // Ejemplo: /files?path=../../../etc/passwd
    const fullPath = path.join(PUBLIC_DIR, userPath);

    try {
      if (!fs.existsSync(fullPath)) {
        res.status(404).json({ error: 'Archivo no encontrado', path: userPath });
        return;
      }
      const stat = fs.statSync(fullPath);
      if (stat.isDirectory()) {
        const entries = fs.readdirSync(fullPath);
        res.json({ directory: userPath, entries });
        return;
      }
      const content = fs.readFileSync(fullPath, 'utf-8');
      res.type('text/plain').send(content);
    } catch (e: any) {
      res.status(500).json({ error: e.message });
    }
  } else {
    // ✅ PARCHEADO: resolver ruta y verificar que esté dentro de PUBLIC_DIR
    const resolved = path.resolve(PUBLIC_DIR, userPath);

    if (!resolved.startsWith(PUBLIC_DIR)) {
      res.status(403).json({
        error: 'Acceso denegado: ruta fuera del directorio permitido',
        hint: '🔒 Path traversal bloqueado (VULN_PATHTRAVERSAL=0)'
      });
      return;
    }

    try {
      if (!fs.existsSync(resolved)) {
        res.status(404).json({ error: 'Archivo no encontrado' });
        return;
      }
      const stat = fs.statSync(resolved);
      if (stat.isDirectory()) {
        const entries = fs.readdirSync(resolved);
        res.json({ directory: userPath, entries });
        return;
      }
      const content = fs.readFileSync(resolved, 'utf-8');
      res.type('text/plain').send(content);
    } catch (e: any) {
      res.status(500).json({ error: 'Error leyendo archivo' });
    }
  }
});

export default router;
