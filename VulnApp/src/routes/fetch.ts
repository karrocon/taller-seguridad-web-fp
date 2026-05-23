import { Router, Request, Response } from 'express';
import { vulns } from '../config/vulns';

const router = Router();

// Dominios permitidos en modo parcheado
const ALLOWED_DOMAINS = [
  'images.unsplash.com',
  'via.placeholder.com',
  'picsum.photos',
  'i.imgur.com',
];

/**
 * GET /fetch-image?url=https://... — Proxy para descargar imágenes externas.
 *
 * ⚠️ VULNERABLE (VULN_SSRF=1): permite acceder a URLs internas:
 *   - /fetch-image?url=http://169.254.169.254/latest/meta-data/ (AWS metadata)
 *   - /fetch-image?url=http://localhost:3000/debug (endpoints internos)
 *   - /fetch-image?url=file:///etc/passwd (proto file://)
 *
 * ✅ PARCHEADO (VULN_SSRF=0): solo dominios de la allowlist
 */
router.get('/', async (req: Request, res: Response) => {
  const url = req.query.url as string | undefined;

  if (!url) {
    res.status(400).json({
      error: 'Parámetro url requerido',
      ejemplo: '/fetch-image?url=https://via.placeholder.com/300',
      allowed_domains: vulns.SSRF ? '(sin restricción ⚠️)' : ALLOWED_DOMAINS
    });
    return;
  }

  if (vulns.SSRF) {
    // ⚠️ VULNERABLE: fetch sin validación de URL
    // Permite SSRF a servicios internos, metadata de cloud, etc.
    try {
      const response = await fetch(url);
      const contentType = response.headers.get('content-type') || 'application/octet-stream';
      const buffer = Buffer.from(await response.arrayBuffer());

      res.set('Content-Type', contentType);
      res.set('X-Fetched-URL', url); // Muestra qué URL se pidió (info)
      res.send(buffer);
    } catch (e: any) {
      res.status(500).json({
        error: 'Error al obtener la URL',
        detail: e.message,
        url
      });
    }
  } else {
    // ✅ PARCHEADO: validar dominio contra allowlist
    let parsedUrl: URL;
    try {
      parsedUrl = new URL(url);
    } catch {
      res.status(400).json({ error: 'URL inválida' });
      return;
    }

    // Solo permitir http/https
    if (!['http:', 'https:'].includes(parsedUrl.protocol)) {
      res.status(403).json({
        error: 'Protocolo no permitido',
        hint: '🔒 Solo se permiten http y https (VULN_SSRF=0)'
      });
      return;
    }

    // Verificar dominio en allowlist
    if (!ALLOWED_DOMAINS.includes(parsedUrl.hostname)) {
      res.status(403).json({
        error: 'Dominio no permitido',
        allowed: ALLOWED_DOMAINS,
        hint: '🔒 SSRF bloqueado (VULN_SSRF=0)'
      });
      return;
    }

    try {
      const response = await fetch(url);
      const contentType = response.headers.get('content-type') || 'application/octet-stream';
      const buffer = Buffer.from(await response.arrayBuffer());

      res.set('Content-Type', contentType);
      res.send(buffer);
    } catch (e: any) {
      res.status(500).json({ error: 'Error al obtener la imagen' });
    }
  }
});

export default router;
