import express from 'express';
import path from 'path';
import { initDb } from './db/database';
import { vulns } from './config/vulns';
import authRouter from './routes/auth';
import commentsRouter from './routes/comments';
import usersRouter from './routes/users';
import debugRouter from './routes/debug';
import productsRouter from './routes/products';
import sessionRouter from './routes/session';
import filesRouter from './routes/files';
import fetchRouter from './routes/fetch';

const app = express();
const PORT = process.env.PORT || 3000;

app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// CORS: permisivo si VULN_CSRF, restrictivo si parcheado
app.use((_req, res, next) => {
  if (vulns.CSRF) {
    // ⚠️ VULNERABLE: acepta cualquier origen → permite CSRF desde sitios maliciosos
    res.setHeader('Access-Control-Allow-Origin', '*');
    res.setHeader('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE');
    res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization');
  } else {
    // ✅ PARCHEADO: solo permite el origen propio
    const origin = _req.headers.origin;
    const allowed = process.env.ALLOWED_ORIGIN || `http://localhost:${PORT}`;
    if (origin === allowed) {
      res.setHeader('Access-Control-Allow-Origin', origin);
    }
    res.setHeader('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE');
    res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization');
    res.setHeader('Access-Control-Allow-Credentials', 'true');
  }
  if (_req.method === 'OPTIONS') { res.sendStatus(204); return; }
  next();
});

// Security headers: si VULN_HEADERS está parcheado, añadir cabeceras de seguridad
if (!vulns.HEADERS) {
  app.use((_req, res, next) => {
    // CSP: solo scripts/estilos del mismo origen + inline (necesario para la SPA)
    res.setHeader('Content-Security-Policy',
      "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' https:; font-src 'self'");
    res.setHeader('Strict-Transport-Security', 'max-age=31536000; includeSubDomains');
    res.setHeader('X-Frame-Options', 'DENY');
    res.setHeader('X-Content-Type-Options', 'nosniff');
    res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');
    res.setHeader('Permissions-Policy', 'camera=(), microphone=(), geolocation=()');
    next();
  });
}

// Frontend estático
app.use(express.static(path.join(__dirname, 'public')));

// Rutas API
app.use('/auth', authRouter);
app.use('/session', sessionRouter);
app.use('/comments', commentsRouter);
app.use('/users', usersRouter);
app.use('/debug', debugRouter);
app.use('/products', productsRouter);
app.use('/files', filesRouter);
app.use('/fetch-image', fetchRouter);

app.get('/api', (_req, res) => {
  res.json({
    app: 'VulnMotors',
    version: '1.0.0',
    description: 'App vulnerable para el taller de seguridad web',
    endpoints: [
      'POST /auth/login',
      'POST /auth/register',
      'POST /session/login      — login con cookie (demo HttpOnly/Secure/SameSite)',
      'GET  /session/me          — perfil por cookie',
      'POST /session/transfer    — acción sensible con cookie (demo CSRF)',
      'POST /session/logout',
      'GET  /users/:id',
      'GET  /products',
      'GET  /products/:id',
      'POST /products',
      'PUT  /products/:id',
      'DELETE /products/:id',
      'GET  /comments',
      'POST /comments',
      'GET  /debug',
      'GET  /files               — lista archivos (demo Path Traversal)',
      'GET  /files?path=x        — descarga archivo',
      'GET  /fetch-image?url=x   — proxy de imagen (demo SSRF)',
    ],
  });
});

// Inicializar BD y arrancar servidor
initDb();

app.listen(PORT, () => {
  console.log(`VulnApp corriendo en http://localhost:${PORT}`);
  console.log('⚠️  Esta app tiene vulnerabilidades INTENCIONADAS. Solo para laboratorio.');
});

export default app;
