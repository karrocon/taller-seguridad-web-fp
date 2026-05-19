import express from 'express';
import path from 'path';
import { initDb } from './db/database';
import authRouter from './routes/auth';
import commentsRouter from './routes/comments';
import usersRouter from './routes/users';
import debugRouter from './routes/debug';
import productsRouter from './routes/products';

const app = express();
const PORT = process.env.PORT || 3000;

// ⚠️ VULNERABILIDAD: No se usan cabeceras de seguridad (helmet).
// T13: Añadir helmet para corregir esto.

app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// ⚠️ VULNERABILIDAD: CORS permisivo — acepta cualquier origen.
// T13: Restringir a orígenes conocidos.
app.use((_req, res, next) => {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization');
  next();
});

// Frontend estático
app.use(express.static(path.join(__dirname, 'public')));

// Rutas API
app.use('/auth', authRouter);
app.use('/comments', commentsRouter);
app.use('/users', usersRouter);
app.use('/debug', debugRouter);
app.use('/products', productsRouter);

app.get('/api', (_req, res) => {
  res.json({
    app: 'VulnMotors',
    version: '1.0.0',
    description: 'App vulnerable para el taller de seguridad web',
    endpoints: [
      'POST /auth/login',
      'POST /auth/register',
      'GET  /users/:id',
      'GET  /products',
      'GET  /products/:id',
      'POST /products',
      'PUT  /products/:id',
      'DELETE /products/:id',
      'GET  /comments',
      'POST /comments',
      'GET  /debug',
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
