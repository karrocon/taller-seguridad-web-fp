import Database from 'better-sqlite3';
import path from 'path';

const DB_PATH = path.join(__dirname, '../../vuln.db');

let db: Database.Database;

export function getDb(): Database.Database {
  if (!db) {
    db = new Database(DB_PATH);
  }
  return db;
}

export function initDb(): void {
  const database = getDb();

  database.exec(`
    CREATE TABLE IF NOT EXISTS users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      username TEXT NOT NULL UNIQUE,
      -- ⚠️ VULNERABILIDAD T11: contraseñas en texto plano
      -- FIX: almacenar hash bcrypt/Argon2 en lugar del valor en claro
      password TEXT NOT NULL,
      role TEXT NOT NULL DEFAULT 'user',
      email TEXT
    );

    CREATE TABLE IF NOT EXISTS comments (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id INTEGER NOT NULL,
      -- ⚠️ VULNERABILIDAD T05: contenido no sanitizado → XSS almacenado
      -- FIX: sanitizar con DOMPurify o similar antes de guardar/renderizar
      content TEXT NOT NULL,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    );
  `);

  // Datos de prueba — solo si la tabla está vacía
  const count = (database.prepare('SELECT COUNT(*) as n FROM users').get() as { n: number }).n;
  if (count === 0) {
    // ⚠️ Contraseñas en plain text — vulnerabilidad T11
    database.prepare(`
      INSERT INTO users (username, password, role, email) VALUES
        ('alice', 'password123', 'admin', 'alice@example.com'),
        ('bob',   'qwerty',      'user',  'bob@example.com'),
        ('carol', 'letmein',     'user',  'carol@example.com')
    `).run();

    database.prepare(`
      INSERT INTO comments (user_id, content) VALUES
        (1, 'Bienvenidos al taller de seguridad web.'),
        (2, 'Mi primer comentario.')
    `).run();
  }

  console.log('Base de datos inicializada:', DB_PATH);
}
