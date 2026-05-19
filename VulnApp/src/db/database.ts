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

    CREATE TABLE IF NOT EXISTS products (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      name TEXT NOT NULL,
      description TEXT NOT NULL,
      image_url TEXT NOT NULL,
      price REAL NOT NULL,
      owner_id INTEGER NOT NULL DEFAULT 1,
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

  // Catálogo de coches de ejemplo — independiente de users
  const productCount = (database.prepare('SELECT COUNT(*) as n FROM products').get() as { n: number }).n;
  if (productCount === 0) {
    database.prepare(`
      INSERT INTO products (name, description, image_url, price, owner_id) VALUES
        ('Seat Ibiza 2019', 'Gasolina 95 CV · 45.000 km · Manual · Blanco', 'https://images.unsplash.com/photo-1502877338535-766e1452684a?w=400&h=250&fit=crop', 12500, 1),
        ('Volkswagen Golf GTI', 'Gasolina 245 CV · 30.000 km · DSG · Negro', 'https://images.unsplash.com/photo-1533473359331-0135ef1b58bf?w=400&h=250&fit=crop', 32000, 1),
        ('Ford Focus ST', 'Gasolina 280 CV · 18.000 km · Manual · Azul', 'https://images.unsplash.com/photo-1494976388531-d1058494cdd8?w=400&h=250&fit=crop', 29500, 2),
        ('BMW Serie 3 320d', 'Diésel 190 CV · 60.000 km · Automático · Gris', 'https://images.unsplash.com/photo-1555215695-3004980ad54e?w=400&h=250&fit=crop', 28000, 2),
        ('Renault Clio V', 'Gasolina 100 CV · 12.000 km · Manual · Rojo', 'https://images.unsplash.com/photo-1549317661-bd32c8ce0db2?w=400&h=250&fit=crop', 15900, 3),
        ('Mazda MX-5 RF', 'Gasolina 184 CV · 8.000 km · Manual · Gris grafito', 'https://images.unsplash.com/photo-1583121274602-3e2820c69888?w=400&h=250&fit=crop', 34500, 1),
        ('Toyota Yaris GR', 'Gasolina 261 CV · 5.000 km · Manual · Blanco', 'https://images.unsplash.com/photo-1618843479313-40f8afb4b4d8?w=400&h=250&fit=crop', 42000, 3),
        ('Peugeot 208 GT', 'Eléctrico 136 CV · 20.000 km · Auto · Amarillo', 'https://images.unsplash.com/photo-1541899481282-d53bffe3c35d?w=400&h=250&fit=crop', 22000, 2)
    `).run();
  }

  console.log('Base de datos inicializada:', DB_PATH);
}
