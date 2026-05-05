# VulnApp — Aplicación Vulnerable para el Taller de Seguridad Web

> ⚠️ **Esta app contiene vulnerabilidades INTENCIONADAS.** No usar en producción ni exponerla a internet.

## Descripción

VulnApp es una API REST Node.js + TypeScript + SQLite con vulnerabilidades reales del **OWASP Top 10** incluidas de forma deliberada. Se usa como app de referencia a lo largo del curso para atacar y reparar cada vulnerabilidad.

## Stack

| Capa | Tecnología |
|------|-----------|
| Lenguaje | TypeScript |
| Framework | Express 4 |
| Base de datos | SQLite (better-sqlite3) |
| Autenticación | JWT (jsonwebtoken) |
| Runtime | Node.js 20+ |

## Instalación y arranque

```bash
npm install
npm start
# → http://localhost:3000
```

## Endpoints

| Método | Ruta | Descripción |
|--------|------|-------------|
| `POST` | `/auth/login` | Login — vulnerable a SQL Injection (T04) |
| `POST` | `/auth/register` | Registro — contraseña en plain text (T11) |
| `GET` | `/users/:id` | Perfil de usuario — vulnerable a IDOR (T08) |
| `GET` | `/comments` | Lista comentarios — XSS almacenado (T05) |
| `POST` | `/comments` | Crear comentario — XSS almacenado (T05) |
| `GET` | `/debug` | Panel de debug — expone env + Command Injection (T06) |

## Usuarios de prueba

| Usuario | Contraseña | Rol |
|---------|-----------|-----|
| `alice` | `password123` | admin |
| `bob` | `qwerty` | user |
| `carol` | `letmein` | user |

## Mapa de vulnerabilidades

| Archivo | Vulnerabilidad | Topic | OWASP |
|---------|---------------|-------|-------|
| `src/routes/auth.ts` | SQL Injection en login | T04 | A03 |
| `src/routes/auth.ts` | Contraseña en plain text | T11 | A02 |
| `src/routes/auth.ts` | JWT con clave débil | T07 | A07 |
| `src/routes/comments.ts` | XSS almacenado | T05 | A03 |
| `src/routes/users.ts` | IDOR en perfil | T08 | A01 |
| `src/routes/debug.ts` | Endpoint expuesto sin auth | T03 | A05 |
| `src/routes/debug.ts` | Command Injection | T06 | A03 |
| `src/routes/debug.ts` | Exposición de process.env | T12 | A02 |
| `src/middleware/auth.ts` | JWT acepta alg:none | T07 | A07 |
| `src/app.ts` | Sin cabeceras de seguridad | T13 | A05 |
| `src/app.ts` | CORS permisivo | T13 | A05 |

## Estructura del código

```
src/
├── app.ts              # Entry point, middlewares globales
├── db/
│   └── database.ts     # Inicialización SQLite, datos de prueba
├── middleware/
│   └── auth.ts         # Verificación JWT (vulnerable a alg:none)
└── routes/
    ├── auth.ts         # Login/registro (SQLi + plain text passwords)
    ├── comments.ts     # CRUD comentarios (XSS almacenado)
    ├── debug.ts        # Panel debug (Command Injection + env exposure)
    └── users.ts        # Perfil usuario (IDOR)
```

## Ejemplo de uso con curl

```bash
# Login (explotando SQLi)
curl -X POST http://localhost:3000/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username": "'\'' OR 1=1 --", "password": "x"}'

# Login legítimo
curl -X POST http://localhost:3000/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username": "alice", "password": "password123"}'

# Perfil propio (IDOR — intenta con /users/2 siendo user 1)
curl http://localhost:3000/users/1 \
  -H "Authorization: Bearer <TOKEN>"

# Debug endpoint (sin autenticación)
curl "http://localhost:3000/debug?cmd=date"
```
