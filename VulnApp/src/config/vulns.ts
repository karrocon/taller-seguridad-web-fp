/**
 * Configuración de vulnerabilidades del taller.
 *
 * Por defecto todas están HABILITADAS (=vulnerable).
 * Para DESACTIVAR (=parcheado), pon la variable a "0" o "false".
 *
 * Ejemplo en App Service:
 *   VULN_SQLI=0        → login usa prepared statements (seguro)
 *   VULN_XSS=0         → comments se sanitizan (seguro)
 *   VULN_CMDI=0        → debug endpoint: solo allowlist (seguro)
 *   VULN_IDOR=0        → se verifica ownership (seguro)
 *   VULN_JWT_WEAK=0    → JWT usa secreto fuerte + algorithms (seguro)
 *   VULN_CSRF=0        → CORS restrictivo (seguro)
 *   VULN_PLAINTEXT=0   → passwords se hashean (seguro)
 *   VULN_SECRETS=0     → /debug no expone process.env (seguro)
 *   VULN_HEADERS=0     → se envían CSP, HSTS, X-Frame-Options, etc. (seguro)
 *   VULN_COOKIES=0     → cookies con HttpOnly, Secure, SameSite=Strict (seguro)
 *   VULN_PATHTRAVERSAL=0 → /files restringido a directorio público (seguro)
 *   VULN_SSRF=0        → /fetch-image con allowlist de dominios (seguro)
 *
 * Atajo por día del taller:
 *   VULN_DAY=2  → habilita SQLi + XSS
 *   VULN_DAY=3  → habilita CMDi + JWT + PathTraversal
 *   VULN_DAY=4  → habilita IDOR + CSRF + Cookies
 *   VULN_DAY=5  → habilita PLAINTEXT + SECRETS
 *   VULN_DAY=6  → habilita HEADERS + SSRF
 *   (sin VULN_DAY o VULN_DAY=all → todo habilitado)
 */

function isEnabled(envVar: string, defaultValue = true): boolean {
  const val = process.env[envVar];
  if (val === undefined) return defaultValue;
  return val !== '0' && val.toLowerCase() !== 'false';
}

// Atajo por día: si VULN_DAY está definido, solo activa las vulns de ese día
const day = process.env.VULN_DAY;

function dayDefault(days: number[]): boolean {
  if (!day || day === 'all') return true; // sin filtro → todo habilitado
  const d = parseInt(day, 10);
  return days.includes(d);
}

export const vulns = {
  /** Día 2: SQL Injection en /auth/login */
  SQLI: isEnabled('VULN_SQLI', dayDefault([2])),

  /** Día 2: Stored XSS en /comments */
  XSS: isEnabled('VULN_XSS', dayDefault([2])),

  /** Día 3: Command Injection en /debug?cmd= */
  CMDI: isEnabled('VULN_CMDI', dayDefault([3])),

  /** Día 3: JWT con secreto débil + sin restricción de algoritmo */
  JWT_WEAK: isEnabled('VULN_JWT_WEAK', dayDefault([3])),

  /** Día 3: Path Traversal en /files?path= */
  PATHTRAVERSAL: isEnabled('VULN_PATHTRAVERSAL', dayDefault([3])),

  /** Día 4: IDOR en /users/:id y /products/:id (PUT/DELETE) */
  IDOR: isEnabled('VULN_IDOR', dayDefault([4])),

  /** Día 4: Sin protección CSRF (CORS *) */
  CSRF: isEnabled('VULN_CSRF', dayDefault([4])),

  /** Día 4: Cookies sin flags de seguridad (HttpOnly, Secure, SameSite) */
  COOKIES: isEnabled('VULN_COOKIES', dayDefault([4])),

  /** Día 5: Passwords en plain text */
  PLAINTEXT: isEnabled('VULN_PLAINTEXT', dayDefault([5])),

  /** Día 5: /debug expone process.env (secretos visibles) */
  SECRETS: isEnabled('VULN_SECRETS', dayDefault([5])),

  /** Día 6: Sin cabeceras de seguridad (CSP, HSTS, X-Frame-Options...) */
  HEADERS: isEnabled('VULN_HEADERS', dayDefault([6])),

  /** Día 6: SSRF en /fetch-image?url= (sin allowlist) */
  SSRF: isEnabled('VULN_SSRF', dayDefault([6])),
};

// Log en arranque para que el instructor vea qué está activo
console.log('[VulnApp] Configuración de vulnerabilidades:');
Object.entries(vulns).forEach(([key, enabled]) => {
  console.log(`  ${enabled ? '🔓' : '🔒'} ${key}: ${enabled ? 'VULNERABLE' : 'PARCHEADO'}`);
});
