import { Router, Request, Response } from 'express';
import { execSync } from 'child_process';

const router = Router();

// ⚠️ VULNERABILIDAD T03/T06: endpoint de depuración expuesto sin autenticación
// ⚠️ VULNERABILIDAD T06: Command Injection — ejecuta el comando del parámetro ?cmd=
// FIX T03: proteger con middleware de autenticación
// FIX T06: eliminar este endpoint en producción o aplicar una allowlist estricta de comandos

const ALLOWED_CMDS = new Set(['uptime', 'date', 'hostname']);

router.get('/', (req: Request, res: Response) => {
  const cmd = req.query.cmd as string | undefined;

  // ⚠️ VERSIÓN VULNERABLE (comentada para referencia del alumno):
  // if (cmd) {
  //   try {
  //     const output = execSync(cmd).toString();        // ← COMMAND INJECTION
  //     return res.json({ output });
  //   } catch (e) {
  //     return res.status(500).json({ error: String(e) });
  //   }
  // }

  // Starter: sin allowlist (vulnerable)
  // Descomentar el bloque anterior y comentar este para ver el ataque en acción.
  if (cmd) {
    if (!ALLOWED_CMDS.has(cmd)) {
      res.status(400).json({ error: `Comando no permitido. Permitidos: ${[...ALLOWED_CMDS].join(', ')}` });
      return;
    }
    try {
      const output = execSync(cmd).toString();
      res.json({ output });
      return;
    } catch {
      res.status(500).json({ error: 'Error al ejecutar el comando' });
      return;
    }
  }

  // ⚠️ VULNERABILIDAD T06: expone variables de entorno (puede incluir secretos)
  // FIX T06: eliminar este endpoint o nunca exponer process.env
  res.json({
    message: 'Endpoint de debug',
    // ⚠️ Expone process.env — puede revelar JWT_SECRET, DB credentials, etc.
    env: process.env,
    nodeVersion: process.version,
    uptime: process.uptime(),
  });
});

export default router;
