import { Router, Request, Response } from 'express';
import { execSync } from 'child_process';

const router = Router();

// ⚠️ VULNERABILIDAD T03/T06: endpoint de depuración expuesto sin autenticación
// ⚠️ VULNERABILIDAD T06: Command Injection — ejecuta el comando del parámetro ?cmd=
// FIX T03: proteger con middleware de autenticación
// FIX T06: eliminar este endpoint en producción o aplicar una allowlist estricta de comandos

// FIX (comentado para el taller): usar allowlist
// const ALLOWED_CMDS = new Set(['uptime', 'date', 'hostname']);

router.get('/', (req: Request, res: Response) => {
  const cmd = req.query.cmd as string | undefined;

  // ⚠️ VERSIÓN VULNERABLE — Command Injection directo
  if (cmd) {
    try {
      const output = execSync(cmd, { timeout: 5000, maxBuffer: 1024 * 512 }).toString();
      res.json({ output });
      return;
    } catch (e: any) {
      // Devuelve stderr también (útil para el alumno)
      const stderr = e.stderr ? e.stderr.toString() : '';
      const stdout = e.stdout ? e.stdout.toString() : '';
      res.status(500).json({ error: e.message, stderr, stdout });
      return;
    }
  }

  // FIX T06 (para referencia del alumno):
  // if (cmd) {
  //   if (!ALLOWED_CMDS.has(cmd)) {
  //     res.status(400).json({ error: `Comando no permitido` });
  //     return;
  //   }
  //   execFile(cmd, [], (err, stdout) => {
  //     if (err) return res.status(500).json({ error: err.message });
  //     res.json({ output: stdout });
  //   });
  //   return;
  // }

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
