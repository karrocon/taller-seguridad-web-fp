import { Router, Request, Response } from 'express';
import { execSync } from 'child_process';
import { vulns } from '../config/vulns';

const router = Router();

// Comandos permitidos (cuando CMDi está parcheado)
const ALLOWED_CMDS = new Set(['uptime', 'date', 'hostname', 'whoami', 'ls']);

router.get('/', (req: Request, res: Response) => {
  const cmd = req.query.cmd as string | undefined;

  if (cmd) {
    if (vulns.CMDI) {
      // ⚠️ VULNERABLE: Command Injection directo
      try {
        const output = execSync(cmd, { timeout: 5000, maxBuffer: 1024 * 512 }).toString();
        res.json({ output });
        return;
      } catch (e: any) {
        const stderr = e.stderr ? e.stderr.toString() : '';
        const stdout = e.stdout ? e.stdout.toString() : '';
        res.status(500).json({ error: e.message, stderr, stdout });
        return;
      }
    } else {
      // ✅ PARCHEADO: solo comandos de la allowlist
      if (!ALLOWED_CMDS.has(cmd)) {
        res.status(400).json({ error: 'Comando no permitido' });
        return;
      }
      try {
        const output = execSync(cmd, { timeout: 5000 }).toString();
        res.json({ output });
        return;
      } catch (e: any) {
        res.status(500).json({ error: e.message });
        return;
      }
    }
  }

  // Info de debug: expone env solo si SECRETS está habilitado
  if (vulns.SECRETS) {
    res.json({
      message: 'Endpoint de debug',
      env: process.env,
      nodeVersion: process.version,
      uptime: process.uptime(),
    });
  } else {
    res.json({
      message: 'Endpoint de debug',
      nodeVersion: process.version,
      uptime: process.uptime(),
    });
  }
});

export default router;
