# Taller de Seguridad Web — FP

> Curso autodidacta de seguridad web para Formación Profesional.  
> 7 módulos · 21 topics · 1 app vulnerable que hackeas y reparas tú mismo.

---

## Tabla de contenidos

- [¿De qué trata este curso?](#de-qué-trata-este-curso)
- [Requisitos previos](#requisitos-previos)
- [Herramientas del curso](#herramientas-del-curso)
- [Estructura — 7 módulos](#estructura--7-módulos)
- [Cómo usar este repositorio](#cómo-usar-este-repositorio)
- [Recursos y referencias](#recursos-y-referencias)

---

## ¿De qué trata este curso?

Aprenderás seguridad web atacando y corrigiendo **VulnApp**, una aplicación Node.js+TypeScript con vulnerabilidades reales incluidas intencionalmente.

**Al terminar sabrás:**

- Explotar y corregir las vulnerabilidades del **OWASP Top 10**
- Almacenar contraseñas correctamente (bcrypt/Argon2)
- Configurar HTTPS, TLS y cabeceras HTTP de seguridad
- Dockerizar apps de forma segura
- Realizar un pentest básico con OWASP ZAP y Burp Suite
- Integrar seguridad en pipelines CI/CD (DevSecOps)
- Escribir un informe de auditoría real

> ⚠️ **Todo el contenido de ataque es exclusivamente para el entorno de laboratorio local.** Nunca pruebes estas técnicas en sistemas reales sin autorización.

---

## Requisitos previos

| Requisito | Nivel mínimo |
|-----------|-------------|
| HTML y HTTP básico | Entender qué es una petición/respuesta |
| Programación | Variables, funciones, condicionales (cualquier lenguaje) |
| Terminal/bash | Saber abrir una terminal y ejecutar comandos básicos |
| Node.js | No necesario — se explica en el curso |
| Docker | No necesario — se explica en el curso |

### Instalaciones necesarias

```bash
# Node.js 20+
https://nodejs.org

# Docker Desktop
https://www.docker.com/products/docker-desktop/

# VS Code (recomendado)
https://code.visualstudio.com

# Extensiones VS Code recomendadas
# - REST Client (Huachao Mao)
# - Docker (Microsoft)
# - ESLint

# Clonar el repositorio
git clone https://github.com/karrocon/taller-seguridad-web-fp
cd taller-seguridad-web-fp/VulnApp
npm install
npm start
# → VulnApp disponible en http://localhost:3000
```

---

## Herramientas del curso

### Herramientas de seguridad (todas gratuitas)

| Herramienta | Para qué | Instalación |
|-------------|---------|-------------|
| **OWASP ZAP** | Scanner de vulnerabilidades automatizado | [zaproxy.org](https://www.zaproxy.org) |
| **Burp Suite Community** | Proxy para interceptar y modificar peticiones HTTP | [portswigger.net/burp/communitydownload](https://portswigger.net/burp/communitydownload) |
| **nikto** | Escáner de servidores web (misconfiguraciones, versiones) | `sudo apt install nikto` / `brew install nikto` |
| **nmap** | Escaneo de puertos y detección de servicios | [nmap.org](https://nmap.org) |
| **Wireshark** | Analizador de tráfico de red | [wireshark.org](https://www.wireshark.org) |

### Herramientas de análisis de código y dependencias

| Herramienta | Para qué | Uso |
|-------------|---------|-----|
| **npm audit** | Dependencias con CVEs conocidos | `npm audit` |
| **Snyk** | Análisis de dependencias + recomendaciones | `npx snyk test` |
| **truffleHog** | Detecta secretos en el historial de git | `npx trufflehog filesystem .` |
| **CodeQL** | SAST — análisis estático de seguridad | GitHub Actions |

### Servicios online gratuitos

| Servicio | Para qué | URL |
|----------|---------|-----|
| **securityheaders.com** | Analiza las cabeceras HTTP de seguridad de tu app | [securityheaders.com](https://securityheaders.com) |
| **SSL Labs** | Analiza la configuración TLS de tu servidor | [ssllabs.com/ssltest](https://www.ssllabs.com/ssltest/) |
| **HaveIBeenPwned** | Comprueba si un email/contraseña ha sido filtrado | [haveibeenpwned.com](https://haveibeenpwned.com) |
| **jwt.io** | Decodificar y analizar tokens JWT | [jwt.io](https://jwt.io) |
| **CyberChef** | Codificación/decodificación/hashing | [gchq.github.io/CyberChef](https://gchq.github.io/CyberChef/) |
| **OSV.dev** | Base de datos de vulnerabilidades open source | [osv.dev](https://osv.dev) |

---

## Estructura — 7 módulos

```
owasp/
├── modulo-01-fundamentos-entorno/
│   ├── t01-arquitectura-web/
│   ├── t02-docker-entorno/
│   └── t03-vulnapp-setup/
├── modulo-02-inyeccion/
│   ├── t04-sql-injection/
│   ├── t05-xss/
│   └── t06-command-injection/
├── modulo-03-identidad-acceso/
│   ├── t07-autenticacion-jwt/
│   ├── t08-idor-control-acceso/
│   └── t09-cookies-csrf-sesiones/
├── modulo-04-datos-secretos/
│   ├── t10-http-https-tls/
│   ├── t11-passwords-seguras/
│   └── t12-secretos-keyvault/
├── modulo-05-superficie-servidor/
│   ├── t13-headers-http/
│   ├── t14-dependencias-vulnerables/
│   └── t15-ssrf-apis/
├── modulo-06-infraestructura-deploy/
│   ├── t16-base-datos-segura/
│   ├── t17-docker-seguro/
│   └── t18-reverse-proxy-tls/
└── modulo-07-devsecops-cierre/
    ├── t19-cicd-secretos/
    ├── t20-pentesting/
    └── t21-owasp-top10-repaso/
```

### Mapeo al OWASP Top 10 (2021)

| OWASP | Categoría | Topics que lo cubren |
|-------|-----------|---------------------|
| A01 | Broken Access Control | T08 (IDOR), T07 (JWT), T09 (CSRF) |
| A02 | Cryptographic Failures | T10 (TLS), T11 (bcrypt), T12 (secretos) |
| A03 | Injection | T04 (SQLi), T05 (XSS), T06 (Command Injection) |
| A04 | Insecure Design | T03 (VulnApp design), T15 (SSRF) |
| A05 | Security Misconfiguration | T13 (Headers), T17 (Docker), T18 (nginx) |
| A06 | Vulnerable Components | T14 (dependencias) |
| A07 | Auth and Session Mgmt | T07 (JWT), T09 (Cookies/CSRF) |
| A08 | Software Integrity Failures | T19 (CI/CD) |
| A09 | Logging & Monitoring | T19 (CI/CD), T20 (Pentesting) |
| A10 | Server-Side Request Forgery | T15 (SSRF) |

---

## Cómo usar este repositorio

### Estructura de cada topic

```
tXX-nombre-del-topic/
├── _private/
│   └── slides-tXX.md      # Slides Marp (compilar a HTML)
├── starter/               # Código vulnerable para el lab
└── solucion/              # Fix aplicado (consultar si te atascas)
```

### Flujo recomendado para cada topic

1. **Lee las slides** en `_private/slides-tXX.html`
2. **Lanza VulnApp**: `cd VulnApp && npm start`
3. **Ataca** siguiendo los pasos del lab con el código de `starter/`
4. **Aplica el fix** (no mires `solucion/` hasta intentarlo)
5. **Verifica** que el ataque ya no funciona

### Compilar slides

```powershell
# Compilar un topic específico
cd owasp/_private
.\build-slides.ps1 -Topic t04

# Compilar un módulo completo
.\build-slides.ps1 -Modulo 2

# Compilar todo
.\build-slides.ps1
```

---

## Recursos y referencias

### OWASP y estándares

| Recurso | URL | Para qué |
|---------|-----|---------|
| **OWASP Top 10** | [owasp.org/Top10](https://owasp.org/www-project-top-ten/) | La referencia principal del curso |
| **OWASP Testing Guide** | [owasp.org/WSTG](https://owasp.org/www-project-web-security-testing-guide/) | Guía completa de pentesting web |
| **OWASP Cheat Sheet Series** | [cheatsheetseries.owasp.org](https://cheatsheetseries.owasp.org) | Referencia rápida de seguridad |
| **CWE — Common Weakness Enumeration** | [cwe.mitre.org](https://cwe.mitre.org) | Taxonomía de debilidades de software |
| **CVE — Common Vulnerabilities and Exposures** | [cve.mitre.org](https://cve.mitre.org) | Base de datos de vulnerabilidades conocidas |
| **CVSS Calculator** | [first.org/cvss/calculator/3.1](https://www.first.org/cvss/calculator/3.1) | Calcular severidad de vulnerabilidades |

### Laboratorios online gratuitos

| Recurso | URL | Nivel |
|---------|-----|-------|
| **PortSwigger Web Security Academy** | [portswigger.net/web-security](https://portswigger.net/web-security) | Iniciación → Avanzado |
| **OWASP WebGoat** | [owasp.org/WebGoat](https://owasp.org/www-project-webgoat/) | Iniciación |
| **DVWA (Damn Vulnerable Web App)** | [dvwa.co.uk](https://dvwa.co.uk) | Iniciación → Intermedio |
| **TryHackMe** | [tryhackme.com](https://tryhackme.com) | Iniciación → Intermedio |
| **HackTheBox** | [hackthebox.com](https://www.hackthebox.com) | Intermedio → Avanzado |
| **PentesterLab** | [pentesterlab.com](https://pentesterlab.com) | Iniciación → Avanzado |

### Herramientas de pentesting

| Herramienta | URL | Nivel |
|-------------|-----|-------|
| **OWASP ZAP** | [zaproxy.org](https://www.zaproxy.org) | Iniciación |
| **Burp Suite Community** | [portswigger.net/burp/communitydownload](https://portswigger.net/burp/communitydownload) | Intermedio |
| **sqlmap** | [sqlmap.org](https://sqlmap.org) | Solo en labs propios |
| **Metasploit** | [metasploit.com](https://www.metasploit.com) | Solo en labs propios |

> ⚠️ El uso de herramientas de pentesting en sistemas sin autorización es ilegal. Úsalas exclusivamente en entornos de laboratorio propios o en plataformas como TryHackMe/HackTheBox que están diseñadas para ello.

### Certificaciones de seguridad (siguiente paso)

| Certificación | Organización | Nivel |
|---------------|-------------|-------|
| **CompTIA Security+** | CompTIA | Iniciación |
| **eWPT** (Web App Pentester) | eLearnSecurity | Intermedio |
| **OSCP** | Offensive Security | Avanzado |
| **CEH** | EC-Council | Iniciación → Intermedio |

---

## Autor

**Carlos Rodríguez Contreras**  
Senior Software Engineer @ Shopify  
<carlos.mailhub@gmail.com> · [github.com/karrocon](https://github.com/karrocon)

---

## Licencia

Este material es para uso educativo en el contexto de Formación Profesional.  
El código de VulnApp es intencionalmente vulnerable — **no usar en producción**.
