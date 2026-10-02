# Hacking Web — explotación, causa en código y corrección (OWASP Top 10:2025)

**Autor:** Iván Muñoz Hernández
**Práctica:** HackingWeb · DVWA + OWASP Juice Shop
**Enfoque:** perfil de desarrollador con mentalidad de seguridad — cada vulnerabilidad se
analiza en tres capas: **cómo se explota**, **por qué el código es vulnerable** y **cómo se
corrige**.
**Entorno:** aplicaciones deliberadamente vulnerables (DVWA, Juice Shop) en Docker, en local.

## 1. Metodología

No basta con explotar: el valor está en entender la causa raíz en el código y escribir la
corrección. Todas las vulnerabilidades practicadas comparten un puñado de causas raíz
(input tratado como código, confiar en el cliente, validación incompleta), que es lo que
permite razonar sobre seguridad en vez de memorizar ataques.

## 2. Tabla maestra de vulnerabilidades

| # | Vulnerabilidad | Plataforma | Cómo se explota | Causa en el código | Corrección segura | OWASP 2025 |
|---|---|---|---|---|---|---|
| 1 | SQL Injection | DVWA / Juice Shop | `1' UNION SELECT user,password FROM users-- ` / login con `' OR 1=1--` | Input concatenado dentro de la consulta SQL | Consultas parametrizadas (prepared statements) / ORM con binding | A05 Injection |
| 2 | Command Injection | DVWA | `127.0.0.1; whoami` en el campo de ping | Input concatenado dentro de un comando de shell | Lista blanca (validar que es IP) + `escapeshellarg()` | A05 Injection |
| 3 | Cross-Site Scripting (XSS) | Juice Shop | `<iframe src="javascript:alert(\`xss\`)">` en la búsqueda | Input pintado en el DOM sin sanitizar | Escapar/codificar la salida; binding seguro; cabecera CSP | A05 Injection |
| 4 | File Upload → webshell (RCE) | DVWA | Subir `shell.php` y llamarla con `?cmd=whoami` | Se guarda el archivo sin validar tipo real y en ruta ejecutable | Lista blanca por contenido, renombrar, guardar fuera del webroot / sin ejecución | A06 Insecure Design (deriva en RCE) |
| 5 | CSRF | DVWA | `<img src=".../csrf/?password_new=hacked&...">` que la víctima carga | El servidor no distingue una petición legítima de una forjada | Token anti-CSRF por sesión; cookies `SameSite`; POST + re-autenticación | A01 Broken Access Control |
| 6 | Fuerza bruta de login | DVWA | Burp Suite → Intruder con diccionario sobre el login | Intentos ilimitados: sin rate limit, bloqueo ni MFA | Rate limiting, bloqueo de cuenta, CAPTCHA, MFA + monitorización | A07 Authentication Failures |
| 7 | Broken Access Control | Juice Shop | Navegar directo a `/#/administration` sin ser admin | Control de acceso ausente en el servidor; ruta solo "oculta" en el cliente | Verificar rol/permiso en el backend en cada petición sensible | A01 Broken Access Control |
| 8 | JWT: `alg: none` | Juice Shop | Editar el JWT (alg none, payload admin, sin firma) en Local Storage | El backend acepta un token sin verificar su firma | Fijar el algoritmo esperado (p.ej. RS256), rechazar `none`, verificar firma siempre | A08 Software or Data Integrity Failures |

## 3. Lecciones transversales (las que importan en entrevista)

- **Nunca confíes en el input del usuario.** SQLi, Command Injection y XSS son el mismo
  error en contextos distintos: datos que acaban interpretándose como código (SQL, shell,
  JavaScript). La defensa es siempre **separar datos de código** (parametrizar, escapar).
- **El frontend no es una frontera de seguridad.** Todo el JavaScript de una SPA se descarga
  al navegador del atacante: puede leer rutas, lógica y endpoints. El control de acceso
  **tiene que vivir en el servidor** (caso del panel de administración).
- **Listas blancas, no listas negras.** Filtrar "lo malo conocido" (bloquear `;` y `&&`)
  siempre se queda corto; definir "lo bueno permitido" es robusto.
- **Una validación a medias da falsa seguridad.** En DVWA nivel *Medium* se vio cómo se
  bypassean protecciones parciales: validar por `Content-Type` (lo controla el cliente),
  por lista negra de separadores, o por header `Referer` (falsificable). Media defensa
  puede ser peor que ninguna, porque genera confianza injustificada.

## 4. Conexión con el resto del itinerario

La seguridad web completa tiene dos mitades que se complementan:

- **Prevenir en el código** (este entregable): escribir aplicaciones que no sean
  explotables.
- **Detectar en el SOC**: el ataque de fuerza bruta web (punto 6) es el mismo patrón que se
  detecta con la regla de Snort (práctica P6_1) y con el SIEM (P6_5). La corrección de
  código y la monitorización son capas de la misma defensa en profundidad.

## 5. Qué demuestra este entregable

- Dominio de las vulnerabilidades web más habituales en dos plataformas (clásica y API
  moderna), con su mapeo al **OWASP Top 10:2025**.
- **Perfil diferencial de desarrollador seguro:** no solo explotar, sino identificar la causa
  en el código y escribir la corrección — exactamente lo que busca un equipo de desarrollo
  que quiere incorporar seguridad (secure SDLC).
- Comprensión de las causas raíz comunes, que permite razonar sobre vulnerabilidades nuevas
  en lugar de depender de recetas.
