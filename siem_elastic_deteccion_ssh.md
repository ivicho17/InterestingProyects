# SIEM end-to-end con Elastic Security — detección de fuerza bruta SSH

**Autor:** Iván Muñoz Hernández
**Prácticas:** P6_3 / P6_5 / P6_6 · Elastic (SIEM), ingesta y detección
**Despliegue:** Elastic Cloud Serverless — proyecto tipo *Security* (Elasticsearch + Kibana gestionados en la nube)
**Fuentes monitorizadas:** Ubuntu 22.04 (servidor SSH) vía Elastic Agent · atacante: Kali (Hydra)

## 1. Objetivo

Desplegar un SIEM de principio a fin: montar la plataforma, **ingerir** logs de un host,
y **detectar** automáticamente un evento de seguridad (ataque de fuerza bruta SSH),
clasificándolo con MITRE ATT&CK y dejándolo listo para alertar.

## 2. Arquitectura del SIEM

Un SIEM se estructura en cinco capas. Correspondencia con este montaje:

| Capa | Función | Componente aquí |
|---|---|---|
| Recolección | Recoger logs en cada host | Elastic Agent (integración System) |
| Normalización | Estructurar el texto crudo en campos comunes | Elastic Common Schema (ECS) |
| Almacenamiento e indexado | Guardar e indexar millones de eventos | Elasticsearch (serverless) |
| Visualización y búsqueda | Consultar y representar | Kibana (Discover, Dashboards) |
| Detección y respuesta | Correlacionar, alertar, clasificar | Detection rules + MITRE ATT&CK + conectores |

Elección de despliegue **serverless**: Elasticsearch y Kibana corren como servicio
gestionado (sin consumir RAM local ni requerir Fleet Server manual); en los hosts solo se
instala el Elastic Agent. Es el modelo más cercano a un SOC real y el adecuado para un
laboratorio con recursos limitados.

## 3. Ingesta de logs (Elastic Agent + integración System)

1. Integración **System** añadida a una política de agente (`Equipos cliente`): captura
   `system.auth` (logins SSH, sudo, altas de usuario), syslog y métricas.
2. **Elastic Agent** instalado en Ubuntu y enrolado en Fleet (estado *Healthy*).
   > En serverless el comando de instalación NO lleva `--insecure` (el certificado de la
   > nube es válido), a diferencia de una instalación local autofirmada.
3. Verificación en **Discover**: los eventos llegan como documentos JSON con campos ECS.

**Concepto clave — ECS (Elastic Common Schema):** campos como `source.ip`, `event.action`,
`event.outcome` o `host.name` tienen el mismo nombre venga el log de donde venga. Esa
normalización es lo que permite buscar y correlacionar a través de toda la infraestructura
desde un único sitio.

## 4. Regla de detección

Tipo **Threshold** (misma lógica que la regla de Snort de la práctica P6_1: no importa el
evento aislado, sino su frecuencia).

| Parámetro | Valor |
|---|---|
| Tipo de regla | Threshold |
| Índice | `logs-*` |
| Query | `event.category:authentication and event.outcome:failure` |
| Group by | `source.ip` |
| Threshold (count) | ≥ 8 |
| Ejecución | cada 1 min, look-back 5 min |
| Severidad / Risk | Medium / ~50 |
| MITRE ATT&CK | Táctica *Credential Access* (TA0006) · Técnica *Brute Force* (T1110.001) |

**Calibración del umbral:** 8 dispara enseguida en laboratorio (Hydra genera cientos de
fallos por segundo). En producción se elevaría para equilibrar *detectar pronto* frente a
*no generar falsos positivos* por un usuario que se equivoca de contraseña.

**Validación:** tras relanzar el ataque desde Kali, la regla generó alertas en
**Security → Alerts**, con la `source.ip` del atacante, el recuento de fallos y la etiqueta
MITRE. Visible también en **MITRE ATT&CK Coverage**.

## 5. Diagnóstico de ingesta (troubleshooting como competencia)

Durante la práctica, una alerta aparentemente "no saltaba". El diagnóstico correcto va de
origen a destino:

1. **¿Se genera el evento?** `sudo sshd -T | grep passwordauthentication` (efectivo, no el
   fichero) y `grep "Failed password" /var/log/auth.log`. Ojo con los *drop-in* de
   `/etc/ssh/sshd_config.d/` que sobrescriben el `sshd_config` (herencia del hardening CIS).
2. **¿Llega al SIEM?** En Discover, ampliar el rango de tiempo (los relojes desincronizados
   de las VMs esconden eventos) y buscar `event.dataset:"system.auth"`.
3. **¿La regla se ejecuta?** El **execution log** de la regla indica, por pasada, si tuvo
   éxito y cuántas alertas creó.

Conclusión del caso real: la regla **sí** había creado alertas; solo se estaban mirando
fuera de la ventana de tiempo de la vista *Alerts*. Lección: descartar primero el rango
temporal y leer el execution log antes de tocar la regla. En un SOC, muchas "incidencias de
detección" son exactamente esto.

## 6. (Opcional) Respuesta — alerta a Slack

Conector de Slack (Incoming Webhook) añadido como acción de la regla, de modo que cada
detección se notifica en tiempo real. Es la capa de *respuesta* del ciclo.

## 7. Qué demuestra este entregable

- **Manejo de un SIEM de extremo a extremo:** desplegar, ingestar, buscar, detectar y
  responder — el flujo de trabajo diario de un analista SOC.
- **Comprensión de arquitectura y de ECS**, no solo uso de una herramienta.
- **Detección basada en MITRE ATT&CK**, el lenguaje común del SOC para clasificar
  comportamientos y medir cobertura.
- **Capacidad de diagnóstico** de problemas de ingesta de origen a destino.
- **El arco defensivo completo**, integrando todo el itinerario:
  - *Prevención* — hardening de SSH y firewall (P2_12, P5_3) + bastionado CIS (P2_9).
  - *Detección local* — regla de IDS con Snort (P6_1).
  - *Detección centralizada y respuesta* — SIEM con Elastic (esta práctica).

  El mismo ataque de fuerza bruta SSH recorre las tres capas: se previene, se detecta en el
  host y se detecta y notifica de forma centralizada. Ese es el mensaje que demuestra
  madurez de analista.
