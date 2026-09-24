# Detección de fuerza bruta SSH con Snort (IDS)

**Autor:** Iván Muñoz Hernández
**Práctica:** P6_1 · Ataque a SSH con Hydra y detección con Snort
**Escenario:** Kali (atacante, Hydra + crunch) → Ubuntu 22.04 (víctima SSH + IDS Snort), red aislada.

## 1. Objetivo

Generar un ataque de fuerza bruta dirigido contra SSH y **detectarlo** escribiendo una
regla de IDS. Cierra el ciclo ataque → detección: pasar del rol preventivo (bastionar) al
rol de monitorización (detectar lo que el bastionado no impide).

## 2. El ataque (contexto)

Con dos pistas de ingeniería social (usuario = 2 letras minúsculas; clave = 1 letra + 1
número) se generan diccionarios acotados con `crunch` y se lanza el ataque con `hydra`:

```bash
crunch 2 2 -t @@ -o usuarios.txt      # 676 combinaciones (26x26)
crunch 2 2 -t @% -o claves.txt        # 260 combinaciones (26x10)
hydra -L usuarios.txt -P claves.txt -o resultados.txt -t 4 -I ssh://IP_VICTIMA:22
```

Lección: un buen OSINT convierte un espacio de búsqueda inviable en uno trivial
(175.760 combinaciones en lugar de fuerza bruta ciega).

## 3. La regla de detección

Ubicación: `/etc/snort/rules/local.rules`

```
alert tcp any any -> any 22 (msg:"Intento acceso SSH"; sid:3000001; threshold: type threshold, track by_src, count 50, seconds 30;)
```

### Anatomía (cabecera + cuerpo)

**Cabecera — qué tráfico inspeccionar:**

| Campo | Valor | Significado |
|---|---|---|
| Acción | `alert` | Genera alerta y la registra |
| Protocolo | `tcp` | Solo TCP |
| Origen | `any any` | Cualquier IP, cualquier puerto de origen |
| Dirección | `->` | Sentido del flujo |
| Destino | `any 22` | Cualquier IP destino, puerto 22 (SSH) |

**Cuerpo — opciones entre paréntesis:**

| Opción | Función |
|---|---|
| `msg:"Intento acceso SSH"` | Texto que aparece en la alerta |
| `sid:3000001` | Identificador único de la regla (locales: sid >= 1.000.000) |
| `threshold: type threshold, track by_src, count 50, seconds 30` | Solo alerta con >50 conexiones en 30 s desde la misma IP de origen |

### La clave conceptual

El `threshold` es lo que convierte "ruido" en "detección útil": **una conexión SSH aislada
es legítima; 50 en 30 segundos es fuerza bruta.** Sin umbral, la regla alertaría de cada
login normal y ahogaría al analista en falsos positivos. Distinguir lo malicioso por
**volumen y frecuencia** (no por el hecho en sí) es criterio de analista.

## 4. Configuración de la salida de alertas

En `/etc/snort/snort.conf` se sustituye el formato binario por texto legible:

```
# output unified2: filename snort.log, limit 128, nostamp, ...   <- comentada
output alert_fast: snort.alert.fast
```

Validación y ejecución:

```bash
sudo snort -T -c /etc/snort/snort.conf -i IFACE          # valida la config
sudo snort -A console -q -c /etc/snort/snort.conf -i IFACE  # a la escucha
```

Alerta resultante (consola y `/var/log/snort/snort.alert.fast`):

```
[**] [1:3000001:0] Intento acceso SSH [**]
```

## 5. Variantes que suben el nivel (para entrevista)

**a) Diferenciar el primer intento de la reincidencia — `detection_filter`.**
`threshold` limita cuántas *alertas* se generan; `detection_filter` solo evalúa la regla
tras superar el umbral. Es la forma moderna de expresar "no me molestes hasta que sea un
patrón":

```
alert tcp any any -> any 22 (msg:"Fuerza bruta SSH"; sid:3000002; \
  detection_filter: track by_src, count 50, seconds 30;)
```

**b) Reducir falsos positivos acotando el origen.** Cambiar `any` de origen por
`!$HOME_NET` para alertar solo de fuentes externas, o excluir IPs de administración
conocidas.

**c) Correlación en el SIEM.** Una regla de IDS detecta el patrón de red; en un SIEM
(práctica P6_5) se correlaciona además con los *fallos de autenticación* de
`/var/log/auth.log` para confirmar el ataque y reducir falsos positivos. La detección
robusta combina varias señales.

## 6. Qué demuestra este entregable

- Comprensión de la **anatomía de una regla de IDS** y capacidad de escribir una desde cero
  (pregunta habitual en entrevistas de SOC).
- Criterio para **distinguir tráfico legítimo de malicioso** mediante umbrales, evitando la
  fatiga por falsos positivos.
- Visión de **defensa en profundidad**: el hardening de SSH (claves, `PasswordAuthentication
  no`) previene el ataque; el IDS lo detecta si la prevención falla. Prevención y detección
  son capas complementarias, no alternativas.
```
