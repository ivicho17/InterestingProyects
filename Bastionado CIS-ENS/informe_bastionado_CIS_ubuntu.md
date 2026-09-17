# Informe de bastionado — Ubuntu 22.04 según CIS (USG)

**Autor:** Iván Muñoz Hernández
**Práctica:** P2_9 · Bastionado de Ubuntu 22.04 según CIS mediante Ubuntu Security Guide (USG)
**Sistema:** Ubuntu 22.04.5 LTS (Desktop)
**Perfil aplicado:** `cis_level1_workstation` (CIS Ubuntu Linux 22.04 LTS Benchmark, Nivel 1 – Workstation)

## 1. Objetivo

Aplicar un baseline de seguridad basado en un **marco normativo** (CIS Benchmarks) en
lugar de un endurecimiento improvisado, y **demostrar el cumplimiento con evidencias**
midiendo el porcentaje de conformidad antes y después de la remediación.

## 2. Marco de referencia

- **CIS Benchmarks:** estándar internacional de configuración segura, consensuado por
  la industria. Define niveles (L1 razonable / L2 alta seguridad) y perfiles por tipo de
  sistema (workstation / server).
- **USG (Ubuntu Security Guide):** herramienta de Canonical, incluida en Ubuntu Pro, que
  automatiza la auditoría (`audit`) y la remediación (`fix`) frente a los benchmarks CIS.
- **Relación con el ENS:** el ciclo auditar → remediar → evidenciar es el mismo que exige
  el Esquema Nacional de Seguridad (marco español) con las guías CCN-STIC y la herramienta
  CLARA. Cambia el estándar y la herramienta; la metodología es idéntica.

## 3. Metodología (ciclo de cumplimiento)

1. **Snapshot** de la VM (`pre-CIS`) para poder revertir: el hardening CIS puede afectar a
   funcionalidad y siempre se prueba sobre un estado reversible.
2. **Auditoría inicial** para medir el estado de partida.
3. **Remediación** con `usg fix` + reinicio (muchas reglas requieren reboot).
4. **Re-auditoría** para evidenciar la mejora.

### Comandos utilizados

```bash
# Alta y habilitación de la herramienta
sudo pro attach <token>
sudo pro enable usg
sudo apt install -y usg

# Auditoría (genera informe HTML/XML en /var/lib/usg/)
sudo usg audit cis_level1_workstation

# Remediación
sudo usg fix cis_level1_workstation
sudo reboot

# Re-auditoría
sudo usg audit cis_level1_workstation
```

## 4. Resultados

| Fase | Cumplimiento CIS L1 Workstation |
|---|---|
| Auditoría inicial (sistema base) | **62,78 %** |
| Tras `usg fix` + reinicio | **94,88 %** |
| **Mejora** | **+32,10 puntos** |

Evidencias adjuntas: `informe_inicial.html` y `informe_final.html` (informes generados por
USG, extraídos de `/var/lib/usg/` y con propietario reasignado al usuario para su entrega).

## 5. Interpretación

- **El cumplimiento no es todo-o-nada.** No se alcanza (ni se busca) el 100 %: algunas
  reglas quedan en *fail* de forma justificada porque dependen del entorno y no se pueden
  automatizar de forma segura. Ejemplos típicos:
  - **Particiones separadas** para `/tmp`, `/var`, `/var/log`, `/home` con opciones
    `noexec`/`nosuid`/`nodev` → se deciden en la instalación (relación con la práctica P2_7).
  - **Contraseña en el gestor de arranque (GRUB).**
  - **Servidor de logs remoto** para centralización (relación con la práctica P6_4 · rsyslog).
- **Tailoring (aplicar con criterio).** En un entorno real no se aplica el baseline a ciegas:
  se genera un fichero de *tailoring* para desactivar o ajustar reglas que no encajan,
  documentando el motivo, y se audita contra esa versión adaptada:

  ```bash
  sudo usg generate-tailoring cis_level1_workstation mi_tailoring.xml
  sudo usg audit --tailoring-file mi_tailoring.xml
  ```

## 6. Qué demuestra este entregable

- Trabajo con **marcos normativos** (CIS / ENS), no con endurecimiento improvisado.
- Capacidad de **generar evidencia de cumplimiento** (auditorías antes/después), que es el
  núcleo de un puesto de bastionado o de cumplimiento (GRC).
- Criterio operativo: pruebas reversibles (snapshot), comprensión de que el 100 % no es el
  objetivo y adaptación del baseline mediante tailoring.
- Conexión con otras áreas del bastionado: particionado del sistema, arranque seguro y
  centralización de logs.
