# =============================================================================
#  sshd_config BASTIONADO
#  Autor: Iván Muñoz Hernández
#  Práctica base: P2_12 (SSH básico y hardening) + P2_13 (redirección/túneles)
#  Objetivo: administración remota segura, orientación Blue Team.
#
#  Nota de uso: este archivo vive en /etc/ssh/sshd_config en el SERVIDOR.
#  Cada directiva incluye QUÉ MITIGA. Valida siempre con `sudo sshd -t`
#  antes de reiniciar el servicio, y mantén una sesión de rescate abierta.
# =============================================================================


# ----------------------------------------------------------------------------
# 1. RED Y EXPOSICIÓN
# ----------------------------------------------------------------------------

Port 22
# Puerto de escucha. Cambiarlo (p.ej. 2222) reduce el RUIDO de escaneos y bots
# automáticos, pero es "seguridad por oscuridad": no protege frente a un
# atacante dirigido. Se cita como medida cosmética, no como control real.

AddressFamily inet
# Escucha solo en IPv4. Si no usas IPv6, desactivarlo elimina una vía de
# acceso que quizá no estés monitorizando (superficie de ataque no vigilada).

# ListenAddress 192.168.1.10
# (Opcional) Atar SSH a UNA interfaz concreta. Evita exponer el servicio en
# redes donde no debería estar accesible (p.ej. la pata pública de un servidor).


# ----------------------------------------------------------------------------
# 2. AUTENTICACIÓN (el núcleo del hardening)
# ----------------------------------------------------------------------------

PermitRootLogin no
# Prohíbe entrar directamente como root. El atacante ya no puede atacar la
# cuenta más golosa: necesita un usuario válido Y su clave, y luego escalar.
# Reduce drásticamente la superficie de fuerza bruta.

PasswordAuthentication no
# Desactiva el login por contraseña. Mata de raíz la fuerza bruta y los
# ataques de diccionario por SSH. Solo entra quien posee la clave privada.

PubkeyAuthentication yes
# Habilita explícitamente la autenticación por clave pública. Ningún secreto
# viaja por la red y no hay contraseña que adivinar.

PermitEmptyPasswords no
# Nunca permitir cuentas con contraseña vacía. Cierra el peor de los descuidos.

AuthenticationMethods publickey
# Exige clave pública como único método aceptado. Deja constancia clara de la
# política (útil de cara a auditorías y a entrevistas: "SSH solo por clave").

MaxAuthTries 3
# Máximo de intentos por conexión antes de cortarla. Menos margen para probar
# credenciales y menos ruido de intentos por sesión.

LoginGraceTime 30
# Solo 30 segundos para completar la autenticación. Cierra conexiones "colgadas"
# que consumen recursos (mitiga agotamiento de slots de login / mini-DoS).

MaxSessions 3
# Límite de sesiones multiplexadas por conexión. Contención de abuso.

MaxStartups 10:30:60
# Control de conexiones a medio autenticar: a partir de 10 empieza a descartar
# (30%) y en 60 las rechaza todas. Frena floods de conexiones (DoS).


# ----------------------------------------------------------------------------
# 3. CONTROL DE ACCESO (quién puede entrar)
# ----------------------------------------------------------------------------

AllowUsers alumno
# Lista blanca: SOLO estos usuarios pueden autenticarse por SSH. Aunque otra
# cuenta tenga clave válida, si no está aquí, no entra. Principio de mínimo
# privilegio aplicado al acceso remoto. (Alternativa: AllowGroups ssh-users)


# ----------------------------------------------------------------------------
# 4. REDIRECCIÓN Y TÚNELES (decisión consciente por rol del servidor)
# ----------------------------------------------------------------------------

AllowTcpForwarding no
# Desactiva el reenvío de puertos (-L / -R). En un servidor de servicio NO
# quieres que se usen túneles: un -R es la técnica clásica de pivoting y de
# canal C2 de un atacante. OJO: en un HOST BASTIÓN cuyo propósito ES tunelizar,
# esto iría en 'yes'. Aquí lo cierro por defecto y lo abro solo si el rol lo pide.

GatewayPorts no
# Impide que un -R exponga el puerto a toda la red (lo ata a localhost).
# Evita abrir sin querer un servicio a terceros. (Lo probamos en la P2_13.)

X11Forwarding no
# Desactiva el reenvío gráfico (-X). Reduce superficie: X11 sobre SSH tiene
# histórico de vulnerabilidades. NOTA: en la P2_12 lo usamos con fines
# didácticos; en un servidor bastionado real se apaga.

PermitTunnel no
# Prohíbe interfaces tun/tap (VPN sobre SSH). Otra vía de pivoting cerrada.

AllowAgentForwarding no
# Impide reenviar el agente de claves. Si el servidor se compromete, el
# atacante no puede "robar" el uso de tu clave para saltar a otros sistemas.


# ----------------------------------------------------------------------------
# 5. SESIÓN Y ROBUSTEZ
# ----------------------------------------------------------------------------

ClientAliveInterval 300
ClientAliveCountMax 2
# Cierra sesiones inactivas (300s x 2 = ~10 min sin respuesta -> desconexión).
# Evita sesiones abiertas y desatendidas que un tercero podría reutilizar.

TCPKeepAlive no
# Evita mantener vivas conexiones mediante keepalives de TCP (spoofables);
# el control de inactividad lo lleva ClientAlive*, que va cifrado.

UsePAM yes
# Integra PAM: habilita políticas del sistema (bloqueo de cuentas con faillock,
# caducidad de contraseñas...). Es el puente con el bastionado del SO (P2_8).


# ----------------------------------------------------------------------------
# 6. REGISTRO Y TRAZABILIDAD (clave para el SIEM / Blue Team)
# ----------------------------------------------------------------------------

LogLevel VERBOSE
# Registro detallado en /var/log/auth.log: incluye el FINGERPRINT de la clave
# usada en cada login. Imprescindible para investigar accesos y para alimentar
# el SIEM (enlaza con P6_4 rsyslog y la detección de fuerza bruta en P6_1).

#echo "AVISO: acceso restringido a usuarios autorizados. Actividad monitorizada." | sudo tee /etc/ssh/banner.txt
Banner /etc/ssh/banner.txt
# Muestra un aviso legal ANTES de autenticar (uso autorizado, monitorización).
# Requisito habitual de cumplimiento (ENS/ISO 27001). Crea el archivo con el texto.


# ----------------------------------------------------------------------------
# 7. CRIPTOGRAFÍA (algoritmos modernos)
# ----------------------------------------------------------------------------

# Restringe a algoritmos fuertes y descarta los débiles/heredados.
# (Descomentar tras verificar compatibilidad de tus clientes.)
# KexAlgorithms curve25519-sha256,curve25519-sha256@libssh.org
# Ciphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com
# MACs hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com
# Motivo: evita cifrados y MACs obsoletos susceptibles a ataques conocidos.


# ----------------------------------------------------------------------------
# 8. SUBSISTEMAS
# ----------------------------------------------------------------------------

Subsystem sftp internal-sftp
# SFTP interno (no invoca binario externo). Menor superficie que el sftp-server clásico.
