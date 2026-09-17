#!/bin/bash
# =============================================================================
#  cortafuegos1.sh  ·  Firewall de host SIN ESTADO (stateless)
#  Autor: Iván Muñoz Hernández  ·  Práctica P5_3 (iptables)
# -----------------------------------------------------------------------------
#  Idea: iptables evalúa cada paquete de forma AISLADA. No sabe si un paquete
#  pertenece a una conexión ya autorizada, así que hay que permitir de forma
#  explícita la IDA y la VUELTA de cada servicio (dos reglas por servicio).
#
#  Ejecutar SIEMPRE desde la consola local de la máquina, NO por SSH:
#  la política DROP cortaría tu propia sesión y te dejaría fuera.
# =============================================================================

IPT=/sbin/iptables

# --- 1. Limpieza: borrar reglas, cadenas de usuario y contadores -------------
$IPT -F          # Flush: elimina todas las reglas de todas las cadenas
$IPT -X          # Borra cadenas definidas por el usuario
$IPT -Z          # Pone a cero los contadores de paquetes/bytes

# --- 2. Políticas por defecto: denegar por defecto (enfoque restrictivo) -----
$IPT -P INPUT   DROP   # Todo lo que entra se descarta salvo regla explícita
$IPT -P OUTPUT  DROP   # Todo lo que sale se descarta salvo regla explícita
$IPT -P FORWARD DROP   # No enrutamos tráfico de terceros

# --- 3. Tráfico de loopback (procesos locales que se comunican entre sí) ------
$IPT -A INPUT  -i lo -j ACCEPT
$IPT -A OUTPUT -o lo -j ACCEPT

# --- 4. SSH (tcp/22): se abre la IDA y la VUELTA por separado -----------------
$IPT -A INPUT  -p tcp --dport 22 -j ACCEPT   # Llega la petición a este host
$IPT -A OUTPUT -p tcp --sport 22 -j ACCEPT   # Sale la respuesta hacia el cliente

# --- 5. Web (tcp/80): de nuevo, dos reglas -----------------------------------
$IPT -A INPUT  -p tcp --dport 80 -j ACCEPT
$IPT -A OUTPUT -p tcp --sport 80 -j ACCEPT

# --- 6. Ping (ICMP): permitido en ambos sentidos -----------------------------
$IPT -A INPUT  -p icmp -j ACCEPT
$IPT -A OUTPUT -p icmp -j ACCEPT

# -----------------------------------------------------------------------------
#  PUNTO DE DOLOR (lo que este script demuestra):
#  6 reglas para solo 3 servicios, y aún sin permitir que ESTE host navegue.
#  Para un simple 'apt update' habría que añadir reglas de salida al destino
#  Y de entrada desde los puertos altos aleatorios (efímeros) del retorno.
#  Frágil y difícil de mantener -> lo resuelve el modelo CON estado.
# =============================================================================
