#!/bin/bash
# =============================================================================
#  cortafuegos2.sh  ·  Firewall de host CON ESTADO (stateful / conntrack)
#  Autor: Iván Muñoz Hernández  ·  Práctica P5_3 (iptables)
# -----------------------------------------------------------------------------
#  Idea: el módulo conntrack mantiene una TABLA DE CONEXIONES. Cada paquete se
#  clasifica según su estado:
#     NEW         -> primer paquete, alguien inicia una conexión
#     ESTABLISHED -> pertenece a una conexión ya autorizada
#     RELATED     -> conexión nueva pero asociada a otra válida (p.ej. ICMP de
#                    error de una conexión TCP, canal de datos de FTP...)
#  Basta autorizar el INICIO (NEW); el retorno lo cubre una única regla
#  ESTABLISHED,RELATED por cadena. Menos reglas y más seguro.
#
#  Ejecutar SIEMPRE desde la consola local, NO por SSH.
# =============================================================================

IPT=/sbin/iptables

# --- 1. Limpieza -------------------------------------------------------------
$IPT -F
$IPT -X
$IPT -Z

# --- 2. Políticas por defecto: denegar por defecto ---------------------------
$IPT -P INPUT   DROP
$IPT -P OUTPUT  DROP
$IPT -P FORWARD DROP

# --- 3. Loopback -------------------------------------------------------------
$IPT -A INPUT  -i lo -j ACCEPT
$IPT -A OUTPUT -o lo -j ACCEPT

# --- 4. *** REGLA CLAVE: retorno de conexiones ya autorizadas *** ------------
#  Una sola regla por cadena sustituye a TODAS las reglas de "vuelta" del
#  script sin estado. Permite el tráfico que casa con una conexión existente.
$IPT -A INPUT  -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
$IPT -A OUTPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT

# --- 5. Solo el INICIO (NEW) de los servicios que ofrece este host -----------
$IPT -A INPUT -p tcp  --dport 22 -m conntrack --ctstate NEW -j ACCEPT   # SSH
$IPT -A INPUT -p tcp  --dport 80 -m conntrack --ctstate NEW -j ACCEPT   # Web
$IPT -A INPUT -p icmp --icmp-type echo-request \
             -m conntrack --ctstate NEW -j ACCEPT                        # ping

# --- 6. Permitir que ESTE host inicie salidas (apt, dns, ping...) ------------
#  Una sola regla. El retorno ya está cubierto por la regla ESTABLISHED (paso 4).
$IPT -A OUTPUT -m conntrack --ctstate NEW -j ACCEPT

# -----------------------------------------------------------------------------
#  RESULTADO: mismo comportamiento que cortafuegos1.sh, con menos reglas, más
#  fácil de mantener y MÁS SEGURO: los paquetes de respuesta "sueltos" que no
#  correspondan a ninguna conexión de la tabla conntrack se descartan.
# =============================================================================
