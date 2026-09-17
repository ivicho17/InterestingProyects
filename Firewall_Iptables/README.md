# Firewall de red con iptables — sin estado vs con estado

**Autor:** Iván Muñoz Hernández
**Práctica:** P5_3 · Configuración de firewall con iptables

## Objetivo

Comparar un firewall **sin estado** (*stateless*) frente a uno **con estado**
(*stateful*, basado en `conntrack`), implementando ambos con `iptables` y
demostrando por qué el modelo con estado es más seguro y mantenible.

## Conceptos clave

- **iptables / netfilter:** filtrado de paquetes en el kernel de Linux mediante
  reglas organizadas en cadenas (`INPUT`, `OUTPUT`, `FORWARD`).
- **Firewall sin estado:** evalúa cada paquete de forma aislada. Obliga a
  autorizar explícitamente la ida y la vuelta de cada conexión.
- **Firewall con estado (`conntrack`):** mantiene una tabla de conexiones y
  clasifica cada paquete como `NEW`, `ESTABLISHED` o `RELATED`. Basta permitir
  el inicio (`NEW`); el retorno lo cubre una sola regla `ESTABLISHED,RELATED`.

## Comparativa

| Aspecto | Sin estado (cortafuegos1.sh) | Con estado (cortafuegos2.sh) |
|---|---|---|
| Unidad de decisión | Paquete individual | Conexión completa |
| Tráfico de retorno | Regla explícita por servicio (ida + vuelta) | Una regla `ESTABLISHED,RELATED` lo cubre todo |
| Nº de reglas | Alto (crece con cada servicio) | Bajo y estable |
| Salida del propio host | Requiere abrir puertos efímeros del retorno | Una regla `OUTPUT NEW` |
| Seguridad | Puede colar paquetes de respuesta falsificados "sueltos" | Descarta paquetes que no casen con una conexión válida |
| Mantenibilidad | Frágil, propenso a errores | Clara y escalable |

## Topología

- **Ubuntu:** actúa como firewall de host y ofrece los servicios SSH (22),
  Web (80) e ICMP.
- **Kali:** cliente que accede a esos servicios.

> **Nota sobre la práctica original:** el enunciado usa un **router Ubuntu** que
> enruta entre dos redes (comercio e informática) y filtra en la cadena
> `FORWARD`. El concepto es idéntico: sin estado hay que autorizar el tráfico
> enrutado en ambos sentidos; con estado, las reglas `NEW` de ida en `FORWARD`
> más una única regla `FORWARD ... ESTABLISHED,RELATED` cubren el retorno.
> Este entregable lo reproduce sobre las cadenas `INPUT`/`OUTPUT` por usar un
> laboratorio de 2 máquinas.

## Ejecución

Ejecutar **desde la consola local de Ubuntu** (no por SSH, para no cortar la
propia sesión con la política `DROP`):

```bash
chmod +x cortafuegos1.sh cortafuegos2.sh
sudo ./cortafuegos1.sh      # versión sin estado
sudo iptables -L -v -n      # observar las reglas
# ... pruebas ...
sudo ./cortafuegos2.sh      # versión con estado
sudo iptables -L -v -n      # observar cuántas reglas menos
```

### Verificación (desde Kali)

```bash
ping -c2 IP_SERVIDOR
curl http://IP_SERVIDOR
ssh alumno@IP_SERVIDOR
```

### Observar el estado en vivo

```bash
sudo apt install -y conntrack
sudo conntrack -E
# lanzar una conexión desde Kali y ver NEW -> ESTABLISHED en tiempo real
```

### Botón de pánico (restaurar acceso)

```bash
sudo iptables -F && sudo iptables -P INPUT ACCEPT && sudo iptables -P OUTPUT ACCEPT
```

## Nota de producción: persistencia

Las reglas de `iptables` se pierden al reiniciar. En un entorno real se
persisten con:

```bash
sudo apt install -y iptables-persistent
sudo netfilter-persistent save
```

## Qué demuestra este entregable (enfoque Blue Team)

Comprender el modelo con estado es la base para diseñar reglas de firewall
correctas y para **detectar tráfico anómalo**: paquetes que no corresponden a
ninguna conexión válida, o conexiones salientes inesperadas, son indicadores
que un analista de seguridad investiga. La tabla `conntrack` es, además, una
fuente de telemetría útil para monitorización y respuesta a incidentes.
