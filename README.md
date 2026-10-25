# Honeypot SSH y web en un VPS

Proyecto personal de ciberseguridad: desplegar un honeypot en un VPS expuesto a internet, recolectar los intentos de ataque durante ~3 semanas y documentar los hallazgos.

> **Estado:** en curso (24 oct - 15 nov 2026). Ver [reportes](reports/).

## Objetivo

Observar y documentar qué intentan los atacantes contra un servidor expuesto (SSH y, más adelante, web) sin poner en riesgo nada real.

## Preguntas a responder

1. ¿Qué usuarios y contraseñas se prueban más?
2. ¿De dónde vienen los intentos (países, ASN)?
3. ¿Qué comandos ejecutan si "entran"?
4. ¿Qué rutas web buscan?

## Arquitectura

```
Internet
   │
   ├── :22      ──► Docker (red honeynet, sin salida) ──► Cowrie  (señuelo SSH)
   ├── :40222   ──► SSH real (solo llave, sin contraseña)
   ├── :80/443  ──► (fase 2) contenedor con página señuelo
   └── :25565   ──► Servidor DB

Host ──(cron diario)──► script de resumen ──► Telegram (resumen + logs .gz)
```

- **VPS:** 2 vCPU, 8 GB RAM, Ubuntu.
- **Honeypot SSH:** [Cowrie](https://github.com/cowrie/cowrie) en contenedor sin root, sin capacidades, sistema de archivos de solo lectura y límites de memoria y procesos.
- **Administración:** SSH real en un puerto alterno, solo con llave.
- **Logs:** el script corre en el host (no dentro del contenedor), así el token del bot no queda al alcance de un atacante.

## Modelo de amenaza

| Riesgo | Mitigación |
|---|---|
| Que el honeypot se use como trampolín contra terceros | Regla de `iptables` que bloquea conexiones nuevas hacia afuera desde la red del señuelo ([config](config/honeynet-block.service)) |
| Que un atacante salte del contenedor al host | Sin root, sin capacidades, sin volúmenes del host, `no-new-privileges` |
| Que ataquen mi acceso real | SSH real en otro puerto, solo con llave, sin login por contraseña |
| Que un atacante borre los logs | Resumen y archivo diario enviados fuera del servidor |
| Credenciales filtradas | Token en archivo con permisos `600`, fuera del repo (`.gitignore`) |

## Estructura del repo

```
.
├── README.md
├── config/
│   └── honeynet-block.service   # regla persistente de bloqueo de salida
├── scripts/
│   └── honeypot_report.py       # resumen diario a Telegram
└── reports/
    └── 2026-10-24.md            # reporte diario / semanal
```

## Calendario

| Fechas | Fase | Estado |
|---|---|---|
| 24-25 oct | Diseño | Hecho |
| 26-28 oct | Montaje (SSH, firewall, Cowrie, bloqueo de salida) | Adelantado: terminado el 24 oct |
| 29-31 oct | Bot de Telegram y pruebas | Adelantado: terminado el 24 oct |
| 1 nov | Checkpoint con primeros datos | Pendiente |
| 2-8 nov | Recolección + página señuelo | Pendiente |
| 9-12 nov | Análisis de datos y gráficas | Pendiente |
| 13-14 nov | Reporte final | Pendiente |
| 15 nov | Cierre y apagado | Pendiente |

## Ética y alcance

- Solo se ataca/observa infraestructura propia, con datos totalmente inventados.
- No se publican IPs de atacantes ni logs crudos: solo estadísticas agregadas.
- No hay credenciales, tokens ni IPs del servidor real en este repositorio.

## Reportes

- [2026-10-24: montaje y puesta en marcha](reports/2026-10-24.md)
