#!/usr/bin/env python3
"""Analiza logs JSON de Cowrie y enriquece cada IP (país, región, ASN, DNS inverso).

Solo usa la librería estándar. Todo dato que no se pueda confirmar queda como
"no identificado": el script no rellena ni supone nada.

Uso:
    python scripts/analizar.py cowrie-2026-10-24
    python scripts/analizar.py cowrie-2026-10-24 --excluir <TU_IP>      # IP propia a ignorar

Busca ENTRADA/cowrie-2026-10-24.json (o .json.gz) y guarda el resultado
(analisis-<nombre>.json y .md) en SALIDA.
"""
import argparse
import gzip
import json
import os
import socket
import time
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path
from urllib.error import URLError
from urllib.request import Request, urlopen
from zoneinfo import ZoneInfo

# Zona horaria local: se lee de la variable de entorno HONEYPOT_TZ (nunca va en el código).
TZ_LOCAL = ZoneInfo(os.environ.get("HONEYPOT_TZ", "UTC"))
NO_ID = "no identificado"

# Ajusta estas dos rutas a tu estructura de carpetas.
ENTRADA = Path.home() / "honeypot" / "registros-del-dia"
SALIDA = Path.home() / "honeypot-analysis"


# ---------- Lectura ----------

def abrir(ruta):
    ruta = Path(ruta)
    if ruta.suffix == ".gz":
        return gzip.open(ruta, "rt", encoding="utf-8")
    return open(ruta, encoding="utf-8")


def leer_eventos(rutas):
    """Devuelve (lista de eventos, cantidad de líneas inválidas)."""
    eventos, malas = [], 0
    for ruta in rutas:
        with abrir(ruta) as f:
            for linea in f:
                linea = linea.strip()
                if not linea:
                    continue
                try:
                    eventos.append(json.loads(linea))
                except json.JSONDecodeError:
                    malas += 1
    return eventos, malas


def parse_ts(s):
    return datetime.fromisoformat(s.replace("Z", "+00:00"))


def fmt_hora(ts):
    """ISO UTC -> (texto UTC, texto local). None si no hay dato."""
    if not ts:
        return None, None
    dt = parse_ts(ts).astimezone(timezone.utc)
    return (dt.strftime("%Y-%m-%d %H:%M:%S UTC"),
            dt.astimezone(TZ_LOCAL).strftime("%Y-%m-%d %H:%M:%S"))


# ---------- Sesiones ----------

def construir_sesiones(eventos):
    sesiones = {}
    for e in eventos:
        sid = e.get("session")
        if not sid:
            continue
        ev, ts = e.get("eventid"), e.get("timestamp")
        s = sesiones.setdefault(sid, {
            "sesion": sid, "ip": e.get("src_ip"), "inicio": None,
            "duracion_ms": None, "version_cliente": None, "hassh": None,
            "handshake": False, "logins": [], "comandos": [], "descargas": [],
        })
        if s["inicio"] is None:
            s["inicio"] = ts  # respaldo si el log no trae el evento connect

        if ev == "cowrie.session.connect":
            s["inicio"] = ts
        elif ev == "cowrie.client.version":
            s["version_cliente"] = e.get("version")
            s["handshake"] = True
        elif ev == "cowrie.client.kex":
            s["hassh"] = e.get("hassh")
            s["handshake"] = True
        elif ev in ("cowrie.login.success", "cowrie.login.failed"):
            s["logins"].append({
                "hora": ts,
                "usuario": e.get("username"),
                "password": e.get("password"),  # None si fue intento con llave
                "llave_fingerprint": e.get("fingerprint"),
                "exito": ev.endswith("success"),
            })
        elif ev == "cowrie.command.input":
            s["comandos"].append(e.get("input"))
        elif ev == "cowrie.session.file_download":
            s["descargas"].append(e.get("url") or e.get("shasum"))
        elif ev == "cowrie.session.closed":
            s["duracion_ms"] = e.get("duration_ms")
    return sesiones


def clasificar(s):
    """Etiqueta basada solo en lo que se observó, sin interpretar intención."""
    if s["comandos"]:
        return "sesión con comandos"
    if s["logins"]:
        return "intento de login"
    if s["handshake"]:
        return "handshake SSH sin login"
    return "conexión sin handshake SSH"


# ---------- Enriquecimiento ----------

def consultar_ipinfo(ip):
    req = Request(f"https://ipinfo.io/{ip}/json",
                  headers={"User-Agent": "honeypot-analysis"})
    try:
        with urlopen(req, timeout=10) as r:
            return json.load(r)
    except (URLError, TimeoutError, ValueError, OSError) as err:
        return {"_error": str(err)}


def dns_inverso(ip):
    try:
        return socket.gethostbyaddr(ip)[0]
    except OSError:
        return None


def datos_red(ip, cache):
    if ip in cache:
        return cache[ip]
    raw = consultar_ipinfo(ip)
    if "_error" in raw:
        # No se guarda en caché: se reintenta en la próxima corrida.
        return {"pais": NO_ID, "region": NO_ID, "ciudad": NO_ID, "asn": NO_ID,
                "organizacion": NO_ID, "hostname_ipinfo": NO_ID,
                "dns_inverso": NO_ID, "zona_horaria": NO_ID,
                "fuente": "ipinfo.io", "error": raw["_error"]}
    asn, org = NO_ID, NO_ID
    texto = raw.get("org")
    if texto:
        partes = texto.split(" ", 1)
        if partes[0].startswith("AS"):
            asn = partes[0]
            org = partes[1] if len(partes) > 1 else NO_ID
        else:
            org = texto
    info = {
        "pais": raw.get("country") or NO_ID,
        "region": raw.get("region") or NO_ID,
        "ciudad": raw.get("city") or NO_ID,
        "asn": asn,
        "organizacion": org,
        "hostname_ipinfo": raw.get("hostname") or NO_ID,
        "dns_inverso": dns_inverso(ip) or NO_ID,
        "zona_horaria": raw.get("timezone") or NO_ID,
        "fuente": "ipinfo.io (geolocalización aproximada, no exacta)",
    }
    cache[ip] = info
    time.sleep(0.3)  # cortesía con el límite de la API gratuita
    return info


# ---------- Agregación ----------

def top(counter):
    return dict(counter.most_common())


def agregar_ip(ip, sesiones, cache):
    sesiones = sorted(sesiones, key=lambda s: s["inicio"] or "")
    tipos, usuarios, passwords, llaves = Counter(), Counter(), Counter(), Counter()
    versiones, hasshs, comandos = set(), set(), []
    detalle = []
    for s in sesiones:
        tipo = clasificar(s)
        tipos[tipo] += 1
        for l in s["logins"]:
            if l["usuario"]:
                usuarios[l["usuario"]] += 1
            if l["password"] is not None:
                passwords[l["password"]] += 1
            if l["llave_fingerprint"]:
                llaves[l["llave_fingerprint"]] += 1
        comandos.extend(s["comandos"])
        if s["version_cliente"]:
            versiones.add(s["version_cliente"])
        if s["hassh"]:
            hasshs.add(s["hassh"])
        utc, local = fmt_hora(s["inicio"])
        detalle.append({
            "sesion": s["sesion"], "inicio_utc": utc, "inicio_local": local,
            "duracion_ms": s["duracion_ms"], "tipo": tipo,
            "version_cliente": s["version_cliente"], "hassh": s["hassh"],
            "logins": s["logins"], "comandos": s["comandos"],
            "descargas": s["descargas"],
        })
    primera = fmt_hora(sesiones[0]["inicio"])
    ultima = fmt_hora(sesiones[-1]["inicio"])
    return {
        "ip": ip,
        "red": datos_red(ip, cache),
        "actividad": {
            "sesiones": len(sesiones),
            "primera_utc": primera[0], "primera_local": primera[1],
            "ultima_utc": ultima[0], "ultima_local": ultima[1],
            "tipos": top(tipos),
            "versiones_cliente": sorted(versiones) or NO_ID,
            "hassh": sorted(hasshs) or NO_ID,
            "usuarios": top(usuarios),
            "passwords": top(passwords),
            "llaves_fingerprint": top(llaves),
            "comandos": comandos,
        },
        "sesiones": detalle,
    }


def construir_reporte(sesiones, cache, archivos, excluidas, malas):
    por_ip = defaultdict(list)
    for s in sesiones.values():
        por_ip[s["ip"]].append(s)
    ips = [agregar_ip(ip, ss, cache) for ip, ss in por_ip.items()]
    ips.sort(key=lambda d: d["actividad"]["sesiones"], reverse=True)

    horas = Counter()
    tipos = Counter()
    for s in sesiones.values():
        tipos[clasificar(s)] += 1
        if s["inicio"]:
            h = parse_ts(s["inicio"]).astimezone(TZ_LOCAL).hour
            horas[f"{h:02d}h"] += 1

    notas = [
        f"Los campos '{NO_ID}' indican que la fuente no devolvió el dato; no se infirió nada.",
        "País, región y ciudad vienen de geolocalización por IP: son aproximados.",
        "Las etiquetas de tipo describen lo observado, no la intención del origen.",
        f"Horas locales según la zona configurada: {TZ_LOCAL.key}.",
    ]
    if malas:
        notas.append(f"Se ignoraron {malas} líneas que no eran JSON válido.")
    return {
        "generado": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC"),
        "archivos": [str(a) for a in archivos],
        "ips_excluidas": excluidas,
        "resumen": {
            "sesiones": len(sesiones),
            "ips_unicas": len(ips),
            "tipos": top(tipos),
            "paises": top(Counter(i["red"]["pais"] for i in ips)),
            "asn": top(Counter(f'{i["red"]["asn"]} {i["red"]["organizacion"]}' for i in ips)),
            "sesiones_por_hora_local": dict(sorted(horas.items())),
        },
        "ips": ips,
        "notas": notas,
    }


# ---------- Salida ----------

def imprimir(rep):
    r = rep["resumen"]
    print(f"\nSesiones: {r['sesiones']} | IPs únicas: {r['ips_unicas']}")
    print("Tipos:", r["tipos"])
    print("Países:", r["paises"])
    print("Sesiones por hora local:", r["sesiones_por_hora_local"])
    for i in rep["ips"]:
        n, a = i["red"], i["actividad"]
        print(f"\n{i['ip']}  ->  {n['pais']} / {n['region']} / {n['ciudad']}")
        print(f"  {n['asn']} {n['organizacion']}  (DNS inverso: {n['dns_inverso']})")
        print(f"  {a['sesiones']} sesión(es), {a['primera_local']} a {a['ultima_local']} (local)")
        print(f"  tipos: {a['tipos']}")
        if a["usuarios"]:
            print(f"  usuarios: {a['usuarios']}  passwords: {a['passwords']}")
        if a["comandos"]:
            print(f"  comandos: {a['comandos']}")
        if "error" in n:
            print(f"  (consulta de red falló: {n['error']})")


def a_markdown(rep):
    r = rep["resumen"]
    L = [f"# Análisis Cowrie ({rep['generado']})", "",
         f"- Archivos: {', '.join(rep['archivos'])}",
         f"- IPs excluidas: {', '.join(rep['ips_excluidas']) or 'ninguna'}",
         f"- Sesiones: {r['sesiones']} | IPs únicas: {r['ips_unicas']}", "",
         "## Resumen", "",
         f"- Tipos: {r['tipos']}",
         f"- Países: {r['paises']}",
         f"- ASN: {r['asn']}",
         f"- Sesiones por hora local: {r['sesiones_por_hora_local']}", "",
         "## Por IP", ""]
    for i in rep["ips"]:
        n, a = i["red"], i["actividad"]
        L += [f"### {i['ip']}", "",
              f"- Ubicación: {n['pais']} / {n['region']} / {n['ciudad']} (aprox.)",
              f"- Red: {n['asn']} {n['organizacion']}",
              f"- DNS inverso: {n['dns_inverso']} | hostname ipinfo: {n['hostname_ipinfo']}",
              f"- Sesiones: {a['sesiones']} ({a['primera_local']} a {a['ultima_local']}, hora local)",
              f"- Tipos: {a['tipos']}",
              f"- Versión de cliente: {a['versiones_cliente']}",
              f"- HASSH: {a['hassh']}",
              f"- Usuarios: {a['usuarios'] or NO_ID} | Passwords: {a['passwords'] or NO_ID}",
              f"- Comandos: {a['comandos'] or 'ninguno'}", ""]
    L += ["## Notas", ""] + [f"- {n}" for n in rep["notas"]]
    return "\n".join(L) + "\n"


def resolver_entrada(nombre, base):
    """Devuelve (nombre base, lista de archivos).

    Acepta un archivo (con o sin extensión), una ruta, o una carpeta con logs.
    """
    base = Path(base)
    candidatos = [Path(nombre), base / nombre,
                  base / f"{nombre}.json", base / f"{nombre}.json.gz"]
    for c in candidatos:
        if c.is_file():
            return c.name.removesuffix(".gz").removesuffix(".json"), [c]
        if c.is_dir():
            archivos = sorted(p for p in c.iterdir()
                              if p.name.endswith((".json", ".json.gz")))
            if archivos:
                return c.name, archivos
    raise SystemExit(f"No encontré '{nombre}' en {base} "
                     "(probé archivo .json, .json.gz y carpeta).")


def main():
    ap = argparse.ArgumentParser(description="Analiza un log de Cowrie.")
    ap.add_argument("paquete", help="archivo dentro de ENTRADA, ej. cowrie-2026-10-24")
    ap.add_argument("--excluir", nargs="*", default=[], help="IPs propias a ignorar")
    ap.add_argument("--entrada", default=str(ENTRADA), help="carpeta que contiene los paquetes")
    ap.add_argument("--salida", default=str(SALIDA),
                    help="carpeta de salida (fuera del repo, contiene IPs)")
    args = ap.parse_args()

    nombre, archivos = resolver_entrada(args.paquete, args.entrada)
    salida = Path(args.salida)
    salida.mkdir(parents=True, exist_ok=True)
    ruta_cache = salida / "cache_ips.json"
    cache = json.loads(ruta_cache.read_text()) if ruta_cache.exists() else {}

    eventos, malas = leer_eventos(archivos)
    sesiones = {k: v for k, v in construir_sesiones(eventos).items()
                if v["ip"] not in args.excluir}
    if not sesiones:
        print("No hay sesiones para analizar (¿todo era de IPs excluidas?).")
        return

    rep = construir_reporte(sesiones, cache, archivos, args.excluir, malas)
    ruta_cache.write_text(json.dumps(cache, indent=2, ensure_ascii=False))

    (salida / f"analisis-{nombre}.json").write_text(
        json.dumps(rep, indent=2, ensure_ascii=False))
    (salida / f"analisis-{nombre}.md").write_text(a_markdown(rep))

    imprimir(rep)
    print(f"\nGuardado en {salida}/analisis-{nombre}.json y .md")


if __name__ == "__main__":
    main()
