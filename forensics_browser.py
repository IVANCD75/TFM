"""Análisis de historial de navegadores Chromium-based (Chrome/Edge/Brave)."""
import os
import re
import sqlite3
import tempfile
import urllib.parse
from datetime import datetime, timedelta

import pytsk3

from utils import get_logger

log = get_logger()


# Rutas estándar de bases de datos History por navegador
_BROWSER_PATHS = {
    "Chrome":   "AppData/Local/Google/Chrome/User Data/Default/History",
    "Edge":     "AppData/Local/Microsoft/Edge/User Data/Default/History",
    "Brave":    "AppData/Local/BraveSoftware/Brave-Browser/User Data/Default/History",
    "Opera":    "AppData/Roaming/Opera Software/Opera Stable/History",
}


# Motores de búsqueda y sus parámetros de query
_SEARCH_ENGINES = [
    ("google.com",       "q"),
    ("google.es",        "q"),
    ("google.co",        "q"),
    ("bing.com",         "q"),
    ("duckduckgo.com",   "q"),
    ("yahoo.com",        "p"),
    ("yandex.",          "text"),
    ("baidu.com",        "wd"),
    ("ecosia.org",       "q"),
    ("startpage.com",    "query"),
    ("brave.com/search", "q"),
    ("search.brave.com", "q"),
    ("qwant.com",        "q"),
]


def _chrome_time_to_dt(chrome_ts):
    """Convierte timestamp Chrome (microsegundos desde 1601) a datetime."""
    if not chrome_ts:
        return None
    try:
        return datetime(1601, 1, 1) + timedelta(microseconds=chrome_ts)
    except (OverflowError, ValueError, OSError) as e:
        log.debug("Timestamp Chrome inválido (%r): %s", chrome_ts, e)
        return None


def _extraer_archivo(fs, path_en_imagen, dest_dir):
    """Extrae un archivo de la imagen forense a un tempfile en disco real."""
    try:
        f = fs.open(path_en_imagen)
        size = f.info.meta.size
        if size <= 0 or size > 500 * 1024 * 1024:  # techo 500 MB
            return None

        out_path = os.path.join(dest_dir, os.path.basename(path_en_imagen))
        with open(out_path, "wb") as out:
            offset = 0
            chunk = 4 * 1024 * 1024
            while offset < size:
                data = f.read_random(offset, min(chunk, size - offset))
                if not data:
                    break
                out.write(data)
                offset += len(data)
        return out_path
    except Exception as e:
        log.debug("No se pudo extraer '%s': %s", path_en_imagen, e)
        return None


def _detectar_motor_busqueda(url):
    """Si la URL es de un motor de búsqueda, devuelve (motor, keyword)."""
    if not url:
        return None, None
    try:
        parsed = urllib.parse.urlparse(url)
        host = parsed.netloc.lower()
        for engine, param in _SEARCH_ENGINES:
            if engine in host:
                # Probar query string y fragment (Google #q=)
                qs = urllib.parse.parse_qs(parsed.query)
                if param in qs and qs[param][0].strip():
                    return engine, qs[param][0]
                # En fragment: "#q=palabras"
                if parsed.fragment:
                    fqs = urllib.parse.parse_qs(parsed.fragment)
                    if param in fqs and fqs[param][0].strip():
                        return engine, fqs[param][0]
        return None, None
    except Exception as e:
        log.debug("URL no parseable para motor de búsqueda: %s", e)
        return None, None


def _analizar_history_db(db_path, navegador, usuario, limite_urls=2000):
    """Lee la base de datos History de un navegador Chromium-based."""
    urls = []
    keywords = []
    downloads = []

    try:
        # uri con read-only para no modificar
        conn = sqlite3.connect(f"file:{db_path}?mode=ro&immutable=1", uri=True)
        cur = conn.cursor()

        # URLs y visitas
        try:
            cur.execute(
                """SELECT url, title, visit_count, last_visit_time
                   FROM urls
                   ORDER BY last_visit_time DESC
                   LIMIT ?""",
                (limite_urls,),
            )
            for url, title, vc, lvt in cur.fetchall():
                dt = _chrome_time_to_dt(lvt)
                urls.append({
                    "Usuario": usuario,
                    "Navegador": navegador,
                    "URL": url,
                    "Título": (title or "")[:200],
                    "Visitas": vc,
                    "Última Visita": dt,
                })

                # Detectar búsqueda
                engine, keyword = _detectar_motor_busqueda(url)
                if keyword:
                    keywords.append({
                        "Usuario": usuario,
                        "Navegador": navegador,
                        "Buscador": engine,
                        "Término": keyword.strip(),
                        "Última Búsqueda": dt,
                        "Visitas": vc,
                    })
        except Exception as e:
            log.debug("No se pudo leer la tabla 'urls' de %s: %s", db_path, e)

        # Descargas
        try:
            cur.execute(
                """SELECT target_path, tab_url, start_time, total_bytes
                   FROM downloads
                   ORDER BY start_time DESC
                   LIMIT 200"""
            )
            for tp, tab, st_, total in cur.fetchall():
                downloads.append({
                    "Usuario": usuario,
                    "Navegador": navegador,
                    "Archivo": tp or "",
                    "URL Origen": (tab or "")[:200],
                    "Tamaño (bytes)": total or 0,
                    "Inicio": _chrome_time_to_dt(st_),
                })
        except Exception as e:
            log.debug("No se pudo leer la tabla 'downloads' de %s: %s", db_path, e)

        conn.close()
    except Exception as e:
        log.warning("No se pudo abrir la BD de historial '%s': %s", db_path, e)

    return urls, keywords, downloads


def _consolidar_keywords(keywords):
    """Agrupa términos repetidos sumando visitas."""
    agg = {}
    for kw in keywords:
        key = (kw["Usuario"], kw["Buscador"], kw["Término"].lower())
        if key not in agg:
            agg[key] = dict(kw)
        else:
            agg[key]["Visitas"] = max(agg[key]["Visitas"], kw["Visitas"])
            # Quedarnos con la fecha más reciente
            if kw["Última Búsqueda"] and (
                not agg[key]["Última Búsqueda"]
                or kw["Última Búsqueda"] > agg[key]["Última Búsqueda"]
            ):
                agg[key]["Última Búsqueda"] = kw["Última Búsqueda"]
    return sorted(
        agg.values(),
        key=lambda x: x["Última Búsqueda"] or datetime.min,
        reverse=True,
    )


def extraer_navegacion(fs):
    """Extrae historial, búsquedas y descargas de todos los navegadores."""
    todas_urls = []
    todas_kw = []
    todas_dl = []

    tmpdir = tempfile.mkdtemp(prefix="tfm_browser_")

    try:
        # Iterar /Users/<user>/<browser>/History
        try:
            users_dir = fs.open_dir("/Users")
        except Exception as e:
            log.info("No se pudo abrir /Users para navegación: %s", e)
            return {"urls": [], "keywords": [], "downloads": []}

        for entry in users_dir:
            try:
                name = entry.info.name.name
                if isinstance(name, bytes):
                    name = name.decode("utf-8", errors="ignore")
                if name in (".", "..", "Public", "Default", "Default User",
                            "All Users", "desktop.ini"):
                    continue
                if not (entry.info.meta
                        and entry.info.meta.type == pytsk3.TSK_FS_META_TYPE_DIR):
                    continue

                for nav, rel in _BROWSER_PATHS.items():
                    full = f"/Users/{name}/{rel}"
                    db_path = _extraer_archivo(fs, full, tmpdir)
                    if db_path:
                        u, k, d = _analizar_history_db(db_path, nav, name)
                        todas_urls.extend(u)
                        todas_kw.extend(k)
                        todas_dl.extend(d)
            except Exception as e:
                log.debug("Usuario de navegación ilegible: %s", e)
                continue
    finally:
        # Limpieza
        try:
            for f in os.listdir(tmpdir):
                try:
                    os.unlink(os.path.join(tmpdir, f))
                except OSError as e:
                    log.debug("No se pudo borrar temp de navegador: %s", e)
            os.rmdir(tmpdir)
        except OSError as e:
            log.debug("No se pudo limpiar el tmpdir de navegación: %s", e)

    # Ordenar URLs por fecha desc
    todas_urls.sort(key=lambda x: x["Última Visita"] or datetime.min, reverse=True)
    todas_dl.sort(key=lambda x: x["Inicio"] or datetime.min, reverse=True)

    return {
        "urls": todas_urls,
        "keywords": _consolidar_keywords(todas_kw),
        "downloads": todas_dl,
    }
