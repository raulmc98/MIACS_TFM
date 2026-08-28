import re
from datetime import datetime, timezone

_OFFSET_RE = re.compile(r'([+-]\d{2})(\d{2})$')


def parse_splunk_time(value):
    """Devuelve un datetime timezone-aware, o None si no se puede parsear."""
    if not value:
        return None

    s = str(value).strip()
    if s in ("", "-", "N/A", "None"):
        return None

    # 2026-07-27T16:14:07.200+0200  ->  ...+02:00
    s = _OFFSET_RE.sub(r'\1:\2', s)
    # 'Z' no lo acepta fromisoformat antes de 3.11
    if s.endswith("Z"):
        s = s[:-1] + "+00:00"

    try:
        dt = datetime.fromisoformat(s)
    except ValueError:
        # Formato Sysmon UtcTime: "2026-07-27 16:14:07.200"
        for fmt in ("%Y-%m-%d %H:%M:%S.%f", "%Y-%m-%d %H:%M:%S"):
            try:
                dt = datetime.strptime(s, fmt).replace(tzinfo=timezone.utc)
                break
            except ValueError:
                continue
        else:
            return None

    # Naive -> asumimos UTC para poder comparar y restar sin errores
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)

    return dt


def format_splunk_time(dt) -> str:
    """Serializa de vuelta al formato de Splunk (offset sin dos puntos)."""
    s = dt.isoformat()
    return _OFFSET_RE.sub(r'\1\2', s.replace("+00:00", "+0000"))


def sort_key(log: dict, field: str = "timestamp"):
    """Clave de ordenación segura: los logs sin fecha van al final."""
    dt = parse_splunk_time(log.get(field))
    return (dt is None, dt or datetime.max.replace(tzinfo=timezone.utc))