"""
Caracterización del dataset — figuras y tablas para la memoria.

Genera, sobre las secuencias ORIGINALES (sin aumentar):

  1. Resumen por clase: nº de capturas, longitudes, duración temporal
  2. Tabla de event_code por clase + análisis de exclusividad
  3. Diagnóstico de atajos: qué señales bastan para clasificar sin aprender
  4. Cobertura del fields_map y tasa de descarte
  5. Estadística de las features derivadas por clase
  6. Distribución de hosts y usuarios (detección de fuga por identidad)

Salidas:
  analisis/resumen.txt          -> todo el informe en texto
  analisis/event_codes.csv      -> tabla para el documento
  analisis/longitudes.csv
  analisis/features.csv

"""

import os
import csv
from collections import Counter, defaultdict

from Preprocesamiento_Logs.generate_dataset import (
    generate_train_dataset_raw, normalize_dataset
)
from Preprocesamiento_Logs.encode_event import ENGINEERED_FIELDS, MAX_SEQ_LEN
from Preprocesamiento_Logs.time_utils import parse_splunk_time
from Preprocesamiento_Logs.fields_map import event_fields_map

OUT_DIR = "analisis"
CLASS_NAMES = {0: "benigna", 1: "maliciosa"}


# =========================================================
# UTILIDADES
# =========================================================

class Informe:
    """Escribe simultáneamente en consola y en el fichero de texto."""

    def __init__(self, path):
        os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
        self.f = open(path, "w", encoding="utf-8")

    def __call__(self, line=""):
        print(line)
        self.f.write(str(line) + "\n")

    def seccion(self, titulo):
        self("")
        self("=" * 78)
        self(titulo)
        self("=" * 78)

    def close(self):
        self.f.close()


def _pct(n, total):
    return f"{100.0 * n / total:.1f}%" if total else "n/d"


def _stats(values):
    if not values:
        return None
    s = sorted(values)
    n = len(s)
    return {
        "n": n,
        "min": s[0],
        "p25": s[n // 4],
        "p50": s[n // 2],
        "p75": s[(3 * n) // 4],
        "max": s[-1],
        "media": sum(s) / n,
    }


def _duracion_segundos(sequence):
    """Duración temporal de una captura, en segundos."""
    times = [parse_splunk_time(l.get("timestamp")) for l in sequence]
    times = [t for t in times if t is not None]
    if len(times) < 2:
        return None
    return (max(times) - min(times)).total_seconds()


# =========================================================
# 1. RESUMEN POR CLASE
# =========================================================

def resumen_por_clase(dataset, rep):
    rep.seccion("1. RESUMEN DEL DATASET (capturas originales, sin aumentar)")

    filas = []
    for label in (0, 1):
        seqs = [s for s, l in dataset if l == label]
        lens = [len(s) for s in seqs]
        durs = [d for d in (_duracion_segundos(s) for s in seqs) if d is not None]

        st = _stats(lens)
        rep("")
        rep(f"Clase {label} ({CLASS_NAMES[label]}): {len(seqs)} capturas")
        if st:
            rep(f"  Longitud (nº de logs): min={st['min']}  p25={st['p25']}  "
                f"p50={st['p50']}  p75={st['p75']}  max={st['max']}  media={st['media']:.1f}")
            truncadas = sum(1 for x in lens if x > MAX_SEQ_LEN)
            rep(f"  Capturas que superan MAX_SEQ_LEN={MAX_SEQ_LEN}: "
                f"{truncadas} ({_pct(truncadas, len(lens))})")
        if durs:
            sd = _stats(durs)
            rep(f"  Duración (min): p50={sd['p50']/60:.1f}  "
                f"min={sd['min']/60:.1f}  max={sd['max']/60:.1f}")
            rep(f"  Densidad: {sum(lens)/max(sum(durs), 1):.2f} logs/segundo")

        for s in seqs:
            filas.append({
                "clase": CLASS_NAMES[label],
                "n_logs": len(s),
                "duracion_seg": round(_duracion_segundos(s) or 0, 1),
            })

    total = len(dataset)
    n_ben = sum(1 for _, l in dataset if l == 0)
    rep("")
    rep(f"TOTAL: {total} capturas  |  ratio benigna:maliciosa = 1:{(total-n_ben)/max(n_ben,1):.1f}")
    rep("")
    rep("[!] El desbalance y el nº de capturas benignas ORIGINALES son la")
    rep("    limitación principal: la augmentación multiplica muestras, no")
    rep("    comportamientos distintos.")

    _escribir_csv("longitudes.csv", filas, ["clase", "n_logs", "duracion_seg"])


# =========================================================
# 2. TABLA DE EVENT CODES
# =========================================================

def tabla_event_codes(dataset, rep):
    rep.seccion("2. DISTRIBUCIÓN DE EVENT CODES POR CLASE")

    # Frecuencia total y nº de capturas en las que aparece
    freq = {0: Counter(), 1: Counter()}
    docs = {0: Counter(), 1: Counter()}
    n_caps = {0: 0, 1: 0}

    for sequence, label in dataset:
        n_caps[label] += 1
        presentes = set()
        for log in sequence:
            code = log.get("event_code") or "?"
            freq[label][code] += 1
            presentes.add(code)
        for code in presentes:
            docs[label][code] += 1

    codes = sorted(set(freq[0]) | set(freq[1]), key=lambda c: (len(c), c))

    rep("")
    rep(f"{'code':<8} {'n_ben':>7} {'n_mal':>7} {'caps_ben':>9} {'caps_mal':>9} "
        f"{'cob_ben':>8} {'cob_mal':>8}  exclusivo")
    rep("-" * 78)

    filas, exclusivos_mal, exclusivos_ben = [], [], []

    for code in codes:
        nb, nm = freq[0][code], freq[1][code]
        cb, cm = docs[0][code], docs[1][code]
        cob_b = cb / max(n_caps[0], 1)
        cob_m = cm / max(n_caps[1], 1)

        if nb == 0 and nm > 0:
            marca = "SOLO MALICIOSA"
            exclusivos_mal.append((code, cm, cob_m))
        elif nm == 0 and nb > 0:
            marca = "solo benigna"
            exclusivos_ben.append((code, cb, cob_b))
        else:
            marca = ""

        rep(f"{code:<8} {nb:>7} {nm:>7} {cb:>9} {cm:>9} "
            f"{cob_b:>8.2f} {cob_m:>8.2f}  {marca}")

        filas.append({
            "event_code": code, "logs_benigna": nb, "logs_maliciosa": nm,
            "capturas_benigna": cb, "capturas_maliciosa": cm,
            "cobertura_benigna": round(cob_b, 3),
            "cobertura_maliciosa": round(cob_m, 3),
            "exclusivo": marca,
        })

    _escribir_csv("event_codes.csv", filas, list(filas[0].keys()) if filas else [])

    # ── Análisis de exclusividad ────────────────────────────
    rep("")
    rep("-" * 78)
    compartidos = [c for c in codes if freq[0][c] > 0 and freq[1][c] > 0]
    rep(f"Códigos distintos observados : {len(codes)}")
    rep(f"  presentes en ambas clases  : {len(compartidos)} ({_pct(len(compartidos), len(codes))})")
    rep(f"  exclusivos de maliciosa    : {len(exclusivos_mal)}")
    rep(f"  exclusivos de benigna      : {len(exclusivos_ben)}")

    rep("")
    rep("[!] Cuanto menor sea el solapamiento, más fácil le resulta al modelo")
    rep("    clasificar por PRESENCIA de un código en lugar de por el PATRÓN")
    rep("    secuencial. Un solapamiento bajo invalida la interpretación de")
    rep("    las métricas como capacidad de detección.")

    return exclusivos_mal, exclusivos_ben, n_caps


# =========================================================
# 3. DIAGNÓSTICO DE ATAJOS
# =========================================================

def diagnostico_atajos(dataset, exclusivos_mal, exclusivos_ben, n_caps, rep):
    rep.seccion("3. DIAGNÓSTICO DE ATAJOS DE CLASIFICACIÓN")

    rep("")
    rep("Reglas triviales que separan las clases sin aprendizaje secuencial.")
    rep("Si alguna alcanza cobertura alta, el resultado del modelo no puede")
    rep("atribuirse a la detección de comportamiento.")

    # 3.1 Un solo código exclusivo que cubra muchas capturas maliciosas
    rep("")
    rep("3.1 Regla 'presencia de un único event_code'")
    criticos = [(c, n, cob) for c, n, cob in exclusivos_mal if cob >= 0.5]
    if criticos:
        for code, n, cob in sorted(criticos, key=lambda x: -x[2]):
            rep(f"    [ATAJO] 'contiene {code}' -> maliciosa: "
                f"cubre {n}/{n_caps[1]} capturas maliciosas ({cob:.0%}), "
                f"0 benignas")
    else:
        rep("    Ningún código exclusivo cubre >=50% de una clase.")

    for code, n, cob in exclusivos_ben:
        if cob >= 0.5:
            rep(f"    [ATAJO] 'contiene {code}' -> benigna: "
                f"cubre {n}/{n_caps[0]} capturas benignas ({cob:.0%})")

    # 3.2 Longitud
    rep("")
    rep("3.2 Regla 'longitud de la secuencia'")
    lens = {l: sorted(len(s) for s, lab in dataset if lab == l) for l in (0, 1)}
    if lens[0] and lens[1]:
        if max(lens[0]) < min(lens[1]):
            rep(f"    [ATAJO] Todas las benignas (<={max(lens[0])} logs) son más "
                f"cortas que todas las maliciosas (>={min(lens[1])}).")
        elif max(lens[1]) < min(lens[0]):
            rep(f"    [ATAJO] Todas las maliciosas (<={max(lens[1])}) son más "
                f"cortas que todas las benignas (>={min(lens[0])}).")
        else:
            solape_min = max(min(lens[0]), min(lens[1]))
            solape_max = min(max(lens[0]), max(lens[1]))
            rep(f"    Rangos solapados en [{solape_min}, {solape_max}]. Sin atajo trivial.")

    # 3.3 Host y usuario
    rep("")
    rep("3.3 Regla 'identidad' (host / usuario / dominio)")
    for campo in ("host", "user", "user_domain", "dst_host"):
        vals = {l: set() for l in (0, 1)}
        for sequence, label in dataset:
            for log in sequence:
                v = log.get(campo)
                if v:
                    vals[label].add(str(v))
        solo_mal = vals[1] - vals[0]
        solo_ben = vals[0] - vals[1]
        comunes  = vals[0] & vals[1]
        estado = "OK" if comunes else "[ATAJO]"
        rep(f"    {campo:<12} comunes={len(comunes):<3} "
            f"solo_ben={len(solo_ben):<3} solo_mal={len(solo_mal):<3}  {estado}")
        if not comunes and (vals[0] or vals[1]):
            rep(f"                 -> sin valores compartidos: el campo "
                f"identifica la clase por sí solo")

    # 3.4 Ventana temporal
    rep("")
    rep("3.4 Regla 'fecha de captura'")
    dias = {l: set() for l in (0, 1)}
    for sequence, label in dataset:
        for log in sequence:
            dt = parse_splunk_time(log.get("timestamp"))
            if dt:
                dias[label].add(dt.date())
    comunes = dias[0] & dias[1]
    rep(f"    días con actividad benigna  : {len(dias[0])}")
    rep(f"    días con actividad maliciosa: {len(dias[1])}")
    rep(f"    días compartidos            : {len(comunes)}  "
        f"{'[ATAJO] la fecha separa las clases' if not comunes else 'OK'}")
    if not comunes:
        rep("                 -> encode_time() codifica día de la semana: el")
        rep("                    modelo puede clasificar por la fecha de captura")


# =========================================================
# 4. COBERTURA DEL FIELDS_MAP
# =========================================================

def cobertura_fields_map(dataset, rep):
    rep.seccion("4. COBERTURA DEL fields_map")

    mapeados = set()
    for events in event_fields_map.values():
        mapeados.update(str(c) for c in events)
    mapeados.add("4103")

    observados = set()
    for sequence, _ in dataset:
        for log in sequence:
            if log.get("event_code"):
                observados.add(str(log["event_code"]))

    usados = observados & mapeados
    rep("")
    rep(f"Eventos definidos en fields_map : {len(mapeados)}")
    rep(f"Eventos observados en el dataset: {len(observados)}")
    rep(f"Cobertura efectiva              : {len(usados)}/{len(mapeados)} "
        f"({_pct(len(usados), len(mapeados))})")

    sin_usar = sorted(mapeados - observados, key=lambda c: (len(c), c))
    if sin_usar:
        rep("")
        rep(f"Definidos pero nunca observados ({len(sin_usar)}):")
        rep("  " + ", ".join(sin_usar))

    huerfanos = observados - mapeados
    if huerfanos:
        rep("")
        rep(f"[!] Observados pero NO mapeados: {sorted(huerfanos)}")


# =========================================================
# 5. FEATURES DERIVADAS
# =========================================================

def analisis_features(dataset, rep):
    rep.seccion("5. FEATURES DERIVADAS (engineer_features)")

    activaciones = {0: defaultdict(int), 1: defaultdict(int)}
    totales = {0: 0, 1: 0}
    caps_con = {0: defaultdict(int), 1: defaultdict(int)}
    n_caps = {0: 0, 1: 0}

    for sequence, label in dataset:
        n_caps[label] += 1
        presentes = set()
        for log in sequence:
            totales[label] += 1
            for f in ENGINEERED_FIELDS:
                if float(log.get(f) or 0.0) > 0:
                    activaciones[label][f] += 1
                    presentes.add(f)
        for f in presentes:
            caps_con[label][f] += 1

    rep("")
    rep(f"{'feature':<32} {'%logs_ben':>10} {'%logs_mal':>10} "
        f"{'caps_ben':>9} {'caps_mal':>9}")
    rep("-" * 78)

    filas = []
    muertas, discriminantes = [], []

    for f in ENGINEERED_FIELDS:
        pb = 100.0 * activaciones[0][f] / max(totales[0], 1)
        pm = 100.0 * activaciones[1][f] / max(totales[1], 1)
        cb, cm = caps_con[0][f], caps_con[1][f]

        marca = ""
        if activaciones[0][f] == 0 and activaciones[1][f] == 0:
            marca = "NUNCA SE ACTIVA"
            muertas.append(f)
        elif cb == 0 and cm >= n_caps[1] * 0.5:
            marca = "solo maliciosa"
            discriminantes.append(f)

        rep(f"{f:<32} {pb:>9.2f}% {pm:>9.2f}% {cb:>9} {cm:>9}  {marca}")
        filas.append({
            "feature": f, "pct_logs_benigna": round(pb, 3),
            "pct_logs_maliciosa": round(pm, 3),
            "capturas_benigna": cb, "capturas_maliciosa": cm,
            "observacion": marca,
        })

    _escribir_csv("features.csv", filas, list(filas[0].keys()) if filas else [])

    if muertas:
        rep("")
        rep(f"[!] Features que nunca se activan ({len(muertas)}): {', '.join(muertas)}")
        rep("    Aportan solo dimensionalidad. Revisar su lógica o eliminarlas.")
    if discriminantes:
        rep("")
        rep(f"[!] Features presentes SOLO en maliciosas: {', '.join(discriminantes)}")
        rep("    Son atajos potenciales: el modelo puede reducirse a una regla.")


# =========================================================
# CSV
# =========================================================

def _escribir_csv(nombre, filas, campos):
    if not filas:
        return
    os.makedirs(OUT_DIR, exist_ok=True)
    path = os.path.join(OUT_DIR, nombre)
    with open(path, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=campos)
        w.writeheader()
        w.writerows(filas)
    print(f"  -> {path}")


# =========================================================
# MAIN
# =========================================================

def main():
    os.makedirs(OUT_DIR, exist_ok=True)
    rep = Informe(os.path.join(OUT_DIR, "resumen.txt"))

    rep("CARACTERIZACIÓN DEL DATASET")
    rep("Todas las cifras se calculan sobre las capturas ORIGINALES,")
    rep("antes de la augmentación.")

    dataset_raw = generate_train_dataset_raw()
    dataset = normalize_dataset(dataset_raw)
    dataset = [(s, l) for s, l in dataset if s]

    resumen_por_clase(dataset, rep)
    ex_mal, ex_ben, n_caps = tabla_event_codes(dataset, rep)
    diagnostico_atajos(dataset, ex_mal, ex_ben, n_caps, rep)
    cobertura_fields_map(dataset, rep)
    analisis_features(dataset, rep)

    rep.seccion("FIN")
    rep(f"Informe: {OUT_DIR}/resumen.txt")
    rep(f"Tablas : {OUT_DIR}/event_codes.csv, longitudes.csv, features.csv")
    rep.close()


if __name__ == "__main__":
    main()