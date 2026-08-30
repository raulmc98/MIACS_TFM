"""
Líneas base para la sección 6.4 de la memoria.

Produce dos tablas:

  TABLA 3 — Reglas triviales de referencia
    Reglas que no requieren modelado alguno:
      - presencia de un event_code exclusivo de una clase
      - umbral sobre la longitud de la sesión
      - umbral sobre la duración y la densidad temporal
      - presencia de un valor de identidad exclusivo (host/user/dominio)
      - activación de un indicador derivado
    Si alguna iguala el rendimiento del LSTM, el modelo no aporta
    capacidad discriminante sobre este conjunto de datos.

  TABLA 4 — Línea base no secuencial
    Regresión logística sobre características AGREGADAS por sesión
    (frecuencias de event_code, medias de los indicadores derivados,
    longitud y duración). Descarta por completo el orden temporal.
    Cuantifica la contribución real del modelado secuencial, que es la
    premisa central del trabajo.

Ambas evaluaciones usan validación cruzada estratificada sobre las
CAPTURAS ORIGINALES, para ser comparables con cross_validate.py.

No requiere TensorFlow.

Uso:
    python -m Preprocesamiento_Logs.baselines
"""

import os
import csv
import numpy as np
from collections import Counter

from sklearn.linear_model import LogisticRegression
from sklearn.dummy import DummyClassifier
from sklearn.pipeline import make_pipeline
from sklearn.preprocessing import StandardScaler
from sklearn.model_selection import StratifiedKFold
from sklearn.metrics import (
    precision_recall_fscore_support, roc_auc_score,
    confusion_matrix, accuracy_score
)

from Preprocesamiento_Logs.generate_dataset import (
    generate_train_dataset_raw, normalize_dataset
)
from Preprocesamiento_Logs.encode_event import ENGINEERED_FIELDS
from Preprocesamiento_Logs.time_utils import parse_splunk_time

OUT_DIR = "analisis"
SEED = 42
N_SPLITS_DESEADOS = 5


# =========================================================
# INFORME
# =========================================================

class Informe:
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


def _escribir_csv(nombre, filas):
    if not filas:
        return
    os.makedirs(OUT_DIR, exist_ok=True)
    path = os.path.join(OUT_DIR, nombre)
    with open(path, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=list(filas[0].keys()))
        w.writeheader()
        w.writerows(filas)
    print(f"  -> {path}")


def _metricas(y_true, y_pred, y_score=None):
    """Métricas macro, para no favorecer a la clase mayoritaria."""
    p, r, f1, _ = precision_recall_fscore_support(
        y_true, y_pred, average="macro", zero_division=0
    )
    out = {
        "accuracy": accuracy_score(y_true, y_pred),
        "precision": p, "recall": r, "f1": f1,
    }
    if y_score is not None and len(set(y_true)) > 1:
        out["auc"] = roc_auc_score(y_true, y_score)
    else:
        out["auc"] = float("nan")
    return out


def _resolve_n_splits(labels, deseados=N_SPLITS_DESEADOS):
    minoritaria = min(Counter(labels).values())
    n = min(deseados, minoritaria)
    if n < 2:
        raise ValueError(
            f"La clase minoritaria tiene {minoritaria} captura(s): "
            f"no es posible la validación cruzada."
        )
    return n


# =========================================================
# CARACTERÍSTICAS AGREGADAS POR SESIÓN
# =========================================================

def _duracion(sequence):
    times = [parse_splunk_time(l.get("timestamp")) for l in sequence]
    times = [t for t in times if t is not None]
    if len(times) < 2:
        return 0.0
    return (max(times) - min(times)).total_seconds()


def construir_matriz_agregada(dataset, codes_vocab=None):
    """
    Representación SIN ORDEN: cada sesión es un vector de
      - frecuencia relativa de cada event_code
      - media de cada indicador derivado
      - longitud, duración y densidad
    """
    if codes_vocab is None:
        codes = set()
        for sequence, _ in dataset:
            for log in sequence:
                if log.get("event_code"):
                    codes.add(str(log["event_code"]))
        codes_vocab = sorted(codes, key=lambda c: (len(c), c))

    nombres = (
        [f"freq_{c}" for c in codes_vocab] +
        [f"mean_{f}" for f in ENGINEERED_FIELDS] +
        ["n_logs", "duracion_seg", "densidad"]
    )

    X, y = [], []
    for sequence, label in dataset:
        n = max(len(sequence), 1)
        conteo = Counter(str(l.get("event_code")) for l in sequence)
        fila = [conteo.get(c, 0) / n for c in codes_vocab]

        for f in ENGINEERED_FIELDS:
            fila.append(sum(float(l.get(f) or 0.0) for l in sequence) / n)

        dur = _duracion(sequence)
        fila.extend([len(sequence), dur, len(sequence) / max(dur, 1.0)])

        X.append(fila)
        y.append(label)

    return np.array(X, dtype=np.float64), np.array(y), nombres, codes_vocab


# =========================================================
# TABLA 3 — REGLAS TRIVIALES
# =========================================================

def _evaluar_regla(dataset, funcion):
    """Aplica una regla determinista. Devuelve (y_true, y_pred)."""
    y_true = np.array([l for _, l in dataset])
    y_pred = np.array([int(bool(funcion(s))) for s, _ in dataset])
    return y_true, y_pred


def reglas_triviales(dataset, rep):
    rep.seccion("TABLA 3 — REGLAS TRIVIALES DE REFERENCIA")
    rep("")
    rep("Reglas deterministas que no requieren modelado. Se evalúan sobre")
    rep("el conjunto completo: cualquier rendimiento alto aquí implica que")
    rep("las clases son separables sin aprender el patrón secuencial.")

    y = np.array([l for _, l in dataset])
    n_mal = int((y == 1).sum())
    n_ben = int((y == 0).sum())

    reglas = []

    # ── 0. Clasificador mayoritario (suelo de referencia) ─────────────
    reglas.append((
        "Mayoritaria (predecir siempre la clase más frecuente)",
        lambda s: 1 if n_mal >= n_ben else 0
    ))

    # ── 1. Presencia de un event_code exclusivo ───────────────────────
    presencia = {0: Counter(), 1: Counter()}
    for sequence, label in dataset:
        for c in set(str(l.get("event_code")) for l in sequence):
            presencia[label][c] += 1

    todos = set(presencia[0]) | set(presencia[1])
    candidatos = []
    for c in todos:
        cb, cm = presencia[0][c], presencia[1][c]
        if cb == 0 and cm > 0:
            candidatos.append((c, cm / max(n_mal, 1), 1))   # -> maliciosa
        elif cm == 0 and cb > 0:
            candidatos.append((c, cb / max(n_ben, 1), 0))   # -> benigna
    candidatos.sort(key=lambda x: -x[1])

    for code, cobertura, clase in candidatos[:5]:
        destino = "maliciosa" if clase == 1 else "benigna"
        reglas.append((
            f"Contiene event_code {code} -> {destino} (cobertura {cobertura:.0%})",
            (lambda c, cl: (lambda s: cl if any(
                str(l.get("event_code")) == c for l in s) else 1 - cl))(code, clase)
        ))

    # ── 2. Umbral de longitud ─────────────────────────────────────────
    lens = sorted(set(len(s) for s, _ in dataset))
    mejor_len, mejor_f1 = None, -1.0
    for umbral in lens:
        yt, yp = _evaluar_regla(dataset, lambda s, u=umbral: len(s) >= u)
        f1 = _metricas(yt, yp)["f1"]
        if f1 > mejor_f1:
            mejor_f1, mejor_len = f1, umbral
    reglas.append((
        f"Longitud >= {mejor_len} logs -> maliciosa (mejor umbral)",
        lambda s, u=mejor_len: len(s) >= u
    ))

    # ── 3. Umbral de densidad temporal ────────────────────────────────
    dens = []
    for sequence, _ in dataset:
        d = _duracion(sequence)
        dens.append(len(sequence) / max(d, 1.0))
    mejor_d, mejor_f1d = None, -1.0
    for u in sorted(set(dens)):
        yt, yp = _evaluar_regla(
            dataset,
            lambda s, u=u: len(s) / max(_duracion(s), 1.0) >= u
        )
        f1 = _metricas(yt, yp)["f1"]
        if f1 > mejor_f1d:
            mejor_f1d, mejor_d = f1, u
    reglas.append((
        f"Densidad >= {mejor_d:.2f} logs/s -> maliciosa (mejor umbral)",
        lambda s, u=mejor_d: len(s) / max(_duracion(s), 1.0) >= u
    ))

    # ── 4. Identidad exclusiva ────────────────────────────────────────
    for campo in ("host", "user", "user_domain"):
        vals = {0: set(), 1: set()}
        for sequence, label in dataset:
            for log in sequence:
                if log.get(campo):
                    vals[label].add(str(log[campo]))
        solo_mal = vals[1] - vals[0]
        if solo_mal:
            reglas.append((
                f"Contiene {campo} exclusivo de maliciosa "
                f"({len(solo_mal)} valor/es) -> maliciosa",
                (lambda c, v: (lambda s: any(
                    str(l.get(c)) in v for l in s)))(campo, solo_mal)
            ))

    # ── 5. Indicador derivado activo ──────────────────────────────────
    for feat in ENGINEERED_FIELDS:
        caps = {0: 0, 1: 0}
        for sequence, label in dataset:
            if any(float(l.get(feat) or 0.0) > 0 for l in sequence):
                caps[label] += 1
        if caps[0] == 0 and caps[1] >= max(n_mal * 0.5, 1):
            reglas.append((
                f"Indicador '{feat}' activo -> maliciosa "
                f"(cobertura {caps[1]/max(n_mal,1):.0%})",
                (lambda f: (lambda s: any(
                    float(l.get(f) or 0.0) > 0 for l in s)))(feat)
            ))

    # ── Evaluación ────────────────────────────────────────────────────
    rep("")
    rep(f"{'regla':<62} {'acc':>6} {'prec':>6} {'rec':>6} {'F1':>6}")
    rep("-" * 78)

    filas = []
    for nombre, fn in reglas:
        yt, yp = _evaluar_regla(dataset, fn)
        m = _metricas(yt, yp)
        etiqueta = nombre if len(nombre) <= 60 else nombre[:57] + "..."
        rep(f"{etiqueta:<62} {m['accuracy']:>6.3f} {m['precision']:>6.3f} "
            f"{m['recall']:>6.3f} {m['f1']:>6.3f}")
        filas.append({
            "regla": nombre,
            "accuracy": round(m["accuracy"], 4),
            "precision": round(m["precision"], 4),
            "recall": round(m["recall"], 4),
            "f1": round(m["f1"], 4),
        })

    _escribir_csv("tabla3_reglas_triviales.csv", filas)

    mejor = max(filas[1:], key=lambda r: r["f1"]) if len(filas) > 1 else None
    if mejor:
        rep("")
        rep(f"[!] Mejor regla trivial: F1 = {mejor['f1']:.3f}")
        rep(f"    {mejor['regla']}")
        rep("")
        rep("    Si el LSTM no supera claramente esta cifra, su capacidad")
        rep("    discriminante sobre este conjunto no es atribuible al")
        rep("    modelado secuencial.")

    return filas


# =========================================================
# TABLA 4 — LÍNEA BASE NO SECUENCIAL
# =========================================================

def linea_base(dataset, rep):
    rep.seccion("TABLA 4 — LÍNEA BASE NO SECUENCIAL (regresión logística)")
    rep("")
    rep("Características agregadas por sesión: frecuencias de event_code,")
    rep("medias de los indicadores derivados, longitud, duración y densidad.")
    rep("Esta representación DESCARTA el orden temporal por completo.")

    X, y, nombres, codes_vocab = construir_matriz_agregada(dataset)
    rep("")
    rep(f"Matriz: {X.shape[0]} sesiones x {X.shape[1]} características")
    rep(f"  {len(codes_vocab)} frecuencias de event_code")
    rep(f"  {len(ENGINEERED_FIELDS)} indicadores derivados")
    rep(f"  3 características de volumen/tiempo")

    n_splits = _resolve_n_splits(y)
    if n_splits < N_SPLITS_DESEADOS:
        rep(f"\n[aviso] folds reducidos a {n_splits} por la clase minoritaria")

    skf = StratifiedKFold(n_splits=n_splits, shuffle=True, random_state=SEED)

    modelos = {
        "Mayoritaria": DummyClassifier(strategy="most_frequent"),
        "Regresión logística": make_pipeline(
            StandardScaler(),
            LogisticRegression(
                max_iter=2000, class_weight="balanced",
                C=0.1, random_state=SEED
            )
        ),
    }

    rep("")
    rep(f"{'modelo':<24} {'acc':>7} {'prec':>7} {'rec':>7} {'F1':>7} {'AUC':>7}")
    rep("-" * 78)

    filas = []
    resultados = {}

    for nombre, modelo in modelos.items():
        yt_all, yp_all, ys_all = [], [], []
        por_fold = []

        for tr, va in skf.split(X, y):
            modelo.fit(X[tr], y[tr])
            yp = modelo.predict(X[va])
            try:
                ys = modelo.predict_proba(X[va])[:, 1]
            except (AttributeError, IndexError):
                ys = yp.astype(float)

            yt_all.append(y[va]); yp_all.append(yp); ys_all.append(ys)
            por_fold.append(_metricas(y[va], yp, ys))

        yt = np.concatenate(yt_all)
        yp = np.concatenate(yp_all)
        ys = np.concatenate(ys_all)
        m = _metricas(yt, yp, ys)
        resultados[nombre] = (yt, yp, ys, m, por_fold)

        rep(f"{nombre:<24} {m['accuracy']:>7.3f} {m['precision']:>7.3f} "
            f"{m['recall']:>7.3f} {m['f1']:>7.3f} {m['auc']:>7.3f}")

        # Desviación entre folds
        f1s = np.array([f["f1"] for f in por_fold])
        rep(f"{'':<24} F1 por fold: {f1s.mean():.3f} ± {f1s.std():.3f}  "
            f"({', '.join(f'{v:.2f}' for v in f1s)})")

        filas.append({
            "modelo": nombre,
            "accuracy": round(m["accuracy"], 4),
            "precision": round(m["precision"], 4),
            "recall": round(m["recall"], 4),
            "f1": round(m["f1"], 4),
            "auc": round(m["auc"], 4),
            "f1_media_folds": round(float(f1s.mean()), 4),
            "f1_desv_folds": round(float(f1s.std()), 4),
        })

    _escribir_csv("tabla4_linea_base.csv", filas)

    # Matriz de confusión del modelo lineal
    yt, yp, _, m, _ = resultados["Regresión logística"]
    rep("")
    rep("Matriz de confusión (regresión logística, out-of-fold):")
    rep("           pred_ben  pred_mal")
    cm = confusion_matrix(yt, yp)
    for i, fila in enumerate(cm):
        etq = "real_ben" if i == 0 else "real_mal"
        rep(f"  {etq}  {fila[0]:>8}  {fila[1]:>8}")

    # ── Características más influyentes ───────────────────────────────
    modelo = modelos["Regresión logística"]
    modelo.fit(X, y)
    coef = modelo[-1].coef_[0]
    orden = np.argsort(np.abs(coef))[::-1][:15]

    rep("")
    rep("Características de mayor peso (|coeficiente|):")
    rep(f"  {'característica':<32} {'coef':>9}  orienta a")
    rep("  " + "-" * 60)
    for i in orden:
        destino = "maliciosa" if coef[i] > 0 else "benigna"
        rep(f"  {nombres[i]:<32} {coef[i]:>9.3f}  {destino}")

    rep("")
    rep("[!] Si un modelo lineal SIN información de orden alcanza el mismo")
    rep("    rendimiento que el LSTM, la premisa de que la señal reside en")
    rep("    la secuencia no queda respaldada por este conjunto de datos.")

    return filas


# =========================================================
# MAIN
# =========================================================

def main():
    os.makedirs(OUT_DIR, exist_ok=True)
    rep = Informe(os.path.join(OUT_DIR, "baselines.txt"))

    rep("LÍNEAS BASE — sección 6.4 de la memoria")
    rep("Todas las cifras se calculan sobre las capturas ORIGINALES,")
    rep("sin aumentación, con métricas macro para no favorecer a la")
    rep("clase mayoritaria.")

    dataset_raw = generate_train_dataset_raw()
    dataset = normalize_dataset(dataset_raw)
    dataset = [(s, l) for s, l in dataset if s]

    y = [l for _, l in dataset]
    rep("")
    rep(f"Capturas: {len(dataset)} "
        f"(benignas={y.count(0)}, maliciosas={y.count(1)})")

    reglas_triviales(dataset, rep)
    linea_base(dataset, rep)

    rep.seccion("FIN")
    rep(f"Informe: {OUT_DIR}/baselines.txt")
    rep(f"Tablas : {OUT_DIR}/tabla3_reglas_triviales.csv, "
        f"tabla4_linea_base.csv")
    rep.close()


if __name__ == "__main__":
    main()