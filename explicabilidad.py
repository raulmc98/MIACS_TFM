"""
Evaluación del componente de explicabilidad — sección 6.6 de la memoria.

Entrena un modelo con la configuración definitiva, lo aplica sobre sesiones
de validación no vistas y produce:

  1. Verificación del enmascaramiento
     Masa de atención asignada a los pasos de relleno. Con el enmascaramiento
     activo debe ser ~0; en caso contrario los pesos no son comparables entre
     sesiones de distinta longitud.

  2. Concentración de la atención
     Fracción de masa acumulada por los k eventos de mayor peso, contrastada
     con la que correspondería a una distribución uniforme. Una concentración
     próxima a la uniforme indicaría que el mecanismo no discrimina.

  3. Cronología explicativa
     Volcado de los eventos de mayor peso, reordenados temporalmente, con los
     campos significativos de cada uno. Es la salida operativa del sistema.

  4. Contraste benigna / maliciosa
     Sobre qué tipo de evento se concentra la atención en cada clase.

Salidas:
  analisis/explicabilidad.txt      informe completo
  analisis/atencion_resumen.csv    métricas por sesión
  analisis/cronologia_<n>.txt      cronologías individuales
"""

import os
import csv
import numpy as np
import tensorflow as tf
from collections import Counter

from sklearn.model_selection import StratifiedKFold
from sklearn.utils.class_weight import compute_class_weight
from tensorflow.keras.callbacks import EarlyStopping

from Preprocesamiento_Logs.generate_dataset import (
    generate_train_dataset_raw, normalize_dataset
)
from Preprocesamiento_Logs.data_augmentation import augment_dataset_raw
from Preprocesamiento_Logs.encode_event import (
    preprocess_dataset, sequence_to_matrices, truncate_sequence, MAX_SEQ_LEN
)
from Preprocesamiento_Logs.time_utils import sort_key
from modeloLSTM import build_model
from Preprocesamiento_Logs.fields_map import event_fields_map

from Preprocesamiento_Logs.encode_event import PAD_ID

OUT_DIR = "analisis"

# ── Configuración definitiva (debe coincidir con cross_validate.py) ──
N_VARIANTS  = 2
EPOCHS      = 80
BATCH_SIZE  = 8
PATIENCE    = 15
LSTM_UNITS  = 32
DROPOUT     = 0.5
LEARNING_RATE = 5e-4
SEED        = 42

TOP_N = 15          # eventos mostrados en la cronología
TOP_K = 5           # eventos para la métrica de concentración

# Campos mostrados en la cronología, por orden de interés
CAMPOS_CRONOLOGIA = [
    "timestamp", "event_code", "user", "user_domain", "host",
    "process_name", "parent_process_name", "command_line", "ps_cmdlet",
    "file_path", "registry_key", "target_process_name", "granted_access",
    "logon_type", "auth_package", "src_ip", "dst_host", "dst_port",
    "task_name", "service_name", "share_name", "target_user",
]

DESCRIPCION_EVENTOS = {
    "1": "Sysmon: creación de proceso",
    "3": "Sysmon: conexión de red",
    "7": "Sysmon: carga de imagen",
    "8": "Sysmon: hilo remoto",
    "10": "Sysmon: acceso a proceso",
    "11": "Sysmon: creación de fichero",
    "12": "Sysmon: creación/borrado de clave de registro",
    "13": "Sysmon: modificación de valor de registro",
    "22": "Sysmon: consulta DNS",
    "23": "Sysmon: borrado de fichero",
    "4103": "PowerShell: invocación de cmdlet",
    "4624": "Inicio de sesión correcto",
    "4625": "Inicio de sesión fallido",
    "4634": "Cierre de sesión",
    "4648": "Inicio de sesión con credenciales explícitas",
    "4672": "Privilegios especiales asignados",
    "4688": "Creación de proceso",
    "4720": "Cuenta de usuario creada",
    "4728": "Miembro añadido a grupo global",
    "4732": "Miembro añadido a grupo local",
    "4768": "Kerberos: ticket TGT solicitado",
    "4769": "Kerberos: ticket de servicio solicitado",
    "4798": "Enumeración de pertenencia a grupos locales",
    "5379": "Lectura de credenciales del almacén",
}


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


# =========================================================
# ALINEACIÓN SECUENCIA <-> PESOS
# =========================================================

def secuencia_alineada(sequence, max_len=MAX_SEQ_LEN):
    """
    Reproduce EXACTAMENTE la transformación del vectorizador:
    ordenación temporal + truncado cabeza/cola.
    Sin esto, weights[i] no corresponde a sequence[i].
    """
    return truncate_sequence(sorted(sequence, key=sort_key), max_len)


# =========================================================
# ENTRENAMIENTO
# =========================================================

def entrenar(train_raw, rep):
    train_aug = augment_dataset_raw(train_raw, n_variants=N_VARIANTS)
    train = normalize_dataset(train_aug)
    Xc, Xn, Xm, y = preprocess_dataset(train)

    classes = np.unique(y)
    weights = compute_class_weight("balanced", classes=classes, y=y)
    class_weight = {int(c): float(w) for c, w in zip(classes, weights)}

    model, attention_model = build_model(
        seq_len=Xc.shape[1], lstm_units=LSTM_UNITS, dropout=DROPOUT
    )
    model.compile(
        optimizer=tf.keras.optimizers.Adam(learning_rate=LEARNING_RATE),
        loss="binary_crossentropy",
        metrics=[tf.keras.metrics.AUC(name="auc")],
    )
    model.fit(
        [Xc, Xn, Xm], y,
        epochs=EPOCHS, batch_size=BATCH_SIZE,
        class_weight=class_weight,
        callbacks=[EarlyStopping(monitor="loss", mode="min",
                                 patience=PATIENCE, restore_best_weights=True)],
        verbose=0,
    )
    rep(f"Modelo entrenado sobre {len(train)} secuencias "
        f"({len(train_raw)} originales x {N_VARIANTS + 1})")
    return model, attention_model


# =========================================================
# ANÁLISIS DE UNA SESIÓN
# =========================================================

def analizar_sesion(model, attention_model, sequence, label, idx, rep,
                    max_len=MAX_SEQ_LEN, volcar=True):
    logs = secuencia_alineada(sequence, max_len)
    cat, num = sequence_to_matrices(sequence, max_len)
    msk = (cat[:, 0] != PAD_ID).astype(np.float32)
    cat, num, msk = cat[None, ...], num[None, ...], msk[None, ...]

    score = float(model.predict([cat, num, msk], verbose=0)[0][0])
    pesos = attention_model.predict([cat, num, msk], verbose=0)[0].ravel()

    n_real = len(logs)
    masa_relleno = float(pesos[n_real:].sum()) if n_real < max_len else 0.0
    pesos_reales = pesos[:n_real]

    # Concentración: top-K frente a la referencia uniforme
    orden_desc = np.argsort(pesos_reales)[::-1]
    top_k = float(pesos_reales[orden_desc[:TOP_K]].sum())
    uniforme_k = TOP_K / n_real
    ratio = top_k / uniforme_k if uniforme_k > 0 else float("nan")

    # Entropía normalizada: 1 = uniforme, 0 = toda la masa en un evento
    p = pesos_reales / max(pesos_reales.sum(), 1e-12)
    p = p[p > 0]
    entropia = float(-(p * np.log(p)).sum() / np.log(n_real)) if n_real > 1 else 0.0

    clase_real = "maliciosa" if label == 1 else "benigna"
    prediccion = "maliciosa" if score > 0.5 else "benigna"
    acierto = "OK" if (score > 0.5) == (label == 1) else "ERROR"

    rep("")
    rep("-" * 78)
    rep(f"SESIÓN {idx}  |  real: {clase_real}  |  predicha: {prediccion} "
        f"(score {score:.4f})  [{acierto}]")
    rep("-" * 78)
    rep(f"  Eventos reales / pasos totales : {n_real} / {max_len}")
    rep(f"  Masa de atención en relleno    : {masa_relleno:.6f}   "
        f"{'OK' if masa_relleno < 1e-3 else '[!] enmascaramiento defectuoso'}")
    rep(f"  Masa en los {TOP_K} eventos de mayor peso : {top_k:.4f}")
    rep(f"    referencia uniforme          : {uniforme_k:.4f}  "
        f"(concentración x{ratio:.1f})")
    rep(f"  Entropía normalizada           : {entropia:.4f}  "
        f"(1 = uniforme, 0 = concentración total)")

    # Distribución de la atención por tipo de evento
    masa_por_codigo = Counter()
    for i, log in enumerate(logs):
        masa_por_codigo[str(log.get("event_code"))] += float(pesos_reales[i])
    rep("")
    rep("  Masa de atención por event_code (5 principales):")
    for code, masa in masa_por_codigo.most_common(5):
        desc = DESCRIPCION_EVENTOS.get(code, "")
        rep(f"    {code:<6} {masa:>7.4f}  {desc}")

    cronologia = None
    if volcar:
        cronologia = volcar_cronologia(logs, pesos_reales, idx, score, rep)

    return {
        "sesion": idx,
        "clase_real": clase_real,
        "prediccion": prediccion,
        "score": round(score, 4),
        "acierto": acierto,
        "n_eventos": n_real,
        "masa_relleno": round(masa_relleno, 8),
        f"masa_top{TOP_K}": round(top_k, 4),
        "concentracion_x": round(ratio, 2),
        "entropia_norm": round(entropia, 4),
    }, cronologia


def volcar_cronologia(logs, pesos, idx, score, rep):
    """Eventos de mayor peso, REORDENADOS CRONOLÓGICAMENTE."""
    n = len(logs)
    top = np.argsort(pesos)[::-1][:min(TOP_N, n)]
    top_cronologico = sorted(top)

    lineas = []
    lineas.append(f"CRONOLOGÍA EXPLICATIVA — sesión {idx} (score {score:.4f})")
    lineas.append(f"Los {len(top_cronologico)} eventos de mayor peso de atención,")
    lineas.append("presentados en orden temporal.")
    lineas.append("")

    for rank, i in enumerate(top_cronologico, 1):
        log = logs[i]
        code = str(log.get("event_code", ""))
        desc = DESCRIPCION_EVENTOS.get(code, "")
        lineas.append(f"[{rank}] peso={pesos[i]:.4f}  paso={i}  "
                      f"evento {code}  {desc}")
        for campo in CAMPOS_CRONOLOGIA:
            v = log.get(campo)
            if v not in (None, "", "-", "N/A") and campo != "event_code":
                lineas.append(f"      {campo:<22}: {v}")
        lineas.append("")

    texto = "\n".join(lineas)

    os.makedirs(OUT_DIR, exist_ok=True)
    path = os.path.join(OUT_DIR, f"cronologia_{idx}.txt")
    with open(path, "w", encoding="utf-8") as f:
        f.write(texto)

    rep("")
    rep(f"  Cronología completa -> {path}")
    return texto


# =========================================================
# MAIN
# =========================================================

def main():
    os.makedirs(OUT_DIR, exist_ok=True)
    rep = Informe(os.path.join(OUT_DIR, "explicabilidad.txt"))

    rep("EVALUACIÓN DEL COMPONENTE DE EXPLICABILIDAD")
    rep("Sección 6.6 de la memoria.")
    rep("")
    rep(f"Configuración: N_VARIANTS={N_VARIANTS} EPOCHS={EPOCHS} "
        f"PATIENCE={PATIENCE} lstm_units={LSTM_UNITS} dropout={DROPOUT} "
        f"lr={LEARNING_RATE} MAX_SEQ_LEN={MAX_SEQ_LEN}")

    np.random.seed(SEED)
    tf.random.set_seed(SEED)

    dataset_raw = generate_train_dataset_raw()
    labels = np.array([l for _, l in dataset_raw])
    rep("")
    rep(f"Capturas: {len(dataset_raw)} "
        f"(benignas={int((labels==0).sum())}, maliciosas={int((labels==1).sum())})")

    # Una partición: se analiza sobre sesiones NO vistas en entrenamiento
    skf = StratifiedKFold(n_splits=5, shuffle=True, random_state=SEED)
    tr_idx, va_idx = next(skf.split(np.arange(len(dataset_raw)), labels))

    train_raw = [dataset_raw[i] for i in tr_idx]
    val_raw   = [dataset_raw[i] for i in va_idx]

    rep(f"Entrenamiento: {len(train_raw)} capturas | "
        f"Análisis: {len(val_raw)} capturas no vistas")

    rep.seccion("ENTRENAMIENTO")
    model, attention_model = entrenar(train_raw, rep)

    # Las sesiones de validación se normalizan SIN aumentar
    val = normalize_dataset(val_raw)
    val = [(s, l) for s, l in val if s]

    rep.seccion("ANÁLISIS POR SESIÓN")

    filas = []
    for i, (sequence, label) in enumerate(val, 1):
        fila, _ = analizar_sesion(
            model, attention_model, sequence, label, i, rep
        )
        filas.append(fila)

    # ── Síntesis ──────────────────────────────────────────
    rep.seccion("SÍNTESIS")

    masas = np.array([f["masa_relleno"] for f in filas])
    conc  = np.array([f["concentracion_x"] for f in filas])
    ent   = np.array([f["entropia_norm"] for f in filas])

    rep("")
    rep(f"Masa de atención en relleno : máx={masas.max():.8f}  "
        f"media={masas.mean():.8f}")
    if masas.max() < 1e-3:
        rep("  -> El enmascaramiento excluye efectivamente los pasos de relleno.")
        rep("     Los pesos son comparables entre sesiones de distinta longitud.")
    else:
        rep("  -> [!] El enmascaramiento NO está funcionando correctamente.")

    rep("")
    rep(f"Concentración top-{TOP_K} frente a uniforme : "
        f"x{conc.mean():.1f} ± {conc.std():.1f}")
    rep(f"Entropía normalizada                : "
        f"{ent.mean():.4f} ± {ent.std():.4f}")
    if ent.mean() < 0.95:
        rep("  -> La atención discrimina entre pasos temporales.")
    else:
        rep("  -> [!] Distribución próxima a la uniforme: el mecanismo apenas")
        rep("         discrimina y la decisión reside en el estado del LSTM.")

    # Contraste por clase
    rep("")
    for clase in ("benigna", "maliciosa"):
        sub = [f for f in filas if f["clase_real"] == clase]
        if sub:
            c = np.mean([f["concentracion_x"] for f in sub])
            e = np.mean([f["entropia_norm"] for f in sub])
            rep(f"  {clase:<10} concentración x{c:.1f}  entropía {e:.4f}  "
                f"(n={len(sub)})")

    # CSV
    path = os.path.join(OUT_DIR, "atencion_resumen.csv")
    with open(path, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=list(filas[0].keys()))
        w.writeheader()
        w.writerows(filas)

    rep("")
    rep(f"Informe     : {OUT_DIR}/explicabilidad.txt")
    rep(f"Resumen CSV : {path}")
    rep(f"Cronologías : {OUT_DIR}/cronologia_*.txt")
    rep.close()


if __name__ == "__main__":
    main()