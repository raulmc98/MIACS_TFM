"""
Validación cruzada estratificada y contraste por permutación de etiquetas.

-----------
La partición se realiza sobre las capturas ORIGINALES, antes de aumentar. La
aumentación se aplica DENTRO de cada partición y únicamente al subconjunto de
entrenamiento, de modo que las variantes de una misma captura nunca cruzan la
frontera entrenamiento/validación. De lo contrario la métrica mediría la
capacidad de reconocer copias casi idénticas a las observadas.

El subconjunto de validación no se aumenta: se evalúa sobre las capturas reales.

No se emplea un conjunto de prueba independiente. Con 28 capturas, reservarlo
reduciría el entrenamiento sin ganar poder estadístico, mientras que la
validación cruzada evalúa cada sesión exactamente una vez sobre un modelo que
no la observó.

"""

import sys
import random
import numpy as np
import tensorflow as tf
from collections import Counter

from sklearn.model_selection import StratifiedKFold
from sklearn.metrics import (
    classification_report, confusion_matrix, roc_auc_score,
    precision_recall_fscore_support, average_precision_score
)
from sklearn.utils.class_weight import compute_class_weight
from tensorflow.keras.callbacks import EarlyStopping

from Preprocesamiento_Logs.generate_dataset import (
    generate_train_dataset_raw, normalize_dataset
)
from Preprocesamiento_Logs.data_augmentation import augment_dataset_raw
from Preprocesamiento_Logs.encode_event import preprocess_dataset, MAX_SEQ_LEN
from modeloLSTM import build_model


# =========================================================
# CONFIGURACIÓN
# =========================================================
# Configuración definitiva. Debe coincidir con explicabilidad.py: si se
# modifica aquí, las secciones de resultados y de explicabilidad dejarían de
# referirse al mismo modelo.

N_SPLITS_DESEADOS = 5
N_VARIANTS        = 2
EPOCHS            = 80
BATCH_SIZE        = 8
PATIENCE          = 15
LEARNING_RATE     = 5e-4
LSTM_UNITS        = 32
DROPOUT           = 0.5
THRESHOLD         = 0.5
SEED              = 42


def _resolve_n_splits(labels, deseados=N_SPLITS_DESEADOS):
    """StratifiedKFold exige n_splits <= muestras de la clase minoritaria."""
    minoritaria = min(Counter(labels).values())
    n = min(deseados, minoritaria)
    if n < deseados:
        print(f"[aviso] clase minoritaria con {minoritaria} secuencias: "
              f"se reducen las particiones de {deseados} a {n}")
    if n < 2:
        raise ValueError(
            f"Imposible realizar validación cruzada: la clase minoritaria "
            f"tiene {minoritaria} secuencia(s). Se necesitan al menos 2."
        )
    return n


def _reset_seeds(seed):
    np.random.seed(seed)
    tf.random.set_seed(seed)
    random.seed(seed)


# =========================================================
# UNA PARTICIÓN
# =========================================================

def run_fold(train_raw, val_raw, fold_idx, verbose=0):
    _reset_seeds(SEED + fold_idx)

    # Aumentación SOLO del entrenamiento de esta partición
    train_aug = augment_dataset_raw(train_raw, n_variants=N_VARIANTS)

    # Normalización: recalcula los indicadores derivados sobre cada variante
    train = normalize_dataset(train_aug)
    val   = normalize_dataset(val_raw)          # sin aumentar

    Xc_tr, Xn_tr, Xm_tr, y_tr = preprocess_dataset(train)
    Xc_va, Xn_va, Xm_va, y_va = preprocess_dataset(val)

    # Ponderación de clases: sin ella el modelo tiende a predecir la mayoritaria
    classes = np.unique(y_tr)
    weights = compute_class_weight("balanced", classes=classes, y=y_tr)
    class_weight = {int(c): float(w) for c, w in zip(classes, weights)}

    model, attention_model = build_model(
        seq_len=Xc_tr.shape[1], lstm_units=LSTM_UNITS, dropout=DROPOUT
    )
    model.compile(
        optimizer=tf.keras.optimizers.Adam(learning_rate=LEARNING_RATE),
        loss="binary_crossentropy",
        metrics=[tf.keras.metrics.AUC(name="auc")],
    )

    # Se monitoriza la pérdida de ENTRENAMIENTO, no la de validación: usar
    # esta última para seleccionar pesos y después reportar sobre ella
    # inflaría la métrica.
    early_stop = EarlyStopping(
        monitor="loss", mode="min", patience=PATIENCE,
        restore_best_weights=True
    )

    model.fit(
        [Xc_tr, Xn_tr, Xm_tr], y_tr,
        epochs=EPOCHS,
        batch_size=BATCH_SIZE,
        class_weight=class_weight,
        callbacks=[early_stop],
        verbose=verbose,
    )

    y_prob = model.predict([Xc_va, Xn_va, Xm_va], verbose=0).ravel()
    y_pred = (y_prob > THRESHOLD).astype(int)

    return y_va.astype(int), y_prob, y_pred, model, attention_model


# =========================================================
# VALIDACIÓN CRUZADA
# =========================================================

def cross_validate(verbose_fit=0):
    dataset_raw = generate_train_dataset_raw()
    labels = np.array([label for _, label in dataset_raw])

    print(f"\nCapturas originales: {len(dataset_raw)} "
          f"(benignas={int((labels == 0).sum())}, "
          f"maliciosas={int((labels == 1).sum())})")

    n_splits = _resolve_n_splits(labels)
    skf = StratifiedKFold(n_splits=n_splits, shuffle=True, random_state=SEED)

    indices = np.arange(len(dataset_raw))
    all_true, all_prob, all_pred = [], [], []
    per_fold = []

    for fold_idx, (tr_idx, va_idx) in enumerate(skf.split(indices, labels), 1):
        train_raw = [dataset_raw[i] for i in tr_idx]
        val_raw   = [dataset_raw[i] for i in va_idx]

        n_ben = sum(1 for _, l in val_raw if l == 0)
        n_mal = sum(1 for _, l in val_raw if l == 1)
        print(f"\n{'=' * 60}")
        print(f"PARTICIÓN {fold_idx}/{n_splits}  "
              f"entrenamiento={len(train_raw)} originales -> "
              f"{len(train_raw) * (N_VARIANTS + 1)} aumentadas | "
              f"validación={len(val_raw)} (ben={n_ben}, mal={n_mal})")

        y_true, y_prob, y_pred, _, _ = run_fold(
            train_raw, val_raw, fold_idx, verbose=verbose_fit
        )

        all_true.append(y_true)
        all_prob.append(y_prob)
        all_pred.append(y_pred)

        p, r, f1, _ = precision_recall_fscore_support(
            y_true, y_pred, average="macro", zero_division=0
        )
        # El AUC solo tiene sentido si la partición contiene ambas clases
        auc = roc_auc_score(y_true, y_prob) if len(set(y_true)) > 1 else float("nan")

        per_fold.append({"precision": p, "recall": r, "f1": f1, "auc": auc})
        print(f"  precision={p:.3f}  recall={r:.3f}  f1={f1:.3f}  auc={auc:.3f}")
        for i, (t, pr) in enumerate(zip(y_true, y_prob)):
            print(f"    val[{i}] real={t}  score={pr:.4f}")

    # ── Resumen ────────────────────────────────────────────
    print(f"\n{'=' * 60}\nRESUMEN ({n_splits} particiones)\n{'=' * 60}")
    for metric in ("precision", "recall", "f1", "auc"):
        vals = np.array([f[metric] for f in per_fold], dtype=float)
        vals = vals[~np.isnan(vals)]
        if len(vals) == 0:
            print(f"  {metric:<10}: n/d")
            continue
        print(f"  {metric:<10}: {vals.mean():.3f} ± {vals.std():.3f}   "
              f"({', '.join(f'{v:.3f}' for v in vals)})")

    # Cada captura original aparece exactamente una vez como validación,
    # de modo que el agregado cubre el conjunto completo.
    y_true_all = np.concatenate(all_true)
    y_prob_all = np.concatenate(all_prob)
    y_pred_all = np.concatenate(all_pred)

    print(f"\n{'-' * 60}\nAGREGADO OUT-OF-FOLD (n={len(y_true_all)})\n{'-' * 60}")
    print(confusion_matrix(y_true_all, y_pred_all))
    print(classification_report(
        y_true_all, y_pred_all,
        target_names=["benigna", "maliciosa"],
        digits=3, zero_division=0
    ))
    if len(set(y_true_all)) > 1:
        print(f"  ROC-AUC           : {roc_auc_score(y_true_all, y_prob_all):.3f}")
        print(f"  PR-AUC (avg prec) : {average_precision_score(y_true_all, y_prob_all):.3f}")

    # Distribución de puntuaciones: separación real o saturación
    ben = y_prob_all[y_true_all == 0]
    mal = y_prob_all[y_true_all == 1]
    print(f"\n  scores benignas  : min={ben.min():.4f} "
          f"media={ben.mean():.4f} max={ben.max():.4f}")
    print(f"  scores maliciosas: min={mal.min():.4f} "
          f"media={mal.mean():.4f} max={mal.max():.4f}")

    return y_true_all, y_prob_all, per_fold


# =========================================================
# CONTRASTE POR PERMUTACIÓN
# =========================================================

def permutation_test(n_repeats=3):
    """
    Repite la validación cruzada con las etiquetas permutadas al azar.

    Un sistema que aprenda el comportamiento debe degradarse hasta un AUC
    próximo a 0,5. Un valor superior indicaría que explota atributos
    correlacionados con la etiqueta por construcción del conjunto y no por
    relación causal con la actividad.
    """
    dataset_raw = generate_train_dataset_raw()
    aucs = []

    for rep in range(n_repeats):
        rng = np.random.RandomState(SEED + rep)
        labels = np.array([l for _, l in dataset_raw])
        shuffled = rng.permutation(labels)
        shuffled_raw = [(seq, int(lab))
                        for (seq, _), lab in zip(dataset_raw, shuffled)]

        n_splits = _resolve_n_splits(shuffled)
        skf = StratifiedKFold(n_splits=n_splits, shuffle=True, random_state=SEED)
        idx = np.arange(len(shuffled_raw))

        t, p = [], []
        for fold_idx, (tr, va) in enumerate(skf.split(idx, shuffled), 1):
            print(f"  permutación {rep + 1}, partición {fold_idx}/{n_splits}...",
                  flush=True)
            yt, yp, _, _, _ = run_fold(
                [shuffled_raw[i] for i in tr],
                [shuffled_raw[i] for i in va],
                fold_idx,
            )
            t.append(yt)
            p.append(yp)

        t, p = np.concatenate(t), np.concatenate(p)
        auc = roc_auc_score(t, p) if len(set(t)) > 1 else float("nan")
        aucs.append(auc)
        print(f"  permutación {rep + 1}: AUC={auc:.3f}")

    print(f"\nAUC con etiquetas permutadas: "
          f"{np.nanmean(aucs):.3f} ± {np.nanstd(aucs):.3f}")
    print("Un valor alejado de 0,5 indicaría fuga en el conjunto de datos.")
    return aucs


# =========================================================

if __name__ == "__main__":
    print(f"MAX_SEQ_LEN = {MAX_SEQ_LEN}")

    if "--permutacion" in sys.argv:
        permutation_test(n_repeats=3)
    else:
        cross_validate(verbose_fit=0)