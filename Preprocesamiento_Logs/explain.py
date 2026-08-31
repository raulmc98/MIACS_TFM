"""Inspección de los pesos de atención."""

import numpy as np
from Preprocesamiento_Logs.encode_event import (
    sequence_to_matrices, truncate_sequence, MAX_SEQ_LEN
)
from Preprocesamiento_Logs.time_utils import sort_key


def aligned_sequence(sequence, max_len=MAX_SEQ_LEN):
    """
    Reproduce exactamente la transformación que aplica el vectorizador:
    ordenar por tiempo y truncar cabeza+cola.
    Sin esto, weights[i] no corresponde a sequence[i].
    """
    return truncate_sequence(sorted(sequence, key=sort_key), max_len)


def explain_sequence(model, attention_model, sequence, top_n=15, max_len=MAX_SEQ_LEN):
    logs = aligned_sequence(sequence, max_len)
    cat, num = sequence_to_matrices(sequence, max_len)
    cat = cat[None, ...]
    num = num[None, ...]

    score   = float(model.predict([cat, num], verbose=0)[0][0])
    weights = attention_model.predict([cat, num], verbose=0)[0].ravel()

    n_real = len(logs)
    real_w = weights[:n_real]

    print(f"\nScore: {score:.4f}  ->  {'MALICIOSA' if score > 0.5 else 'BENIGNA'}")
    print(f"Logs reales: {n_real} / {max_len}")
    # Control de sanidad: con el masking correcto esto debe ser ~0
    print(f"Peso total en padding: {weights[n_real:].sum():.6f}")
    print(f"Peso concentrado en el top-5: {np.sort(real_w)[-5:].sum():.3f}")

    order = np.argsort(real_w)[::-1][:top_n]
    for rank, idx in enumerate(sorted(order), 1):
        log = logs[idx]
        print(f"\n[{rank}] peso={real_w[idx]:.4f}  t={idx}")
        for f in ("timestamp", "event_code", "user", "process_name",
                  "parent_process_name", "command_line", "file_path",
                  "registry_key", "target_process_name", "granted_access"):
            v = log.get(f)
            if v not in (None, "", "-"):
                print(f"    {f:<22}: {v}")

    return score, real_w