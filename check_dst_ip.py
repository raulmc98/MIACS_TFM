"""Comprobación de fuga por dirección de destino."""

from collections import Counter
from Preprocesamiento_Logs.generate_dataset import (
    generate_train_dataset_raw, normalize_dataset
)

dataset = normalize_dataset(generate_train_dataset_raw())

for campo in ("dst_ip", "src_ip", "dst_host"):
    print(f"\n{'='*60}\n{campo}\n{'='*60}")
    vals = {0: Counter(), 1: Counter()}   # frecuencia de logs
    caps = {0: Counter(), 1: Counter()}   # nº de capturas donde aparece
    n_caps = {0: 0, 1: 0}

    for sequence, label in dataset:
        n_caps[label] += 1
        presentes = set()
        for log in sequence:
            v = log.get(campo)
            if v:
                vals[label][str(v)] += 1
                presentes.add(str(v))
        for v in presentes:
            caps[label][v] += 1

    todos = set(vals[0]) | set(vals[1])
    print(f"{'valor':<24} {'logs_ben':>9} {'logs_mal':>9} "
          f"{'caps_ben':>9} {'caps_mal':>9}  exclusivo")
    print("-" * 75)
    for v in sorted(todos, key=lambda x: -(vals[0][x] + vals[1][x])):
        marca = ""
        if vals[0][v] == 0:
            marca = f"SOLO MALICIOSA ({caps[1][v]}/{n_caps[1]} capturas)"
        elif vals[1][v] == 0:
            marca = f"solo benigna ({caps[0][v]}/{n_caps[0]} capturas)"
        print(f"{v:<24} {vals[0][v]:>9} {vals[1][v]:>9} "
              f"{caps[0][v]:>9} {caps[1][v]:>9}  {marca}")