"""

Salida de preprocess_dataset:
    X_cat : (n_seq, MAX_SEQ_LEN, n_categorical)  int32
    X_num : (n_seq, MAX_SEQ_LEN, NUM_SIZE)       float32
    y     : (n_seq,)                             float32
"""

import hashlib
import math
import numpy as np

from Preprocesamiento_Logs.time_utils import parse_splunk_time, sort_key
from Preprocesamiento_Logs.fields_map import event_fields_map

# ─────────────────────────────────────────
# CONFIGURACIÓN
# ─────────────────────────────────────────

HASH_BUCKETS = 512
MAX_SEQ_LEN  = 1200       

PAD_ID     = 0            # timestep de relleno
MISSING_ID = 1            # campo categórico ausente
HASH_OFFSET = 2           # los hashes empiezan en 2

CAT_VOCAB_SIZE = HASH_BUCKETS + HASH_OFFSET

# Delta temporal: se satura para que un salto de días no domine la escala
MAX_DELTA_SECONDS = 3600.0

# ─────────────────────────────────────────
# VOCABULARIO EXPLÍCITO DE EVENT CODES
# ─────────────────────────────────────────

def _build_event_code_vocab():
    codes = set()
    for events in event_fields_map.values():
        codes.update(str(c) for c in events.keys())
    codes.add("4103")                       # PowerShell ScriptBlock
    return {code: i + HASH_OFFSET for i, code in enumerate(sorted(codes))}

EVENT_CODE_VOCAB = _build_event_code_vocab()
EVENT_CODE_VOCAB_SIZE = len(EVENT_CODE_VOCAB) + HASH_OFFSET + 1   # +1 = OOV

OOV_ID = EVENT_CODE_VOCAB_SIZE - 1

# ─────────────────────────────────────────
# CAMPOS
# ─────────────────────────────────────────

# event_code SIEMPRE en la posición 0: de ahí se deriva la máscara.
CATEGORICAL_FIELDS = [
    "event_code",
    "host",
    "user",
    "user_domain",
    "target_user",
    "process_name",
    "parent_process_name",
    "command_line",
    "file_path",
    "registry_key",
    "auth_package",
    "share_name",
    "task_name",
    "service_name",
    "privileges",
    "hash",
    "logon_type",
    # identificadores de sesión (antes en SESSION_FIELDS)
    "session_id",
    "process_guid",
    "user_sid",
    "target_sid",
]

NUMERIC_FIELDS = [
    "process_id",
    "parent_process_id",
    "src_port",
    "dst_port",
]

IP_FIELDS = ["src_ip", "dst_ip"]

ENGINEERED_FIELDS = [
    "is_system_account",
    "process_outside_system32",
    "process_in_user_space",
    "registry_is_persistence_key",
    "registry_is_hku",
    "file_in_sensitive_path",
    "file_is_dump_or_archive",
    "auth_is_ntlm",
    "logon_is_remote",
    "src_is_local",
    "access_lsass",
    "is_lsass_dump_lolbin",
    "parent_is_powershell",
    "ps_cmd_is_lsass",
]

# valor + flag de ausencia por cada numérico
NUM_SIZE = (
    len(NUMERIC_FIELDS) * 2 +
    4 +                         # tiempo cíclico (hour_sin/cos, dow_sin/cos)
    2 +                         # delta temporal: log1p normalizado + flag
    len(IP_FIELDS) * 4 +
    len(ENGINEERED_FIELDS)
)

CAT_SIZE = len(CATEGORICAL_FIELDS)

_MISSING = ("", "-", "N/A", "None", "0x0")

# ─────────────────────────────────────────
# CODIFICADORES
# ─────────────────────────────────────────

def hash_category(value, n_buckets=HASH_BUCKETS) -> int:
    """Devuelve un ID ENTERO de bucket, no un float."""
    if value is None or str(value).strip() in _MISSING:
        return MISSING_ID
    h = int(hashlib.md5(str(value).encode()).hexdigest(), 16)
    return h % n_buckets + HASH_OFFSET


def encode_event_code(value) -> int:
    if value is None or str(value).strip() in _MISSING:
        return MISSING_ID
    return EVENT_CODE_VOCAB.get(str(value).strip(), OOV_ID)


def encode_time(timestamp_str):
    dt = parse_splunk_time(timestamp_str)
    if dt is None:
        return [0.0, 0.0, 0.0, 0.0]
    return [
        math.sin(2 * math.pi * dt.hour / 24),
        math.cos(2 * math.pi * dt.hour / 24),
        math.sin(2 * math.pi * dt.weekday() / 7),
        math.cos(2 * math.pi * dt.weekday() / 7),
    ]


def encode_delta(current_dt, previous_dt):
    """
    Tiempo transcurrido desde el evento anterior.
    Devuelve [valor_normalizado, flag_disponible].
    'diez eventos en dos segundos' vs 'diez eventos en tres horas'
    es a menudo la señal más discriminante de la secuencia.
    """
    if current_dt is None or previous_dt is None:
        return [0.0, 0.0]
    delta = abs((current_dt - previous_dt).total_seconds())
    norm = math.log1p(min(delta, MAX_DELTA_SECONDS)) / math.log1p(MAX_DELTA_SECONDS)
    return [norm, 1.0]


def encode_ip(ip_str):
    if not ip_str or str(ip_str).strip() in ("", "-", "N/A", "::1", "None"):
        return [0.0, 0.0, 0.0, 0.0]
    octets = str(ip_str).strip().split(".")
    if len(octets) != 4:
        return [0.0, 0.0, 0.0, 0.0]
    try:
        return [int(o) / 255.0 for o in octets]
    except ValueError:
        return [0.0, 0.0, 0.0, 0.0]


def encode_numeric(value, min_val=0, max_val=65535):
    """Devuelve [valor_normalizado, flag_ausente]."""
    if value is None or str(value).strip() in _MISSING:
        return [0.0, 1.0]
    s = str(value).strip()
    try:
        # BUGFIX: float() no acepta base. Los PIDs y LogonIDs vienen en hex.
        v = float(int(s, 16)) if s.lower().startswith("0x") else float(s)
    except ValueError:
        return [0.0, 1.0]
    return [(v - min_val) / (max_val - min_val + 1e-9), 0.0]


# ─────────────────────────────────────────
# LOG -> VECTORES
# ─────────────────────────────────────────

def log_to_categorical(log: dict) -> list:
    out = [encode_event_code(log.get("event_code"))]
    for field in CATEGORICAL_FIELDS[1:]:
        out.append(hash_category(log.get(field)))
    return out


def log_to_numeric(log: dict, current_dt, previous_dt) -> list:
    vec = []
    for field in NUMERIC_FIELDS:
        vec.extend(encode_numeric(log.get(field)))
    vec.extend(encode_time(log.get("timestamp")))
    vec.extend(encode_delta(current_dt, previous_dt))
    for field in IP_FIELDS:
        vec.extend(encode_ip(log.get(field)))
    for field in ENGINEERED_FIELDS:
        vec.append(float(log.get(field) or 0.0))
    return vec


# ─────────────────────────────────────────
# SECUENCIA -> MATRICES
# ─────────────────────────────────────────

def truncate_sequence(sequence: list, max_len: int = MAX_SEQ_LEN) -> list:
    """
    Conserva cabeza Y cola. Truncar solo por el final descarta la
    exfiltración y el borrado de rastro, que es donde está la señal.
    """
    if len(sequence) <= max_len:
        return sequence
    head = max_len // 2
    tail = max_len - head
    return sequence[:head] + sequence[-tail:]


def sequence_to_matrices(sequence: list, max_len: int = MAX_SEQ_LEN):
    """Devuelve (cat_matrix int32, num_matrix float32), ambas de long. max_len."""
    # Ordenación temporal explícita: no confiar en el orden del fichero
    sequence = sorted(sequence, key=sort_key)
    sequence = truncate_sequence(sequence, max_len)

    cat_matrix, num_matrix = [], []
    previous_dt = None

    for log in sequence:
        current_dt = parse_splunk_time(log.get("timestamp"))
        cat_matrix.append(log_to_categorical(log))
        num_matrix.append(log_to_numeric(log, current_dt, previous_dt))
        if current_dt is not None:
            previous_dt = current_dt

    # Padding explícito y sin ambigüedad
    pad_cat = [PAD_ID] * CAT_SIZE
    pad_num = [0.0] * NUM_SIZE
    while len(cat_matrix) < max_len:
        cat_matrix.append(pad_cat)
        num_matrix.append(pad_num)

    cat = np.array(cat_matrix, dtype=np.int32)
    num = np.array(num_matrix, dtype=np.float32)

    if cat.shape != (max_len, CAT_SIZE):
        raise ValueError(f"cat shape {cat.shape}, esperado {(max_len, CAT_SIZE)}")
    if num.shape != (max_len, NUM_SIZE):
        raise ValueError(f"num shape {num.shape}, esperado {(max_len, NUM_SIZE)}")

    return cat, num


def preprocess_dataset(dataset, max_len: int = MAX_SEQ_LEN):
    """dataset: [(sequence_normalizada, label), ...]"""
    X_cat, X_num, y = [], [], []

    for sequence, label in dataset:
        cat, num = sequence_to_matrices(sequence, max_len)
        X_cat.append(cat)
        X_num.append(num)
        y.append(float(label))

    return (
        np.array(X_cat, dtype=np.int32),
        np.array(X_num, dtype=np.float32),
        np.array(y, dtype=np.float32),
    )