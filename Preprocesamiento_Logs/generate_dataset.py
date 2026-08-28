import json
import os

from Preprocesamiento_Logs.fields_map import event_fields_map
from Preprocesamiento_Logs.logs_powershell import extract_4103
from Preprocesamiento_Logs.engineer_features import engineer_features
from Preprocesamiento_Logs.time_utils import sort_key

POWERSHELL_SOURCETYPE = "wineventlog:microsoft-windows-powershell/operational"


# =========================================================
# NORMALIZACIÓN
# =========================================================

def normalize_log(log: dict) -> dict:
    def get_first(*fields):
        for f in fields:
            v = log.get(f)
            if v and str(v).strip() not in ("", "-", "N/A", "None", "0x0"):
                return str(v).strip()
        return None

    event_code = str(log.get("EventCode", ""))
    sourcetype = str(log.get("sourcetype", "")).lower()

    normalized = {
        "timestamp"          : get_first("_time"),
        "host"               : get_first("host"),
        "event_code"         : event_code,
        "sourcetype"         : sourcetype,

        "session_id"         : get_first("Logon_ID", "LogonId", "New_Logon_ID"),

        "user"               : get_first("Account_Name", "User", "SourceUser"),
        "user_sid"           : get_first("Security_ID", "Sid"),
        "user_domain"        : get_first("Account_Domain"),

        "target_user"        : get_first("Target_Account_Name", "TargetUser", "Member_Name"),
        "target_sid"         : get_first("Target_Sid", "Member_Sid"),

        "process_id"         : get_first("Process_ID", "New_Process_ID", "ProcessId", "SourceProcessId"),
        # 'command' ELIMINADO de aquí: era el nombre del cmdlet, no una ruta,
        # y rompía todas las features que hacen startswith() sobre rutas.
        "process_name"       : get_first("Process_Name", "New_Process_Name", "Image", "SourceImage"),
        "process_guid"       : get_first("ProcessGuid", "SourceProcessGuid"),
        "command_line"       : get_first("Process_Command_Line", "CommandLine"),

        "parent_process_id"  : get_first("Creator_Process_ID", "ParentProcessId"),
        "parent_process_name": get_first("Creator_Process_Name", "ParentImage"),

        # Sysmon 10: el proceso ACCEDIDO va aparte del que accede
        "target_process_name": get_first("TargetImage", "Target_Process_Name"),

        "src_ip"             : get_first("Source_Network_Address", "Client_Address", "Network_Address", "SourceIp"),
        "src_port"           : get_first("Source_Port", "Client_Port", "SourcePort"),
        "dst_ip"             : get_first("DestinationIp"),
        "dst_port"           : get_first("DestinationPort", "Port"),
        "dst_host"           : get_first("Target_Server_Name", "Workstation_Name", "DestinationHostname", "ComputerName"),
        "query_name"         : get_first("QueryName"),
        "query_status"       : get_first("QueryStatus"),

        "file_path"          : get_first("Object_Name", "TargetFilename", "ImageLoaded", "FilePath"),
        "registry_key"       : get_first("TargetObject"),

        "hash"               : get_first("Hashes"),
        "privileges"         : get_first("Privileges"),
        "logon_type"         : get_first("Logon_Type"),
        "auth_package"       : get_first("Authentication_Package"),
        "share_name"         : get_first("Share_Name"),
        "task_name"          : get_first("Task_Name"),
        "service_name"       : get_first("Service_Name"),
        "ticket_encryption"  : get_first("Ticket_Encryption_Type"),
        "granted_access"     : get_first("GrantedAccess"),
        "ps_cmdlet"          : None,
    }

    if event_code == "4103":
        extracted = extract_4103(log)
        if extracted is None:
            return None
        normalized["user"]         = extracted.get("User") or normalized["user"]
        normalized["user_domain"]  = extracted.get("domain") or normalized["user_domain"]
        normalized["ps_cmdlet"]    = extracted.get("command")
        normalized["process_name"] = "powershell.exe"
        normalized["dst_host"]     = extracted.get("ComputerName") or normalized["dst_host"]
        normalized["dst_port"]     = extracted.get("Port") or normalized["dst_port"]
        normalized["file_path"]    = extracted.get("FilePath") or normalized["file_path"]
        normalized["command_line"] = extracted.get("sb_executable")

    for user_field in ("user", "target_user"):
        val = normalized.get(user_field)
        if val and "\\" in val:
            parts = val.split("\\", 1)
            if user_field == "user" and not normalized.get("user_domain"):
                normalized["user_domain"] = parts[0]
            normalized[user_field] = parts[1]

    normalized.update(engineer_features(normalized))
    return normalized


def normalize_sequence(raw_sequence: list) -> list:
    """Normaliza y ORDENA CRONOLÓGICAMENTE una secuencia RAW."""
    normalized = []
    for raw in raw_sequence:
        n = normalize_log(raw)
        if n is not None:
            normalized.append(n)
    return sorted(normalized, key=sort_key)


def normalize_dataset(dataset_raw: list) -> list:
    return [(normalize_sequence(seq), label) for seq, label in dataset_raw]


# =========================================================
# EXTRACCIÓN RAW
# =========================================================

def extract_fields(obj, fields):
    wanted = {f.lower(): f for f in fields}
    row = {}

    def walk(o):
        if isinstance(o, dict):
            for k, v in o.items():
                lk = k.lower()
                if lk in wanted:
                    row[wanted[lk]] = v[-1] if isinstance(v, list) else v
                walk(v)
        elif isinstance(o, list):
            for i in o:
                walk(i)

    walk(obj)
    return row


def extract_raw_sequence(logs, stats: dict = None):
    """
    Devuelve la lista de logs RAW de un fichero.
    stats acumula los descartes para que no desaparezcan en silencio.
    """
    if stats is None:
        stats = {}

    raw_rows = []

    for line in logs:
        line = line.strip()
        if not line:
            continue
        try:
            log_json = json.loads(line)
        except json.JSONDecodeError:
            stats["json_error"] = stats.get("json_error", 0) + 1
            continue

        source     = extract_fields(log_json, ["sourcetype"]).get("sourcetype", "").lower()
        event_code = extract_fields(log_json, ["EventCode"]).get("EventCode")

        if source == POWERSHELL_SOURCETYPE:
            if str(event_code) != "4103":
                stats[f"ps_skip_{event_code}"] = stats.get(f"ps_skip_{event_code}", 0) + 1
                continue
            raw_log = dict(log_json.get("result", log_json))
            raw_log["sourcetype"] = source
            raw_rows.append(raw_log)
            continue

        fields = event_fields_map.get(source, {}).get(str(event_code))
        if not fields:
            key = f"unmapped_{source}_{event_code}"
            stats[key] = stats.get(key, 0) + 1
            continue

        row = extract_fields(log_json, fields)
        row["sourcetype"] = source
        raw_rows.append(row)

    return raw_rows, stats


# =========================================================
# CARGA DE DIRECTORIOS
# =========================================================

def _load_directory(path: str, label: int, stats: dict):
    dataset_raw = []
    if not os.path.isdir(path):
        raise FileNotFoundError(f"No existe el directorio: {path}")

    for filename in sorted(os.listdir(path)):
        if not filename.endswith(".json"):
            continue
        filepath = os.path.join(path, filename)
        with open(filepath, "r", encoding="utf-8") as f:
            raw, _ = extract_raw_sequence(f.readlines(), stats)
        if not raw:
            print(f"  [aviso] secuencia vacía tras el filtrado: {filename}")
            continue
        dataset_raw.append((raw, label))

    return dataset_raw

def _report(stats: dict, split_name: str):
    if stats:
        print(f"\n[descartes durante la extracción — {split_name}]")
        for k, v in sorted(stats.items(), key=lambda kv: -kv[1]):
            print(f"  {k:<50} {v}")
            
def _load_split(split_path: str, stats: dict):
    """Carga un split con subcarpetas 'Actividad Benigna' y 'Actividad Maliciosa'."""
    if not os.path.isdir(split_path):
        raise FileNotFoundError(f"No existe el directorio: {split_path}")

    dataset_raw  = _load_directory(os.path.join(split_path, "Actividad Benigna"),   0, stats)
    dataset_raw += _load_directory(os.path.join(split_path, "Actividad Maliciosa"), 1, stats)
    return dataset_raw


def generate_train_dataset_raw(base_path="Preprocesamiento_Logs/logs"):
    stats = {}
    data = _load_split(os.path.join(base_path, "train"), stats)
    _report(stats, "train")
    return data


def generate_test_dataset_raw(base_path="Preprocesamiento_Logs/logs"):
    stats = {}
    data = _load_split(os.path.join(base_path, "test"), stats)
    _report(stats, "test")
    return data

# =========================================================
# DEDUPLICACIÓN
# =========================================================

def deduplicate_logs(sequence: list) -> list:
    """BUGFIX: tuple(sorted(log.items())) falla con valores dict/list."""
    seen, out = set(), []
    for log in sequence:
        key = json.dumps(log, sort_keys=True, default=str)
        if key not in seen:
            seen.add(key)
            out.append(log)
    return out


def deduplicate_dataset(dataset: list) -> list:
    return [(deduplicate_logs(seq), label) for seq, label in dataset]