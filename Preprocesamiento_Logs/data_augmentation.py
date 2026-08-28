import copy
import random
import re
import uuid

from Preprocesamiento_Logs.time_utils import parse_splunk_time, format_splunk_time
from datetime import timedelta

# =========================================================
# IDENTIDADES DEL LABORATORIO
# =========================================================

# El SID viaja con el usuario. Nunca se rotan por separado.
DOMAIN_SID = "S-1-5-21-1004336348-1177238915-682003330"

LAB_IDENTITIES = [
    {"user": "user-01",       "domain": "MIACSDOMAIN", "sid": f"{DOMAIN_SID}-1601"},
    {"user": "user-02",       "domain": "MIACSDOMAIN", "sid": f"{DOMAIN_SID}-1602"},
    {"user": "jsmith",        "domain": "MIACSDOMAIN", "sid": f"{DOMAIN_SID}-1603"},
    {"user": "mgarcia",       "domain": "MIACSDOMAIN", "sid": f"{DOMAIN_SID}-1604"},
    {"user": "adminlocal",    "domain": "WIN-10",      "sid": "S-1-5-21-2140393329-1094754378-1934365201-1001"},
    {"user": "Administrator", "domain": "MIACSDOMAIN", "sid": f"{DOMAIN_SID}-500"},
]

LAB_HOSTS = ["Win-10", "DC-01"]
SRC_IP_RANGE = "192.168.100"

# Valores que nunca se sustituyen aunque el campo sea rotable
_SENTINELS = ("", "-", "N/A", "None", "NOT_TRANSLATED", "::1", "0x0")

# Cuentas de sistema: rotarlas rompería la semántica del log
_SYSTEM_ACCOUNTS = {"SYSTEM", "LOCAL SERVICE", "NETWORK SERVICE",
                    "ANONYMOUS LOGON", "LOCAL SYSTEM"}

# =========================================================
# CAMPOS INMUTABLES (SOLO NOMBRES RAW DE fields_map.py)
# =========================================================

IMMUTABLE_FIELDS = {
    # Identificadores del evento
    "EventCode", "sourcetype", "source", "Type", "TaskCategory",
    "Keywords", "OpCode", "LogName", "SourceName",

    # Procesos: rutas y líneas de comando (la señal de detección)
    "Image", "ParentImage", "SourceImage", "TargetImage", "ImageLoaded",
    "Process_Name", "New_Process_Name", "Creator_Process_Name",
    "Target_Process_Name", "CommandLine", "ParentCommandLine",
    "Process_Command_Line", "CurrentDirectory", "OriginalFileName",
    "Description", "Product", "Company",

    # Ficheros y registro
    "TargetFilename", "TargetObject", "Object_Name", "Object_Type",
    "Object_Server", "Details", "NewName", "Relative_Target_Name",
    "Share_Name", "Share_Path", "FilePath",

    # Tareas y servicios
    "Task_Name", "Service_Name", "Service_File_Name", "Service_Type",
    "Service_Start_Type", "Service_Account", "TaskContent",

    # Autenticación y privilegios
    "Logon_Type", "Logon_Process", "Authentication_Package",
    "Ticket_Encryption_Type", "Ticket_Options", "Failure_Code",
    "Status", "Sub_Status", "Privileges", "Privilege_List",
    "Impersonation_Level", "Elevated_Token", "Token_Elevation_Type",
    "Mandatory_Label", "IntegrityLevel", "Accesses", "Access_Mask",
    "GrantedAccess", "CallTrace",

    # Red: puerto/host destino y protocolo son semánticos
    "DestinationPort", "DestinationPortName", "Port", "Protocol",
    "Initiated", "SourceIsIpv6", "DestinationIsIpv6",
    "QueryName", "QueryStatus", "QueryResults", "DestinationIp",

    # Integridad
    "Hashes", "Hash", "Signature", "Signed", "SignatureStatus",
}

# Prefijos de campo que nunca se tocan (PowerShell 4103)
IMMUTABLE_PREFIXES = ("parameterbinding_",)

# =========================================================
# GRUPOS DE CAMPOS ROTABLES (nombres raw)
# =========================================================

TIME_FIELDS      = {"_time", "UtcTime", "CreationUtcTime", "PreviousCreationUtcTime"}
USER_FIELDS      = {"Account_Name", "User", "SourceUser", "TargetUser",
                    "ParentUser", "TargetUserName", "Target_Account_Name",
                    "Member_Name", "Subject_Account_Name"}
DOMAIN_FIELDS    = {"Account_Domain", "Target_Domain_Name", "TargetDomainName",
                    "Subject_Domain_Name", "Supplied_Realm_Name"}
SID_FIELDS       = {"Security_ID", "Sid", "Target_Sid", "Member_Sid",
                    "Subject_Security_ID", "Service_ID"}
HOST_FIELDS      = {"host", "Computer", "ComputerName"}
DST_HOST_FIELDS  = {"Workstation_Name", "Target_Server_Name",
                    "DestinationHostname", "SourceHostname"}
SRC_PORT_FIELDS  = {"Source_Port", "Client_Port", "SourcePort"}
SRC_IP_FIELDS    = {"Source_Network_Address", "Client_Address",
                    "Network_Address", "SourceIp"}
PID_FIELDS       = {"Process_ID", "New_Process_ID", "ProcessId",
                    "SourceProcessId", "TargetProcessId",
                    "Creator_Process_ID", "ParentProcessId", "Target_Process_ID"}
LOGON_ID_FIELDS  = {"Logon_ID", "LogonId", "New_Logon_ID", "Subject_Logon_ID"}
GUID_FIELDS      = {"ProcessGuid", "SourceProcessGuid", "TargetProcessGuid",
                    "ParentProcessGuid", "LogonGuid", "Logon_GUID"}

_USER_LINE_RE = re.compile(r'(^\s*User\s*=\s*)([^\r\n]+)', re.MULTILINE)


# =========================================================
# GENERADORES
# =========================================================

def _is_sentinel(value) -> bool:
    return value is None or str(value).strip() in _SENTINELS


def _is_system_account(value) -> bool:
    v = str(value).strip().upper()
    return v in _SYSTEM_ACCOUNTS or v.endswith("$")


def shift_timestamp(value: str, minutes_delta: int) -> str:
    dt = parse_splunk_time(value)
    if dt is None:
        return value
    return format_splunk_time(dt + timedelta(minutes=minutes_delta))


def randomize_src_port() -> str:
    return str(random.randint(49152, 65535))


def randomize_process_id() -> str:
    return str(random.randint(1000, 65000))


def randomize_src_ip(base_range: str = SRC_IP_RANGE) -> str:
    return f"{base_range}.{random.randint(10, 250)}"


def _rewrite_message_user(message: str, identity: dict) -> str:
    """Reescribe la línea 'User = DOMINIO\\usuario' del campo Message (4103)."""
    if not message:
        return message

    def _repl(m):
        old = m.group(2).strip()
        if "Connected" in old or _is_system_account(old.split("\\")[-1]):
            return m.group(0)
        return f"{m.group(1)}{identity['domain']}\\{identity['user']}"

    return _USER_LINE_RE.sub(_repl, message)


# =========================================================
# AUGMENTACIÓN DE UN LOG RAW
# =========================================================

def augment_log(log: dict, ctx: dict) -> dict:
    """
    ctx contiene el estado COMPARTIDO por toda la secuencia:
        time_delta, identity, host, dst_host, src_ip,
        pid_map, logon_map, guid_map
    Los mapas garantizan que un mismo PID/LogonID/GUID original se
    traduce siempre al mismo valor nuevo dentro de la secuencia:
    sin eso se rompe la correlación padre-hijo entre logs.
    """
    augmented = copy.deepcopy(log)
    identity = ctx["identity"]

    for key in list(augmented.keys()):

        if key in IMMUTABLE_FIELDS:
            continue
        if key.lower().startswith(IMMUTABLE_PREFIXES):
            continue

        value = augmented[key]

        if isinstance(value, (dict, list)):
            continue

        if key in TIME_FIELDS:
            augmented[key] = shift_timestamp(str(value), ctx["time_delta"])

        elif key in USER_FIELDS:
            if not _is_sentinel(value) and not _is_system_account(value):
                augmented[key] = identity["user"]

        elif key in DOMAIN_FIELDS:
            if not _is_sentinel(value):
                augmented[key] = identity["domain"]

        elif key in SID_FIELDS:
            # El SID viaja con el usuario: nunca se aleatoriza suelto
            if not _is_sentinel(value) and not str(value).startswith("S-1-5-1"):
                augmented[key] = identity["sid"]

        elif key in HOST_FIELDS:
            augmented[key] = ctx["host"]

        elif key in DST_HOST_FIELDS:
            if not _is_sentinel(value):
                augmented[key] = ctx["dst_host"]

        elif key in SRC_PORT_FIELDS:
            if not _is_sentinel(value):
                augmented[key] = randomize_src_port()

        elif key in SRC_IP_FIELDS:
            if not _is_sentinel(value):
                augmented[key] = ctx["src_ip"]

        elif key in PID_FIELDS:
            if not _is_sentinel(value):
                augmented[key] = ctx["pid_map"].setdefault(
                    str(value), randomize_process_id()
                )

        elif key in LOGON_ID_FIELDS:
            if not _is_sentinel(value):
                augmented[key] = ctx["logon_map"].setdefault(
                    str(value), hex(random.randint(0x100000, 0xFFFFFF))
                )

        elif key in GUID_FIELDS:
            if not _is_sentinel(value):
                augmented[key] = ctx["guid_map"].setdefault(
                    str(value), "{" + str(uuid.uuid4()).upper() + "}"
                )

        elif key == "RecordNumber":
            augmented[key] = str(random.randint(1000, 99999))

        elif key == "Message":
            augmented[key] = _rewrite_message_user(str(value), identity)

    return augmented


def augment_sequence(sequence: list, n_variants: int = 5) -> list:
    """Genera n_variants variantes de una secuencia RAW completa."""
    variants = []

    for _ in range(n_variants):
        ctx = {
            "time_delta": random.randint(-120, 120),
            "identity"  : random.choice(LAB_IDENTITIES),
            "host"      : random.choice(LAB_HOSTS),
            "dst_host"  : random.choice(LAB_HOSTS),
            "src_ip"    : randomize_src_ip(),
            "pid_map"   : {},
            "logon_map" : {},
            "guid_map"  : {},
        }
        variants.append([augment_log(log, ctx) for log in sequence])

    return variants


def augment_dataset_raw(dataset_raw: list, n_variants: int = 5) -> list:
    """
    dataset_raw: [(raw_sequence, label), ...]
    Devuelve el dataset RAW ampliado. La normalización y el cálculo de
    features derivadas se hace DESPUÉS, sobre cada variante.
    """
    out = []
    for sequence, label in dataset_raw:
        out.append((sequence, label))
        for variant in augment_sequence(sequence, n_variants):
            out.append((variant, label))
    return out