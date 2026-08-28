import re


KNOWN_EXECUTABLES = {
    "schtasks.exe", "net.exe", "net1.exe", "cmd.exe", "powershell.exe",
    "wmic.exe", "reg.exe", "certutil.exe", "bitsadmin.exe", "msiexec.exe",
    "rundll32.exe", "regsvr32.exe", "mshta.exe", "cscript.exe", "wscript.exe",
    "nltest.exe", "whoami.exe", "ipconfig.exe", "netstat.exe", "tasklist.exe",
    "psexec.exe", "mimikatz.exe", "rubeus.exe", "invoke-expression",
    "invoke-webrequest", "invoke-command", "new-pssession", "start-process"
}

# Acciones/flags relevantes para detección
KNOWN_ACTIONS = {
    "/create", "/delete", "/run", "/query",    # schtasks
    "/add", "/domain",                          # net
    "add", "delete", "query",                   # reg
    "-urlcache", "-decode", "-encode",          # certutil
    "-encodedcommand", "-enc", "-nop",          # powershell
    "create", "call",                           # wmic
    "/transfer",                                # bitsadmin
    "sekurlsa", "lsadump", "kerberos"          # mimikatz
}

def extract_scriptblock_semantics(scriptblock: str) -> dict:
    if not scriptblock:
        return {"sb_executable": None, "sb_action": None}

    tokens = re.split(r'[\s;|&]+', scriptblock.lower())

    executable = None
    action     = None

    for token in tokens:
        token = token.strip('"\'')

        # Detectar ejecutable
        if executable is None and token in KNOWN_EXECUTABLES:
            executable = token

        # Detectar acción/flag
        if action is None and token in KNOWN_ACTIONS:
            action = token

        if executable and action:
            break

    return {
        "sb_executable": executable,
        "sb_action"    : action
    }


def extract_user_from_context(message: str):
    if not message:
        return None, None

    # Buscar específicamente la línea "        User = ..." excluyendo "Connected User"
    match = re.search(r'^\s+User\s*=\s*([^\r\n]+)', message, re.MULTILINE)
    if not match:
        return None, None

    user_full = match.group(1).strip()

    if not user_full or "Connected" in user_full:
        return None, None

    if "\\" in user_full:
        parts = user_full.split("\\", 1)
        return parts[0].strip(), parts[1].strip()

    return None, user_full


def parse_binding(binding: str) -> tuple:
    """
    Parsea una línea tipo:
    name="ComputerName"; value="DC-01"
    name="ScriptBlock"; value=" schtasks.exe /create /tn \"Update\" ..."
    """
    binding = str(binding).strip()

    # Buscar el separador '; value=' y partir por ahí
    separator = '; value='
    sep_index = binding.find(separator)

    if sep_index == -1:
        return None, None

    # Extraer name (entre las primeras comillas)
    name_part  = binding[:sep_index]
    value_part = binding[sep_index + len(separator):]

    # Limpiar comillas externas de name
    name_match = re.search(r'name="([^"]+)"', name_part)
    if not name_match:
        return None, None

    param_name = name_match.group(1).strip()

    # Limpiar comillas externas del value (primera y última)
    if value_part.startswith('"') and value_part.endswith('"'):
        value_part = value_part[1:-1]

    # Desescapar comillas internas
    param_value = value_part.replace('\\"', '"').strip()

    return param_name, param_value


COMMANDS_TO_IGNORE = {
    "Resolve-Path",       # autocompletado con Tab
    "Get-FileHash",       # interno de PSReadLine
    "Set-StrictMode",     # inicialización interna de módulos
    "Out-Default",        # pipeline interno de PowerShell
    "Out-Null",           # descarte de output, sin valor semántico
    "Add-Type",           # carga de assemblies, muy ruidoso
}


def extract_4103(log: dict) -> dict:
    Account_Domain, Account_Name = extract_user_from_context(log.get("Message", ""))
    row = {
        "_time"        : log.get("_time"),
        "host"         : log.get("host"),
        "EventCode"    : log.get("EventCode"),
        "TaskCategory" : log.get("TaskCategory"),
        "Sid"          : log.get("Sid"),
        "User" : Account_Name,
        "domain" : Account_Domain,
        "command"      : None,
        "sb_executable": None,
        "sb_action"    : None,
        "ComputerName" : None,
        "Port"         : None,
        "FilePath"     : None,
        "Uri"          : None
    }

    for key, value in log.items():
        if not key.lower().startswith("parameterbinding_"):
            continue

        command_name   = key.replace("ParameterBinding_", "").strip("_").replace("_", "-")
        if command_name in COMMANDS_TO_IGNORE:
            return None  # señal al pipeline para descartar este log


        row["command"] = command_name

        bindings = value if isinstance(value, list) else [value]

        for binding in bindings:
            param_name, param_value = parse_binding(binding)
            if not param_name or not param_value:
                continue

            p = param_name.lower()

            if p == "computername":
                row["ComputerName"] = param_value
            elif p == "port":
                row["Port"] = param_value
            elif p in ("filepath", "path", "file"):
                row["FilePath"] = param_value
            elif p in ("uri", "url"):
                row["Uri"] = param_value
            elif p == "scriptblock":
                semantics = extract_scriptblock_semantics(param_value)
                row["sb_executable"] = semantics["sb_executable"]
                row["sb_action"]     = semantics["sb_action"]


    return row if row["command"] is not None else None