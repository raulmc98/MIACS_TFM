import re

SYSTEM_ACCOUNTS = {
    "SYSTEM", "LOCAL SERVICE", "NETWORK SERVICE",
    "NT AUTHORITY", "ANONYMOUS LOGON"
}

SYSTEM32_PATHS = (
    "c:\\windows\\system32\\", 
    "c:\\windows\\syswow64\\"
)


PERSISTENCE_KEYS = (
    "CurrentVersion\\Run",
    "CurrentVersion\\RunOnce",
    "SpecialAccounts\\UserList",
    "Winlogon",
    "Image File Execution Options",
)

SENSITIVE_PATHS = (
    "\\Temp\\", "\\AppData\\Local\\Temp\\",
    "\\Users\\Public\\",
    "\\ProgramData\\",
)

DUMP_EXTENSIONS = (".dmp", ".zip", ".7z", ".gz", ".lz4")

def engineer_features(log: dict) -> dict:
    """
    Genera campos derivados de alto valor de detección.
    Se añaden al log normalizado ANTES de vectorizarlo.
    """

    process_name       = (log.get("process_name")       or "").lower()
    parent_process_name = (log.get("parent_process_name") or "").lower()
    command_line       = (log.get("command_line")        or "").lower()
    file_path          = (log.get("file_path")           or "").lower()
    registry_key       = (log.get("registry_key")        or "").lower()
    user               = (log.get("user")                or "")
    user_sid           = (log.get("user_sid")            or "")
    auth_package       = (log.get("auth_package")        or "")
    logon_type         = (log.get("logon_type")          or "")
    granted_access     = (log.get("granted_access")      or "")
    src_ip             = (log.get("src_ip")              or "")

    features = {}

    # ── 1. Usuario es cuenta de sistema (genera mucho ruido benigno) ──────────
    features["is_system_account"] = 1.0 if (
        user in SYSTEM_ACCOUNTS
        or user.endswith("$")                          # cuentas de máquina
        or user_sid in ("S-1-5-18", "S-1-5-19", "S-1-5-20")
    ) else 0.0

    # ── 2. Proceso ejecutado fuera de System32/SysWOW64 ───────────────────────
    # Señal clave para detectar binarios maliciosos en rutas no estándar
    features["process_outside_system32"] = 0.0 if (
        not process_name
        or process_name.startswith(SYSTEM32_PATHS)
        or "\\program files\\" in process_name
        or "\\program files (x86)\\" in process_name
    ) else 1.0

    # ── 3. Proceso ejecutado desde directorio de usuario ──────────────────────
    # Un .exe en C:\Users\...\AppData o C:\Temp es sospechoso
    features["process_in_user_space"] = 1.0 if (
        process_name
        and ("\\users\\" in process_name or "\\temp\\" in process_name)
    ) else 0.0

    # ── 4. Clave de registro de persistencia modificada ───────────────────────
    # Detecta Run Keys, Winlogon, SpecialAccounts — todos en tus actividades
    features["registry_is_persistence_key"] = 1.0 if (
        registry_key
        and any(k.lower() in registry_key for k in PERSISTENCE_KEYS)
    ) else 0.0

    # ── 5. Clave de registro en HKU/HKCU (espacio de usuario) ─────────────────
    features["registry_is_hku"] = 1.0 if (
        registry_key
        and (registry_key.startswith("hku\\") or registry_key.startswith("hkcu\\"))
    ) else 0.0

    # ── 6. Archivo creado/borrado en directorio temporal o de usuario ──────────
    features["file_in_sensitive_path"] = 1.0 if (
        file_path
        and any(p.lower() in file_path for p in SENSITIVE_PATHS)
    ) else 0.0

    # ── 7. Archivo de volcado o comprimido (credenciales, exfiltración) ────────
    # lsass.dmp, backup.zip, etc. — presente literalmente en tus logs
    features["file_is_dump_or_archive"] = 1.0 if (
        file_path
        and any(file_path.endswith(ext) for ext in DUMP_EXTENSIONS)
    ) else 0.0

    # ── 8. Autenticación NTLM (vs Kerberos) ───────────────────────────────────
    # NTLM en tu laboratorio es señal de Pass-the-Hash o fallback sospechoso
    # Ves auth_package='NTLM' en los 4624 de admin-01 copiando lsass.zip
    features["auth_is_ntlm"] = 1.0 if auth_package.upper().startswith("NTLM") else 0.0

    # ── 9. Logon remoto (Type 3 o Type 10) ────────────────────────────────────
    features["logon_is_remote"] = 1.0 if logon_type in ("3", "10") else 0.0

    # ── 10. IP de origen es loopback o IPv6 link-local ────────────────────────
    # Distingue tráfico local del externo
    features["src_is_local"] = 1.0 if (
        src_ip in ("127.0.0.1", "::1")
        or src_ip.startswith("fe80::")
    ) else 0.0

    # ── 11. Acceso a LSASS (Sysmon 10) ────────────────────────────────────────
    # GrantedAccess 0x1010/0x1410 = lectura de memoria completa = Mimikatz
    features["access_lsass"] = 1.0 if (
        log.get("event_code") == "10"
        and "lsass" in (log.get("target_process_name") or "").lower()
    ) else 0.0

    # ── 12. rundll32 con comsvcs.dll (LSASS dump via LOLBin) ──────────────────
    # Exactamente lo que aparece en tus logs: rundll32.exe + MiniDump + lsass
    features["is_lsass_dump_lolbin"] = 1.0 if (
        "rundll32" in process_name
        and "comsvcs.dll" in command_line
        and "minidump" in command_line
    ) else 0.0

    # ── 13. PowerShell como proceso padre de algo inesperado ──────────────────
    # powershell.exe → rundll32.exe es la firma que ves en tus logs
    features["parent_is_powershell"] = 1.0 if (
        "powershell" in parent_process_name
    ) else 0.0

    # ── 14. Comando PowerShell con rutas de archivo inusuales ─────────────────
    # Detecta Copy-Item .\\lsass.*, Remove-Item .\\lsass.* que aparecen en logs
    features["ps_cmd_is_lsass"] = 1.0 if (
        log.get("event_code") == "4103"
        and "lsass" in (log.get("file_path") or "").lower()
    ) else 0.0

    return features