# Actividades maliciosas

Catálogo de sesiones de actividad adversaria capturadas en el laboratorio.

Cada actividad reproduce una cadena de ataque completa siguiendo la
metodología MITRE ATT&CK, ejecutada manualmente en el entorno de pruebas y
exportada desde Splunk como un único fichero JSON.

## Criterio de diseño

La selección de técnicas prioriza aquellas que se materializan mediante
utilidades legítimas del sistema operativo, por dos razones. Son las técnicas
ante las que las reglas de detección deterministas resultan más frágiles, y son
las que producen telemetría solapada con la administración legítima, condición
necesaria para que el problema de clasificación no sea trivial.

Cada actividad recorre varias tácticas en un orden con dependencias causales
—no hay persistencia antes de una ejecución, ni exfiltración antes de una
recopilación—, de modo que la secuencia contenga la estructura temporal que
constituye el objeto de aprendizaje del modelo.

No se empleó malware ni herramientas ofensivas externas.

---

## M01 — Ataque interno con PowerShell

Un usuario con acceso legítimo al dominio intenta obtener información sobre su
estructura y ejecutar código descargado.

**Secuencia**

1. Abrir PowerShell
2. Enumerar usuarios del dominio
3. Enumerar grupos
4. Enumerar equipos
5. Buscar recursos compartidos
6. Descargar un script desde un recurso SMB
7. Ejecutarlo

**Técnicas**

| Táctica | Técnica | ID |
|---|---|---|
| Execution | Command and Scripting Interpreter: PowerShell | T1059.001 |
| Discovery | Account Discovery: Domain Account | T1087.002 |
| Discovery | Permission Groups Discovery: Domain Groups | T1069.002 |
| Discovery | Remote System Discovery | T1018 |
| Discovery | Network Share Discovery | T1135 |
| Command and Control | Ingress Tool Transfer | T1105 |

---

## M02 — Robo de credenciales

Volcado de la memoria del proceso LSASS y traslado del resultado a un recurso
compartido.

**Secuencia**

1. Enumerar procesos
2. Enumerar privilegios
3. Volcar LSASS
4. Copiar el dump
5. Comprimir
6. Mover el ZIP a un recurso compartido

**Técnicas**

| Táctica | Técnica | ID |
|---|---|---|
| Discovery | Process Discovery | T1057 |
| Discovery | System Owner/User Discovery | T1033 |
| Credential Access | OS Credential Dumping: LSASS Memory | T1003.001 |
| Defense Evasion | System Binary Proxy Execution: Rundll32 | T1218.011 |
| Collection | Local Data Staging | T1074.001 |
| Collection | Archive Collected Data: Archive via Utility | T1560.001 |
| Exfiltration | Exfiltration Over Alternative Protocol | T1048 |

---

## M03 — Movimiento lateral

Acceso a un segundo equipo del dominio mediante credenciales válidas y
establecimiento de persistencia remota.

**Secuencia**

1. Enumerar equipos
2. Probar credenciales
3. Crear sesión WinRM
4. Ejecutar comandos remotos
5. Copiar herramientas
6. Crear tarea programada remota

**Técnicas**

| Táctica | Técnica | ID |
|---|---|---|
| Discovery | Remote System Discovery | T1018 |
| Credential Access | Brute Force: Password Guessing | T1110.001 |
| Lateral Movement | Remote Services: Windows Remote Management | T1021.006 |
| Lateral Movement | Lateral Tool Transfer | T1570 |
| Execution | Command and Scripting Interpreter: PowerShell | T1059.001 |
| Persistence | Scheduled Task/Job: Scheduled Task | T1053.005 |

---

## M04 — Persistencia

Establecimiento de múltiples mecanismos de persistencia sobre un equipo
comprometido.

**Secuencia**

1. Crear usuario oculto
2. Añadir a Administradores
3. Crear Scheduled Task
4. Crear Run Key
5. Modificar Firewall
6. Reiniciar

**Técnicas**

| Táctica | Técnica | ID |
|---|---|---|
| Persistence | Create Account: Local Account | T1136.001 |
| Privilege Escalation | Account Manipulation | T1098 |
| Defense Evasion | Hide Artifacts: Hidden Users | T1564.002 |
| Persistence | Scheduled Task/Job: Scheduled Task | T1053.005 |
| Persistence | Boot or Logon Autostart Execution: Registry Run Keys | T1547.001 |
| Defense Evasion | Impair Defenses: Disable or Modify System Firewall | T1562.004 |
| Impact | System Shutdown/Reboot | T1529 |

---

## M05 — Exfiltración de documentos

Localización, recopilación y traslado de documentación sensible, con
eliminación posterior del rastro.

**Secuencia**

1. Buscar documentos
2. Copiar documentos
3. Comprimir
4. Cifrar ZIP
5. Copiar al recurso compartido
6. Limpiar temporales

**Técnicas**

| Táctica | Técnica | ID |
|---|---|---|
| Discovery | File and Directory Discovery | T1083 |
| Collection | Data from Local System | T1005 |
| Collection | Local Data Staging | T1074.001 |
| Collection | Archive Collected Data: Archive via Utility | T1560.001 |
| Exfiltration | Exfiltration Over Alternative Protocol | T1048 |
| Defense Evasion | Indicator Removal: File Deletion | T1070.004 |

---

## M06 — Ransomware (simulado)

Reproducción del comportamiento de un cifrador sin cifrado real: recopilación
masiva, renombrado, destrucción de originales y nota de rescate.

**Secuencia**

1. Inicio de sesión
2. Enumerar unidades de disco
3. Enumerar recursos SMB
4. Copiar cientos de documentos a una carpeta temporal
5. Renombrar masivamente los archivos (simulando cifrado)
6. Eliminar copias originales
7. Crear una nota de rescate (`README.txt`)
8. Desactivar Defender

**Técnicas**

| Táctica | Técnica | ID |
|---|---|---|
| Discovery | System Information Discovery | T1082 |
| Discovery | Network Share Discovery | T1135 |
| Collection | Data from Network Shared Drive | T1039 |
| Collection | Local Data Staging | T1074.001 |
| Impact | Data Encrypted for Impact | T1486 |
| Impact | Data Destruction | T1485 |
| Defense Evasion | Impair Defenses: Disable or Modify Tools | T1562.001 |

> El cifrado se sustituye por un renombrado masivo, que produce telemetría de
> creación y borrado de ficheros equivalente sin causar daño irreversible en el
> laboratorio.

---

## M07 — Enumeración completa del dominio

Reconocimiento sistemático del entorno inmediatamente posterior a la obtención
de acceso.

**Secuencia**

1. `whoami`
2. `hostname`
3. `ipconfig`
4. `net user /domain`
5. `net group /domain`
6. `nltest`
7. `net view`
8. `arp -a`
9. `route print`

**Técnicas**

| Táctica | Técnica | ID |
|---|---|---|
| Execution | Command and Scripting Interpreter: Windows Command Shell | T1059.003 |
| Discovery | System Owner/User Discovery | T1033 |
| Discovery | System Information Discovery | T1082 |
| Discovery | System Network Configuration Discovery | T1016 |
| Discovery | Account Discovery: Domain Account | T1087.002 |
| Discovery | Permission Groups Discovery: Domain Groups | T1069.002 |
| Discovery | Domain Trust Discovery | T1482 |
| Discovery | Remote System Discovery | T1018 |
| Discovery | System Network Connections Discovery | T1049 |

---

## M08 — Persistencia mediante servicios

Instalación de un servicio de Windows como mecanismo de arranque persistente
con privilegios elevados.

**Secuencia**

1. Copiar binario a `C:\ProgramData`
2. Crear servicio de Windows
3. Configurar inicio automático
4. Arrancar el servicio
5. Modificar permisos del servicio
6. Reiniciar el equipo

**Técnicas**

| Táctica | Técnica | ID |
|---|---|---|
| Persistence | Create or Modify System Process: Windows Service | T1543.003 |
| Execution | System Services: Service Execution | T1569.002 |
| Privilege Escalation | Hijack Execution Flow: Services Registry Permissions Weakness | T1574.011 |
| Defense Evasion | Masquerading: Match Legitimate Name or Location | T1036.005 |
| Impact | System Shutdown/Reboot | T1529 |

---

## M09 — Uso de LOLBins

Cadena de ejecución basada exclusivamente en binarios firmados del sistema
operativo, sin introducir código externo.

**Secuencia**

1. PowerShell
2. `certutil` descarga un fichero
3. `bitsadmin`
4. `wmic`
5. `schtasks`
6. `reg add`
7. `cmd`

**Técnicas**

| Táctica | Técnica | ID |
|---|---|---|
| Execution | Command and Scripting Interpreter: PowerShell | T1059.001 |
| Execution | Command and Scripting Interpreter: Windows Command Shell | T1059.003 |
| Command and Control | Ingress Tool Transfer | T1105 |
| Defense Evasion | System Binary Proxy Execution | T1218 |
| Persistence | BITS Jobs | T1197 |
| Execution | Windows Management Instrumentation | T1047 |
| Persistence | Scheduled Task/Job: Scheduled Task | T1053.005 |
| Defense Evasion | Modify Registry | T1112 |

> Actividad diseñada específicamente para evaluar la detección de técnicas que
> no introducen ningún binario ajeno al sistema, y que por tanto eluden los
> controles basados en firma o reputación de ficheros.

---

## M10 — Robo de información del usuario

Recopilación de documentación personal y credenciales almacenadas en el perfil
del usuario.

**Secuencia**

1. Buscar documentos
2. Buscar PDF
3. Buscar Excel
4. Buscar contraseñas en navegadores
5. Copiar información
6. Comprimir
7. Mover al recurso compartido

**Técnicas**

| Táctica | Técnica | ID |
|---|---|---|
| Discovery | File and Directory Discovery | T1083 |
| Collection | Data from Local System | T1005 |
| Credential Access | Credentials from Password Stores: Credentials from Web Browsers | T1555.003 |
| Credential Access | Unsecured Credentials: Credentials In Files | T1552.001 |
| Collection | Archive Collected Data: Archive via Utility | T1560.001 |
| Exfiltration | Exfiltration Over Alternative Protocol | T1048 |

---

## M11 — Ataque con PsExec (movimiento lateral)

Ejecución remota de código mediante recursos administrativos compartidos.

**Secuencia**

1. Enumerar equipos del dominio
2. Comprobar conectividad SMB
3. Copiar un ejecutable al equipo remoto mediante `ADMIN$`
4. Ejecutarlo con PsExec
5. Abrir una consola remota
6. Ejecutar varios comandos
7. Eliminar el ejecutable

**Técnicas**

| Táctica | Técnica | ID |
|---|---|---|
| Discovery | Remote System Discovery | T1018 |
| Discovery | Network Share Discovery | T1135 |
| Lateral Movement | Remote Services: SMB/Windows Admin Shares | T1021.002 |
| Lateral Movement | Lateral Tool Transfer | T1570 |
| Execution | System Services: Service Execution | T1569.002 |
| Defense Evasion | Indicator Removal: File Deletion | T1070.004 |

---

## M12 — Abuso de tareas programadas

Ciclo completo de creación, modificación y eliminación de una tarea programada
como mecanismo de persistencia.

**Secuencia**

1. Crear un script PowerShell
2. Crear una Scheduled Task
3. Configurar ejecución al iniciar sesión
4. Ejecutarla manualmente
5. Modificar la tarea
6. Eliminar la tarea

**Técnicas**

| Táctica | Técnica | ID |
|---|---|---|
| Execution | Command and Scripting Interpreter: PowerShell | T1059.001 |
| Persistence | Scheduled Task/Job: Scheduled Task | T1053.005 |
| Privilege Escalation | Scheduled Task/Job: Scheduled Task | T1053.005 |
| Defense Evasion | Indicator Removal: File Deletion | T1070.004 |

> La eliminación final de la tarea reproduce el comportamiento de un adversario
> que retira sus mecanismos tras completar el objetivo, dificultando el análisis
> forense posterior.

---

## M13 — Reconocimiento mediante WMI

Enumeración del sistema empleando exclusivamente la infraestructura de gestión
de Windows.

**Secuencia**

1. Consultar procesos mediante WMI
2. Enumerar servicios
3. Enumerar discos
4. Enumerar usuarios conectados
5. Consultar software instalado
6. Ejecutar un comando remoto vía WMI

**Técnicas**

| Táctica | Técnica | ID |
|---|---|---|
| Execution | Windows Management Instrumentation | T1047 |
| Discovery | Process Discovery | T1057 |
| Discovery | System Service Discovery | T1007 |
| Discovery | System Information Discovery | T1082 |
| Discovery | System Owner/User Discovery | T1033 |
| Discovery | Software Discovery | T1518 |
| Lateral Movement | Remote Services | T1021 |

---

## M14 — Manipulación del Registro

Modificación de claves del Registro con fines de persistencia y evasión.

**Secuencia**

1. Enumerar claves del Registro
2. Crear una Run Key
3. Modificar asociaciones de archivos
4. Cambiar políticas de PowerShell
5. Crear una nueva clave
6. Eliminar evidencias

**Técnicas**

| Táctica | Técnica | ID |
|---|---|---|
| Discovery | Query Registry | T1012 |
| Persistence | Boot or Logon Autostart Execution: Registry Run Keys | T1547.001 |
| Persistence | Event Triggered Execution: Change Default File Association | T1546.001 |
| Defense Evasion | Modify Registry | T1112 |
| Defense Evasion | Impair Defenses: Disable or Modify Tools | T1562.001 |
| Defense Evasion | Indicator Removal | T1070 |

---

## M15 — Enumeración y acceso a recursos compartidos

Descubrimiento sistemático de recursos de red y sustracción de su contenido.

**Secuencia**

1. Enumerar shares SMB
2. Acceder a varios recursos
3. Buscar documentos
4. Copiar información sensible
5. Comprimir los datos
6. Transferir el ZIP a otro recurso compartido

**Técnicas**

| Táctica | Técnica | ID |
|---|---|---|
| Discovery | Network Share Discovery | T1135 |
| Discovery | File and Directory Discovery | T1083 |
| Lateral Movement | Remote Services: SMB/Windows Admin Shares | T1021.002 |
| Collection | Data from Network Shared Drive | T1039 |
| Collection | Archive Collected Data: Archive via Utility | T1560.001 |
| Exfiltration | Exfiltration Over Alternative Protocol | T1048 |

---

## M16 — Creación de un usuario oculto en el dominio

Establecimiento de una cuenta administrativa encubierta como mecanismo de
acceso persistente.

**Secuencia**

1. Inicio de sesión como administrador comprometido
2. Crear un nuevo usuario
3. Añadirlo a Domain Admins
4. Ocultar el usuario de la pantalla de inicio
5. Iniciar sesión con la nueva cuenta

**Técnicas**

| Táctica | Técnica | ID |
|---|---|---|
| Defense Evasion | Valid Accounts: Domain Accounts | T1078.002 |
| Persistence | Create Account: Domain Account | T1136.002 |
| Privilege Escalation | Account Manipulation | T1098 |
| Defense Evasion | Hide Artifacts: Hidden Users | T1564.002 |

> Es la actividad maliciosa con mayor solapamiento respecto a la administración
> legítima: los pasos 2 y 3 son idénticos a los de las actividades benignas B02,
> B08 y B10. Únicamente el paso 4 introduce un indicador propio.

---

## M17 — Manipulación de políticas de grupo

Alteración de la configuración de seguridad del dominio mediante políticas de
grupo.

**Secuencia**

1. Abrir GPMC
2. Modificar una GPO
3. Desactivar Windows Defender
4. Forzar `gpupdate`
5. Verificar la aplicación de la política

**Técnicas**

| Táctica | Técnica | ID |
|---|---|---|
| Defense Evasion | Domain or Tenant Policy Modification: Group Policy Modification | T1484.001 |
| Defense Evasion | Impair Defenses: Disable or Modify Tools | T1562.001 |
| Discovery | Group Policy Discovery | T1615 |

> La modificación de GPO es un mecanismo de persistencia de alcance
> organizativo: afecta a todos los equipos del dominio y sobrevive a la
> remediación de un endpoint individual.

---

## M18 — Descarga y ejecución mediante PowerShell

Obtención de código desde un servidor interno, ejecución y eliminación
posterior del rastro.

**Secuencia**

1. Abrir PowerShell
2. Descargar un script desde un servidor HTTP interno
3. Guardarlo en `%TEMP%`
4. Ejecutarlo
5. Eliminar el script
6. Vaciar el historial de PowerShell

**Técnicas**

| Táctica | Técnica | ID |
|---|---|---|
| Execution | Command and Scripting Interpreter: PowerShell | T1059.001 |
| Command and Control | Ingress Tool Transfer | T1105 |
| Command and Control | Application Layer Protocol: Web Protocols | T1071.001 |
| Defense Evasion | Indicator Removal: File Deletion | T1070.004 |
| Defense Evasion | Indicator Removal: Clear Command History | T1070.003 |

---


## Cobertura de tácticas

| Táctica | Actividades |
|---|---|
| Reconnaissance / Discovery | M01, M02, M03, M05, M06, M07, M09, M10, M11, M13, M14, M15, M17, M19 |
| Execution | M01, M03, M07, M08, M09, M12, M13, M18 |
| Persistence | M03, M04, M08, M09, M12, M14, M16, M17 |
| Privilege Escalation | M04, M08, M12, M16, M17 |
| Defense Evasion | M02, M04, M05, M06, M08, M09, M11, M12, M14, M16, M17, M18 |
| Credential Access | M02, M03, M10 |
| Lateral Movement | M03, M11, M13, M15 |
| Collection | M02, M05, M06, M10, M15, M19 |
| Command and Control | M01, M09, M18 |
| Exfiltration | M02, M05, M10, M15 |
| Impact | M04, M06, M08 |

## Técnicas más frecuentes

| Técnica | ID | Actividades |
|---|---|---|
| Command and Scripting Interpreter: PowerShell | T1059.001 | M01, M03, M09, M12, M18 |
| Network Share Discovery | T1135 | M01, M06, M11, M15 |
| Archive Collected Data: Archive via Utility | T1560.001 | M02, M05, M10, M15 |
| Exfiltration Over Alternative Protocol | T1048 | M02, M05, M10, M15 |
| Indicator Removal: File Deletion | T1070.004 | M05, M11, M12, M18 |
| Remote System Discovery | T1018 | M01, M03, M07, M11 |
| Scheduled Task/Job: Scheduled Task | T1053.005 | M03, M04, M09, M12 |
| Account Discovery: Domain Account | T1087.002 | M01, M07, M19 |
| Impair Defenses: Disable or Modify Tools | T1562.001 | M06, M14, M17 |

---

## Notas de captura

- No se empleó malware ni herramientas ofensivas externas al sistema operativo,
  con la salvedad de PsExec (Sysinternals) en M11.
- El cifrado de M06 se sustituye por renombrado masivo, preservando la
  telemetría de la técnica sin causar daño irreversible.
- La configuración de auditoría del entorno permaneció invariable durante toda
  la campaña de captura, en las mismas condiciones que las actividades
  benignas. Las subcategorías de auditoría de acceso a objetos no se
  encontraban habilitadas, por lo que los eventos 4663, 4660, 5140 y 5145 no
  están presentes en el conjunto.
- El conjunto de datos no contiene eventos Sysmon 10 (acceso a proceso), lo que
  limita la observabilidad de la técnica T1003.001 en M02.