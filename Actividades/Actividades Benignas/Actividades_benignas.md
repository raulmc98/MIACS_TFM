# Actividades benignas

Catálogo de sesiones de actividad legítima capturadas en el laboratorio.

Cada actividad corresponde a una sesión completa de administración o uso
ordinario de sistemas, ejecutada manualmente en el entorno de pruebas y
exportada desde Splunk como un único fichero JSON.

## Criterio de diseño

La actividad benigna **no** se construyó como contraste trivial de la
maliciosa. El criterio adoptado es que sea *composicionalmente similar*: que
genere los mismos identificadores de evento que las técnicas adversarias, de
modo que las clases no resulten separables por el vocabulario de eventos que
contienen sino únicamente por su composición y ordenación.

Por ello cada actividad incluye una columna de **técnica adversaria
equivalente**: la técnica ATT&CK que produciría telemetría comparable si la
misma acción fuera ejecutada con intención maliciosa. Esta correspondencia es
el fundamento de la dificultad del problema y no una anotación de que la
actividad sea sospechosa.

El solapamiento de identificadores de evento entre ambas clases resultante de
este diseño es del 92,3 %, sin ningún identificador exclusivo de la clase
maliciosa.

---

## B01 — Inicio normal de jornada

Uso ordinario de una estación de trabajo por parte de un usuario de dominio
sin privilegios administrativos.

**Secuencia**

1. Inicio de sesión
2. Abrir Outlook
3. Abrir Edge
4. Acceder a carpeta compartida
5. Abrir Word
6. Guardar documento
7. Cerrar sesión

**Correspondencia adversaria**

| Paso | Técnica equivalente | ID |
|---|---|---|
| Inicio de sesión | Valid Accounts: Domain Accounts | T1078.002 |
| Acceder a carpeta compartida | Network Share Discovery | T1135 |
| Acceder a carpeta compartida | Data from Network Shared Drive | T1039 |

---

## B02 — Administración de sistemas

Sesión administrativa completa sobre el controlador de dominio, incluyendo
gestión de cuentas y revisión de registros.

**Secuencia**

1. Inicio de sesión del administrador
2. Abrir Server Manager
3. Abrir AD Users and Computers
4. Crear usuario
5. Añadir a grupo
6. Ejecutar `gpupdate`
7. Revisar Event Viewer

**Correspondencia adversaria**

| Paso | Técnica equivalente | ID |
|---|---|---|
| Inicio de sesión del administrador | Valid Accounts: Domain Accounts | T1078.002 |
| Crear usuario | Create Account: Domain Account | T1136.002 |
| Añadir a grupo | Account Manipulation | T1098 |
| Revisar Event Viewer | Data from Local System | T1005 |

> Esta actividad genera los eventos 4720, 4722, 4724, 4728 y 4738, idénticos a
> los de la actividad maliciosa M16 (creación de usuario oculto). La distinción
> entre ambas reside exclusivamente en el contexto secuencial.

---

## B03 — Desarrollo

Sesión de trabajo de un desarrollador: edición de código, ejecución de scripts
propios y operaciones de control de versiones.

**Secuencia**

1. Abrir VS Code
2. Abrir PowerShell
3. Ejecutar scripts propios
4. Compilar proyecto
5. `git commit`
6. `git push`

**Correspondencia adversaria**

| Paso | Técnica equivalente | ID |
|---|---|---|
| Abrir PowerShell | Command and Scripting Interpreter: PowerShell | T1059.001 |
| Ejecutar scripts propios | Command and Scripting Interpreter: PowerShell | T1059.001 |
| Compilar proyecto | Ingress Tool Transfer | T1105 |

> La ejecución de scripts PowerShell no firmados es indistinguible, a nivel de
> evento 4103, de la ejecución de un script adversario.

---

## B04 — Trabajo de oficina

Uso ofimático con acceso a recursos compartidos e impresión.

**Secuencia**

1. Abrir Excel
2. Abrir Word
3. Abrir PDF
4. Navegar por recurso SMB
5. Imprimir documento
6. Cerrar aplicaciones

**Correspondencia adversaria**

| Paso | Técnica equivalente | ID |
|---|---|---|
| Navegar por recurso SMB | Network Share Discovery | T1135 |
| Navegar por recurso SMB | Data from Network Shared Drive | T1039 |
| Imprimir documento | Data from Local System | T1005 |

---

## B05 — Mantenimiento del equipo

Tareas de mantenimiento programado, incluyendo actualización, análisis
antimalware y reinicio.

**Secuencia**

1. Windows Update
2. Defender Scan
3. Limpieza de disco
4. Reinicio
5. Inicio de sesión
6. Abrir navegador
7. Abrir Outlook

**Correspondencia adversaria**

| Paso | Técnica equivalente | ID |
|---|---|---|
| Limpieza de disco | Indicator Removal: File Deletion | T1070.004 |
| Reinicio | System Shutdown/Reboot | T1529 |
| Defender Scan | *(interacción con Defender; comparable a T1562.001 en su telemetría)* | T1562.001 |

> El borrado masivo de ficheros temporales produce eventos Sysmon 23 en
> volumen comparable al de la actividad maliciosa M05 (limpieza de rastro).

---

## B06 — Cambio de contraseña de usuario

Renovación de credenciales por parte del propio usuario y verificación de
acceso posterior.

**Secuencia**

1. Inicio de sesión
2. Cambio de contraseña
3. Cierre de sesión
4. Inicio con la nueva contraseña
5. Acceso a recursos compartidos

**Correspondencia adversaria**

| Paso | Técnica equivalente | ID |
|---|---|---|
| Cambio de contraseña | Account Manipulation | T1098 |
| Inicio con la nueva contraseña | Valid Accounts: Domain Accounts | T1078.002 |
| Acceso a recursos compartidos | Data from Network Shared Drive | T1039 |

> Genera los eventos 4723 y 4724, los mismos que produce el restablecimiento de
> credenciales tras un compromiso de cuenta.

---

## B07 — Trabajo con recursos compartidos

Gestión de documentación en un recurso compartido de red: creación,
modificación, borrado y compresión.

**Secuencia**

1. Abrir Explorador
2. Acceder a `\\SOC-DC\Shares`
3. Crear carpetas
4. Copiar documentos
5. Editarlos
6. Eliminarlos
7. Crear ZIP

**Correspondencia adversaria**

| Paso | Técnica equivalente | ID |
|---|---|---|
| Acceder al recurso compartido | Network Share Discovery | T1135 |
| Copiar documentos | Data from Network Shared Drive | T1039 |
| Eliminarlos | Indicator Removal: File Deletion | T1070.004 |
| Crear ZIP | Archive Collected Data: Archive via Utility | T1560.001 |

> Es la actividad benigna con mayor solapamiento estructural respecto a la
> exfiltración: acceso remoto, recopilación, compresión y borrado. La secuencia
> es análoga a la de M05 y M15.

---

## B08 — Administración de Active Directory

Creación de estructura organizativa y cuentas mediante la consola gráfica de
administración.

**Secuencia**

1. Abrir ADUC
2. Crear OU
3. Crear grupo
4. Crear usuario
5. Añadir usuario al grupo
6. Ejecutar `gpupdate`

**Correspondencia adversaria**

| Paso | Técnica equivalente | ID |
|---|---|---|
| Crear usuario | Create Account: Domain Account | T1136.002 |
| Crear grupo / añadir usuario | Account Manipulation | T1098 |
| Añadir usuario al grupo | Account Manipulation: Additional Cloud/Domain Roles | T1098.007 |

---

## B09 — Navegación y productividad

Descarga de documentación desde un recurso interno y elaboración de un
documento derivado.

**Secuencia**

1. Abrir navegador
2. Descargar un PDF desde recurso SMB interno
3. Leer el PDF
4. Abrir Word
5. Copiar contenido
6. Guardar
7. Imprimir (Microsoft Print to PDF)
8. Cerrar aplicaciones

**Correspondencia adversaria**

| Paso | Técnica equivalente | ID |
|---|---|---|
| Descargar el PDF | Ingress Tool Transfer | T1105 |
| Descargar el PDF | Data from Network Shared Drive | T1039 |
| Guardar / imprimir | Local Data Staging | T1074.001 |

> El patrón «transferencia desde recurso remoto → escritura en disco →
> generación de fichero derivado» es estructuralmente equivalente al de una
> exfiltración con preparación local.

---

## B10 — Alta de un nuevo empleado

Proceso completo de incorporación: creación de cuenta, directorio personal,
permisos y verificación desde el puesto del usuario.

**Secuencia**

1. Crear usuario en Active Directory
2. Crear carpeta personal
3. Asignar permisos NTFS
4. Añadir al grupo correspondiente
5. Forzar `gpupdate`
6. Verificar acceso desde el puesto del usuario

**Correspondencia adversaria**

| Paso | Técnica equivalente | ID |
|---|---|---|
| Crear usuario en AD | Create Account: Domain Account | T1136.002 |
| Asignar permisos NTFS | File and Directory Permissions Modification | T1222.001 |
| Añadir al grupo | Account Manipulation | T1098 |
| Verificar acceso remoto | Valid Accounts: Domain Accounts | T1078.002 |
| Verificar acceso remoto | Remote Services: SMB/Windows Admin Shares | T1021.002 |

> Combina creación de cuenta, elevación de pertenencia y modificación de
> permisos sobre objetos: la misma composición que una escalada de privilegios
> con persistencia.

---

## Resumen de correspondencias

| Técnica adversaria equivalente | ID | Actividades benignas |
|---|---|---|
| Valid Accounts: Domain Accounts | T1078.002 | B01, B02, B06, B10 |
| Create Account: Domain Account | T1136.002 | B02, B08, B10 |
| Account Manipulation | T1098 | B02, B06, B08, B10 |
| Network Share Discovery | T1135 | B01, B04, B07 |
| Data from Network Shared Drive | T1039 | B01, B04, B06, B07, B09 |
| Command and Scripting Interpreter: PowerShell | T1059.001 | B03 |
| Ingress Tool Transfer | T1105 | B03, B09 |
| Indicator Removal: File Deletion | T1070.004 | B05, B07 |
| Archive Collected Data: Archive via Utility | T1560.001 | B07 |
| File and Directory Permissions Modification | T1222.001 | B10 |
| Data from Local System | T1005 | B02, B04 |
| Local Data Staging | T1074.001 | B09 |
| Remote Services: SMB/Windows Admin Shares | T1021.002 | B10 |
| System Shutdown/Reboot | T1529 | B05 |

---

## Notas de captura

- Las sesiones se ejecutaron mediante interfaz gráfica siempre que fue posible,
  a fin de evitar que la línea de comandos introdujera indicadores no presentes
  en el uso ordinario.
- Se mantuvieron pausas irregulares entre pasos, reproduciendo el ritmo de
  interacción de un operador humano.
- La configuración de auditoría del entorno permaneció invariable durante toda
  la campaña de captura. Las subcategorías de auditoría de acceso a objetos no
  se encontraban habilitadas, por lo que los eventos 4663, 4660, 5140 y 5145 no
  están presentes en el conjunto.