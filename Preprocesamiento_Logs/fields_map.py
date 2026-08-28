event_fields_map = {
    "wineventlog:security": {
        # 4624, 4634, 4647, 4648, 4662, 4672, 4688, 4696, 4768, 4769, 4798, 4799, 5058, 5059, 5061, 5379, 5382
        # Log de auditoria borrado
        "1102": [
            "_time",
            "host",
            "EventCode",
            "Account_Name",
            "Account_Domain",
            "Security_ID",
            "Process_Name"
        ],
        # Cambio en la hora del sistema
        "4616" : [
            "_time",
            "host",
            "EventCode",
            "Account_Name",
            "Account_Domain",
            "Security_ID",
            "Logon_ID",
            "Process_IDUser",
            "Name",
            "Previous_Time",
            "New_Time"
        ],
        # Log in 
        "4624": [
            "_time",
            "host",
            "EventCode",
            "Logon_Type",
            "Authentication_Package",
            "Logon_Process",
            "Source_Network_Address",
            "Source_Port",
            "Logon_GUID",
            "Logon_ID",
            "Impersonation_Level",
            "Elevated_Token",
            "Account_Name",
            "Account_Domain",
            "Security_ID",
            "Workstation_Name",
            "Process_Name",
            "Process_ID"
        ],
        # Logon fallido
        "4625": [
            "_time",
            "host",
            "EventCode",
            "Account_Name",
            "Account_Domain",
            "Security_ID",
            "Logon_Type",
            "Status",
            "Sub_Status",
            "Failure_Reason",
            "Logon_Process",
            "Authentication_Package",
            "Workstation_Name",
            "Source_Network_Address",
            "Source_Port",
            "Process_ID",
            "Process_Name"
        ],
        # Log off
        "4634": [
            "_time",
            "host",
            "EventCode",
            "Account_Name",
            "Account_Domain",
            "Security_ID",
            "Logon_ID",
            "Logon_Type"
        ],
        # Cierre de sesion explicito
        "4647": [
           "_time",
            "host",
            "EventCode",
            "Account_Name",
            "Account_Domain",
            "Security_ID",
            "Logon_ID"
        ],
        # Uso de credenciales explicitas
        "4648": [
            "_time",
            "host",
            "EventCode",
            "Account_Name",
            "Account_Domain",
            "Security_ID",
            "Logon_ID",
            "TargetUserName",
            "TargetDomainName",
            "Process_ID",
            "Process_Name",
            "Target_Server_Name",
            "Network_Address",
            "Port",
            "Additional_Information"
        ],
        # Handle a objeto solicitado
        "4656": [
            "_time",
            "host",
            "EventCode",
            "Account_Name",
            "Account_Domain",
            "Security_ID",
            "Logon_ID",
            "Object_Server",
            "Object_Type",
            "Object_Name",
            "Handle_ID",
            "Access_List",
            "Access_Mask",
            "Process_ID",
            "Process_Name"
        ],
        # Valor de registro modificado
        "4657": [
            "_time",
            "host",
            "EventCode",
            "Account_Name",
            "Account_Domain",
            "Security_ID",
            "Logon_ID",
            "Object_Name",
            "Object_Value_Name",
            "Old_Value",
            "New_Value",
            "Process_ID",
            "Process_Name"
        ],
        # Objeto eliminado
        "4660": [
            "_time",
            "host",
            "EventCode",
            "Account_Name",
            "Account_Domain",
            "Security_ID",
            "Logon_ID",
            "Object_Server",
            "Handle_ID",
            "Process_ID",
            "Process_Name"
        ],
        # Handle a objeto cerrado
        "4661": [
            "_time",
            "host",
            "EventCode",
            "Account_Name",
            "Account_Domain",
            "Security_ID",
            "Logon_ID",
            "Object_Server",
            "Object_Type",
            "Object_Name",
            "Handle_ID",
            "Process_ID"
        ],
        # Acceso a objeto de Active directory
        "4662": [
            "_time",
            "host",
            "EventCode",
            "Account_Name",
            "Account_Domain",
            "Security_ID",
            "Logon_ID",
            "Object_Server",
            "Object_Type",
            "Object_Name",
            "Operation_Type",
            "Access_Mask",
            "Accesses",
            "Properties"
        ],
        # Intento de acceso a objeto
        "4663": [
            "_time",
            "host",
            "EventCode",
            "Account_Name",
            "Account_Domain",
            "Security_ID",
            "Logon_ID",
            "Object_Server",
            "Object_Type",
            "Object_Name",
            "Handle_ID",
            "Access_List",
            "Process_ID",
            "Process_Name"
        ],
        # Permisos modificados en objeto
        "4670": [
            "_time",
            "host",
            "EventCode",
            "Account_Name",
            "Account_Domain",
            "Security_ID",
            "Logon_ID",
            "Object_Server",
            "Object_Type",
            "Object_Name",
            "Handle_ID",
            "Old_Sd",
            "New_Sd"
        ],
        # Login privilegiado
        "4672": [
            "_time",
            "host",
            "EventCode",
            "Account_Name",
            "Account_Domain",
            "Security_ID",
            "Logon_ID",
            "Privileges"
        ],
        # Uso de privilegio sensible
        "4673": [
            "_time",
            "host",
            "EventCode",
            "Account_Name",
            "Account_Domain",
            "Security_ID",
            "Logon_ID",
            "Service_Name",
            "Process_Name",
            "Privileges"
        ],
        # Operacion intentada sobre objeto privilegiado
        "4674": [
            "_time",
            "host",
            "EventCode",
            "Account_Name",
            "Account_Domain",
            "Security_ID",
            "Logon_ID",
            "Object_Server",
            "Object_Name",
            "Object_Type",
            "Process_ID",
            "Process_Name",
            "Privileges"
        ],
        # Creacion de proceso
        "4688": [
            "_time",
            "host",
            "EventCode",
            "Account_Name",
            "Account_Domain",
            "Security_ID",
            "Logon_ID",
            "New_Process_ID",
            "New_Process_Name",
            "Process_ID",
            "Process_Name",
            "Creator_Process_ID",
            "Creator_Process_Name",
            "Process_Command_Line",
            "Token_Elevation_Type",
            "Mandatory_Label"
        ],
        # Finalizacion de proceso
        "4689": [
            "_time",
            "host",
            "EventCode",
            "Account_Name",
            "Account_Domain",
            "Security_ID",
            "Logon_ID",
            "Status",
            "Process_ID",
            "Process_Name"
        ],
        # asignacion de un token primario a un proceso
        "4696": [
            "_time",
            "host",
            "EventCode",
            "Account_Name",
            "Account_Domain",
            "Security_ID",
            "Logon_ID",
            "Process_ID",
            "Target_Process_ID",
            "Target_Process_Name"
        ],
        # Servicio instalado
        "4697": [
            "_time",
            "host",
            "EventCode",
            "Account_Name",
            "Account_Domain",
            "Security_ID",
            "Logon_ID",
            "Service_Name",
            "Service_File_Name",
            "Service_Type",
            "Service_Start_Type",
            "Service_Account"
        ],
        # Tarea programada creada
        "4698": [
            "_time",
            "host",
            "EventCode",
            "Account_Name",
            "Account_Domain",
            "Security_ID",
            "Logon_ID",
            "Task_Name",
            "Task_Content"
        ],
        # Tarea programada eliminada
        "4699": [
            "_time",
            "host",
            "EventCode",
            "Account_Name",
            "Account_Domain",
            "Security_ID",
            "Logon_ID",
            "Task_Name"
        ],
        # Tarea programada actualizada
        "4702": [
            "_time",
            "host",
            "EventCode",
            "Account_Name",
            "Account_Domain",
            "Security_ID",
            "Logon_ID",
            "Task_Name",
            "Task_Content"
        ],
        # Cambio en politica de auditoria del sistema
        "4719": [
            "_time",
            "host",
            "EventCode",
            "Account_Name",
            "Account_Domain",
            "Security_ID",
            "Logon_ID",
            "Category_ID",
            "Subcategory_ID",
            "Subcategory_Guid",
            "Audit_Policy_Changes"
        ],
        # Usuario creado
        "4720": [
            "_time",
            "host",
            "EventCode",
            "Target_Account_Name",
            "Target_Domain_Name",
            "Target_Sid",
            "Account_Name",
            "Account_Domain",
            "Security_ID",
            "Logon_ID",
            "Sam_Account_Name",
            "Display_Name",
            "User_Principal_Name",
            "Primary_Group_Id"
        ],
        # Usuario habilitado
        "4722": [
            "_time",
            "host",
            "EventCode",
            "Target_Account_Name",
            "Target_Domain_Name",
            "Target_Sid",
            "Account_Name",
            "Account_Domain",
            "Security_ID",
            "Logon_ID"
        ],
        # Intento de cambio de contraseña
        "4723": [
            "_time",
            "host",
            "EventCode",
            "Target_Account_Name",
            "Target_Domain_Name",
            "Target_Sid",
            "Account_Name",
            "Account_Domain",
            "Security_ID",
            "Logon_ID"
        ],
        # Intento de reseteo de contraseña
        "4724": [
            "_time",
            "host",
            "EventCode",
            "Target_Account_Name",
            "Target_Domain_Name",
            "Target_Sid",
            "Account_Name",
            "Account_Domain",
            "Security_ID",
            "Logon_ID"
        ],
        # Usuario deshabilitado
        "4725": [
            "_time",
            "host",
            "EventCode",
            "Target_Account_Name",
            "Target_Domain_Name",
            "Target_Sid",
            "Account_Name",
            "Account_Domain",
            "Security_ID",
            "Logon_ID"
        ],
        # Usuario eliminado
        "4726": [
            "_time",
            "host",
            "EventCode",
            "Target_Account_Name",
            "Target_Domain_Name",
            "Target_Sid",
            "Account_Name",
            "Account_Domain",
            "Security_ID",
            "Logon_ID"
        ],
        # Miembro añadido a grupo global (ej. Domain Admins)
        "4728": [
            "_time",
            "host",
            "EventCode",
            "Target_Account_Name",
            "Target_Domain_Name",
            "Target_Sid",
            "Member_Name",
            "Member_Sid",
            "Account_Name",
            "Account_Domain",
            "Security_ID",
            "Logon_ID"
        ],
        # Miembro añadido a grupo local
        "4732": [
            "_time",
            "host",
            "EventCode",
            "Target_Account_Name",
            "Target_Domain_Name",
            "Target_Sid",
            "Member_Name",
            "Member_Sid",
            "Account_Name",
            "Account_Domain",
            "Security_ID",
            "Logon_ID"
        ],
        # Miembro eliminado de grupo local
        "4733": [
            "_time",
            "host",
            "EventCode",
            "Target_Account_Name",
            "Target_Domain_Name",
            "Target_Sid",
            "Member_Name",
            "Member_Sid",
            "Account_Name",
            "Account_Domain",
            "Security_ID",
            "Logon_ID"
        ],
        # Cuenta de usuario modificada
        "4738": [
            "_time",
            "host",
            "EventCode",
            "Target_Account_Name",
            "Target_Domain_Name",
            "Target_Sid",
            "Account_Name",
            "Account_Domain",
            "Security_ID",
            "Logon_ID"
        ],
        # Politica de dominio modificada
        "4739": [
            "_time",
            "host",
            "EventCode",
            "Domain_Name",
            "Domain_Sid",
            "Account_Name",
            "Account_Domain",
            "Security_ID",
            "Logon_ID"
        ],
        # Cuenta de usuario bloqueada
        "4740": [
            "_time",
            "host",
            "EventCode",
            "Target_Account_Name",
            "Target_Domain_Name",
            "Target_Sid",
            "Caller_Computer_Name",
            "Account_Name",
            "Account_Domain",
            "Security_ID",
            "Logon_ID"
        ],
        # Cuenta de equipo modificada (ej. Zerologon)
        "4742": [
            "_time",
            "host",
            "EventCode",
            "Target_Account_Name",
            "Target_Domain_Name",
            "Target_Sid",
            "Account_Name",
            "Account_Domain",
            "Security_ID",
            "Logon_ID",
            "New_Uac_Value",
            "Old_Uac_Value",
            "Sam_Account_Name",
            "Dns_Host_Name"
        ],
        # Cuenta de equipo eliminada
        "4743": [
            "_time",
            "host",
            "EventCode",
            "Target_Account_Name",
            "Target_Domain_Name",
            "Target_Sid",
            "Account_Name",
            "Account_Domain",
            "Security_ID",
            "Logon_ID"
        ],
        # Miembro añadido a grupo universal
        "4756": [
            "_time",
            "host",
            "EventCode",
            "Target_Account_Name",
            "Target_Domain_Name",
            "Target_Sid",
            "Member_Name",
            "Member_Sid",
            "Account_Name",
            "Account_Domain",
            "Security_ID",
            "Logon_ID"
        ],
        # peticion de un ticket kerberos TGT
        "4768": [
            "_time",
            "host",
            "EventCode",
            "Account_Name",
            "User_ID",
            "Service_Name",
            "Service_ID",
            "Client_Address",
            "Client_Port",
            "Result_Code",
            "Pre_Authentication_Type",
            "Ticket_Encryption_Type",
            "Ticket_Options",
            "Supplied_Realm_Name"
        ],
        # peticion de un ticket kerberos TGS
        "4769": [
            "_time",
            "host",
            "EventCode",
            "Account_Name",
            "Account_Domain",
            "Service_Name",
            "Service_ID",
            "Client_Address",
            "Client_Port",
            "Failure_Code",
            "Ticket_Encryption_Type",
            "Ticket_Options",
            "Logon_GUID",
            "Transited_Services"
        ],
        # Renovacion de ticket TGT
        "4770": [
            "_time",
            "host",
            "EventCode",
            "Account_Name",
            "Account_Domain",
            "Service_Name",
            "Service_ID",
            "Client_Address",
            "Client_Port",
            "Ticket_Encryption_Type",
            "Ticket_Options"
        ],
        # Fallo de pre-autenticacion Kerberos
        "4771": [
            "_time",
            "host",
            "EventCode",
            "Account_Name",
            "Security_ID",
            "Service_Name",
            "Client_Address",
            "Client_Port",
            "Failure_Code",
            "Pre_Authentication_Type",
            "Ticket_Options"
        ],
        # Validacion de credenciales (NTLM)
        "4776": [
            "_time",
            "host",
            "EventCode",
            "Logon_Account",
            "Source_Workstation",
            "Error_Code"
        ],
        # Sesion RDP reconectada
        "4778": [
            "_time",
            "host",
            "EventCode",
            "Account_Name",
            "Account_Domain",
            "Security_ID",
            "Logon_ID",
            "Session_Name",
            "Client_Name",
            "Client_Address"
        ],
        # Sesion RDP desconectada
        "4779": [
            "_time",
            "host",
            "EventCode",
            "Account_Name",
            "Account_Domain",
            "Security_ID",
            "Logon_ID",
            "Session_Name",
            "Client_Name",
            "Client_Address"
        ],
        # enumeracion de pertenencia a grupos locales de un usuario
        "4798": [
            "_time",
            "host",
            "EventCode",
            "Account_Name",
            "Account_Domain",
            "Security_ID",
            "Logon_ID",
            "Process_ID",
            "Process_Name"
        ],
        # enumeración de los miembros de un grupo local de seguridad
        "4799": [
            "_time",
            "host",
            "EventCode",
            "Account_Name",
            "Account_Domain",
            "Security_ID",
            "Logon_ID",
            "Process_ID",
            "Process_Name",
            "Group_Name",
            "Group_Domain"
        ],
        # Tabla de politica de auditoria por usuario creada
        "4902": [
            "_time",
            "host",
            "EventCode",
            "Account_Name",
            "Account_Domain",
            "Security_ID",
            "Logon_ID",
            "Policy_ID"
        ],
        # Regla añadida al firewall (MPSSVC)
        "4946": [
            "_time",
            "host",
            "EventCode",
            "Profile_Changed",
            "Rule_ID",
            "Rule_Name",
            "Account_Name",
            "Account_Domain",
            "Security_ID"
        ],
        # Configuracion del firewall modificada
        "4950": [
            "_time",
            "host",
            "EventCode",
            "Setting_Type",
            "New_Value",
            "Profile_Changed",
            "Account_Name",
            "Account_Domain",
            "Security_ID"
        ],
        # Perfil activo del firewall cambiado
        "4956": [
            "_time",
            "host",
            "EventCode",
            "Profile_Changed"
        ],
        # Regla de firewall no procesada
        "4957": [
            "_time",
            "host",
            "EventCode",
            "Rule_ID",
            "Rule_Name"
        ],
        # registra operaciones sobre claves criptogrtaficas
        "5058": [
            "_time",
            "host",
            "EventCode",
            "Account_Name",
            "Account_Domain",
            "Security_ID",
            "Logon_ID",
            "Process_ID",
            "Process_Creation_Time",
            "Algorithm_Name",
            "Provider_Name",
            "Operation",
            "Key_Name",
            "Key_Type",
            "File_Path",
            "Return_Code"
        ],
        # registra operación de migración/exportación de una clave criptográfica
        "5059": [
            "_time",
            "host",
            "EventCode",
            "Account_Name",
            "Account_Domain",
            "Security_ID",
            "Logon_ID",
            "Process_ID",
            "Process_Creation_Time",
            "Provider_Name",
            "Operation",
            "Key_Name",
            "Key_Type",
            "Algorithm_Name",
            "Return_Code"
        ],
        # registra operación criptográfica sobre una clave
        "5061": [
            "_time",
            "host",
            "EventCode",
            "Account_Name",
            "Account_Domain",
            "Security_ID",
            "Logon_ID",
            "Provider_Name",
            "Operation",
            "Key_Name",
            "Key_Type",
            "Algorithm_Name",
            "Return_Code"
        ],
        # Objeto de directorio modificado (GPO, etc.)
        "5136": [
            "_time",
            "host",
            "EventCode",
            "Account_Name",
            "Account_Domain",
            "Security_ID",
            "Logon_ID",
            "Object_DN",
            "Object_GUID",
            "Object_Class",
            "Attribute_LDAP_Display_Name",
            "Attribute_Value",
            "Operation_Type"
        ],
        # Acceso a recurso compartido
        "5140": [
            "_time",
            "host",
            "EventCode",
            "Account_Name",
            "Account_Domain",
            "Security_ID",
            "Logon_ID",
            "Source_Address",
            "Source_Port",
            "Share_Name",
            "Share_Path"
        ],
        # Comprobacion de acceso detallada a recurso compartido
        "5145": [
            "_time",
            "host",
            "EventCode",
            "Account_Name",
            "Account_Domain",
            "Security_ID",
            "Logon_ID",
            "Source_Address",
            "Source_Port",
            "Share_Name",
            "Share_Path",
            "Relative_Target_Name",
            "Access_Mask",
            "Access_List"
        ],
        # Objeto de Credential Manager creado/modificado (previo a 5379)
        "5378": [
            "_time",
            "host",
            "EventCode",
            "TaskCategory",
            "Keywords",
            "Account_Domain",
            "Account_Name",
            "Security_ID",
            "Logon_ID"
        ],
        # Lectura de credenciales en Credential Manager
        "5379": [
            "_time",
            "host",
            "EventCode",
            "TaskCategory",
            "Keywords",
            "Account_Domain",
            "Account_Name",
            "Security_ID",
            "Logon_ID",
            "Read_Operation"
        ],
        # Lectura de credeniales del Valut
        "5382": [
            "_time",
            "host",
            "EventCode",
            "TaskCategory",
            "Keywords",
            "Account_Domain",
            "Account_Name",
            "Security_ID",
            "Logon_ID"
        ]
    },
    "wineventlog:microsoft-windows-sysmon/operational": {
        # 1, 2, 4, 8, 11, 12, 13, 22
        # Process Create
        "1": [
            "_time",
            "host",
            "EventCode",
            "UtcTime",
            "Image",
            "CommandLine",
            "ProcessGuid",
            "ProcessId",
            "ParentImage",
            "ParentCommandLine",
            "ParentProcessGuid",
            "ParentProcessId",
            "ParentUser",
            "LogonGuid",
            "LogonId",
            "IntegrityLevel",
            "CurrentDirectory",
            "TerminalSessionId"
        ],
        # File Creation Time Changed
        "2": [
            "_time",
            "host",
            "EventCode",
            "UtcTime",
            "Image",
            "ProcessGuid",
            "ProcessId",
            "TargetFilename",
            "CreationUtcTime",
            "PreviousCreationUtcTime",
            "RuleName"
        ],
         "3": [
            "_time",
            "host",
            "EventCode",
            "UtcTime",
            "Image",
            "ProcessGuid",
            "ProcessId",
            "User",
            "Protocol",
            "Initiated",
            "SourceIsIpv6",
            "SourceIp",
            "SourceHostname",
            "SourcePort",
            "DestinationIsIpv6",
            "DestinationIp",
            "DestinationHostname",
            "DestinationPort"
        ],
        # Sysmon started
        # dudas si eliminarlo
        "4": [
            "_time",
            "host",
            "EventCode",
            "UtcTime",
            "State",
            "Version",
            "SchemaVersion"
        ],
        # Image/DLL Loaded
        "7": [
            "_time",
            "host",
            "EventCode",
            "UtcTime",
            "Image",
            "ProcessGuid",
            "ProcessId",
            "ImageLoaded",
            "Signed",
            "Signature",
            "SignatureStatus",
            "Hashes"
        ],
        # create remote threat
        "8": [
            "_time",
            "host",
            "EventCode",
            "UtcTime",
            "SourceImage",
            "SourceProcessGuid",
            "SourceProcessId",
            "SourceUser",
            "TargetImage",
            "TargetProcessGuid",
            "TargetProcessId",
            "TargetUser",
            "StartAddress",
            "StartModule",
            "StartFunction",
            "NewThreadId"
        ],
        # Process Access (acceso a otro proceso, ej. lsass.exe)
        "10": [
            "_time",
            "host",
            "EventCode",
            "UtcTime",
            "SourceImage",
            "SourceProcessGuid",
            "SourceProcessId",
            "SourceUser",
            "TargetImage",
            "TargetProcessGuid",
            "TargetProcessId",
            "TargetUser",
            "GrantedAccess",
            "CallTrace"
        ],
        # FileCreate
        "11": [
            "_time",
            "host",
            "EventCode",
            "UtcTime",
            "Image",
            "ProcessGuid",
            "ProcessId",
            "TargetFilename",
            "CreationUtcTime",
            "User"
        ],
        # Registry object added or deleted
        "12": [
            "_time",
            "host",
            "EventCode",
            "UtcTime",
            "Image",
            "ProcessGuid",
            "ProcessId",
            "TargetObject"
        ],
        # Registry value set
        "13": [
            "_time",
            "host",
            "EventCode",
            "UtcTime",
            "Image",
            "ProcessGuid",
            "ProcessId",
            "TargetObject",
            "Details"
        ],
        # Registry Key/Value Rename
        "14": [
            "_time",
            "host",
            "EventCode",
            "UtcTime",
            "Image",
            "ProcessGuid",
            "ProcessId",
            "EventType",
            "TargetObject",
            "NewName"
        ],
        # DNS Query
        "22": [
            "_time",
            "host",
            "EventCode",
            "UtcTime",
            "Image",
            "ProcessGuid",
            "ProcessId",
            "QueryName",
            "QueryResults",
            "QueryStatus"
        ],
        # File Delete (Archived / logged delete)
        "23": [
            "_time",
            "host",
            "EventCode",
            "UtcTime",
            "Image",
            "ProcessGuid",
            "ProcessId",
            "User",
            "TargetFilename",
            "Hashes",
            "IsExecutable",
            "Archived"
        ],
    },
}
