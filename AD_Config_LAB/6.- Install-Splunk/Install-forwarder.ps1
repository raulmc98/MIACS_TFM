$msi = "\\DC\Software\Splunk\splunkforwarder-10.4.0-x64.msi"

if (!(Get-Service SplunkForwarder -ErrorAction SilentlyContinue)) {

    Start-Process msiexec.exe -Wait -ArgumentList @(
        "/i"
        "`"$msi`""
        "AGREETOLICENSE=Yes"
        "RECEIVING_INDEXER=192.168.1.20:9997"
        "SERVICESTARTTYPE=auto"
        "/quiet"
    )

}