<#
#########################################################
#
# michael.masuch@faps.fau.de
#
# MMa v1 2023-07-25
#
# Deinstallations-Skript zur Deinstallation von Sophos
# da kein On-Prem Support mehr und FAU-Sophos Server down
#
#   !!!ACHTUNG!!!
#       Funktioniert nicht mit eingeschalteter "Tamper-Protection" bzw. zu deutsch "Manipulations-Schutz"
#       Diese Funktion erst deaktivieren
#
#
# https://docs.sophos.com/esg/endpoint/help/en-us/help/Uninstall/index.html
# https://docs.sophos.com/esg/endpoint-security-and-control/10-6/help/en-us/esg/Endpoint-Security-and-Control/tasks/Uninstall_Sophos_security_software_TP.html
# https://scripts.itarian.com/frontend/web/topic/uninstall-sophos-endpoint-protection
# https://support.sophos.com/support/s/article/KB-000034444?language=en_US
# https://support.sophos.com/support/s/article/KB-000033686?language=en_US
# 
# 32-bit: REG QUERY HKLM\Software\Microsoft\Windows\CurrentVersion\Uninstall /s /f SOPHOS > C:\Sophos_Uninstall_Strings.txt
# 64-bit: REG QUERY HKLM\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall /s /f SOPHOS > C:\Sophos_Uninstall_Strings.txt
# Computer\HKEY_LOCAL_MACHINE\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\{644ADF05-0B2E-452C-B720-3CF1580A9368}
# DisplayName Sophos AutoUpdate
# UninstallString MsiExec.exe /X{644ADF05-0B2E-452C-B720-3CF1580A9368}
# InstallLocation C:\Program Files (x86)\Sophos\AutoUpdate\
#       Action                  String
#       Uninstall string        MsiExec.exe /X{01423865-551B-4C59-B44A-CC604BC21AF3}
#       Silent uninstall        MsiExec.exe /X{01423865-551B-4C59-B44A-CC604BC21AF3} /qn
#       Delay restart           MsiExec.exe /X{01423865-551B-4C59-B44A-CC604BC21AF3} /qn REBOOT=SUPPRESS
#       Logs created            MsiExec.exe /X{01423865-551B-4C59-B44A-CC604BC21AF3} /qn REBOOT=SUPPRESS /L*v %windir%\Temp\Uninstall_SAV10_Log.txt
#       REBOOT=ReallySuppress
#
#   net stop "Sophos AutoUpdate Service"
#   sc delete "Sophos Policy Evaluation Service"
#   
#       Von Martina:
#
#           REM if /i exist C:\%computername%.txt goto end
#           
#           
#           MsiExec.exe /X{4B1F9009-CD85-43C0-BCBD-D491908D5A52} /qn /L*v %windir%\Temp\Uninstall_SAV10_Log_32.txt
#           MsiExec.exe /X{644ADF05-0B2E-452C-B720-3CF1580A9368} /qn /L*v %windir%\Temp\Uninstall_SAV10_Log_64_1.txt
#           MsiExec.exe /X{723D5504-CE98-4785-AF5F-E91E250086B3} /qn /L*v %windir%\Temp\Uninstall_SAV10_Log_64_2.txt
#           
#           "C:\Program Files\Sophos\Endpoint Defense\SEDuninstall.exe" 
#           
#           Echo Sophos Deinstallations Script ist schon gelaufen > C:\%computername%.txt
#           
#           :end
#
#           # "C:\Program Files\Sophos\Endpoint Defense\SEDuninstall.exe"
#           
#           net stop "savservice"
#########################################################
#>

function StopSophosProcesses {
    Get-Service -DisplayName '*sophos*' | Set-Service -StartupType 'Disabled' -ErrorAction 'SilentlyContinue'
    Get-Service -DisplayName '*sophos*' | Where-Object { $_.status -eq 'Running' } | Stop-Service -Force -ErrorAction 'SilentlyContinue'
    Get-CimInstance -ClassName 'Win32_Process' -Namespace 'root/CIMV2' | Where-Object { $_.ExecutablePath -like '*\Sophos\*' } | Select-Object @{n = 'Name'; e = { $_.Name.Split('.')[0] } } | Stop-Process -Force
    
} 

function UnistallSophos {

    $RegUninstallPaths = @(
        'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall',
        'HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall'
    )
    
    $UninstallSearchFilter = { ($_.GetValue('DisplayName') -like '*Sophos*') }

    foreach ($Path in $RegUninstallPaths) {
        if (Test-Path -Path $Path) {
            Get-ChildItem -Path $Path | Where-Object $UninstallSearchFilter | ForEach-Object { 
                $TargetPath = Join-Path -Path $Path -ChildPath $($_.PSChildName) 
                $UninstallString = Get-ItemPropertyValue -Path $TargetPath -Name 'UninstallString'
                if ($UninstallString -like '*MsiExec.exe*') {
                    if ($path -like '*Wow6432Node*') {
                        Add-Content -Path "${Env:SystemRoot}\FAPS\Uninstall_SOPHOS_Unistall_Log32.txt" -Value ('{0}    Path: {1}    UninstallString: {2} ' -f ((Get-Date).ToString('yyyy-MM-dd HH:mm:ss')), $TargetPath, $UninstallString) -Encoding 'unicode' -ErrorAction 'SilentlyContinue'
                        Start-Process -FilePath "${Env:SystemRoot}\SysWOW64\msiexec.exe" -ArgumentList "/uninstall $($_.PSChildName) /qn REBOOT=SUPPRESS /L*+v ${Env:SystemRoot}\FAPS\Uninstall_SOPHOS_Unistall_Log32.txt" -Wait
                        #"/X$($_.PSChildName) /qn REBOOT=SUPPRESS %windir%\Temp\Uninstall_SAV.txt"
                    }
                    else {
                        Add-Content -Path "${Env:SystemRoot}\FAPS\Uninstall_SOPHOS_Unistall_Log64.txt" -Value ('{0}    Path: {1}    UninstallString: {2} ' -f ((Get-Date).ToString('yyyy-MM-dd HH:mm:ss')), $TargetPath, $UninstallString) -Encoding 'unicode' -ErrorAction 'SilentlyContinue'
                        Start-Process -FilePath "${Env:SystemRoot}\System32\msiexec.exe" -ArgumentList "/uninstall $($_.PSChildName) /qn REBOOT=SUPPRESS /L*+v ${Env:SystemRoot}\FAPS\Uninstall_SOPHOS_Unistall_Log64.txt" -Wait
                    }
                }
                elseif ($UninstallString -like '*SEDuninstal*') {
                    Add-Content -Path "${Env:SystemRoot}\FAPS\Uninstall_SOPHOS_SED_Unistall_Log.txt" -Value ('{0}    Path: {1}    UninstallString: {2} ' -f ((Get-Date).ToString('yyyy-MM-dd HH:mm:ss')), $TargetPath, $UninstallString) -Encoding 'unicode' -ErrorAction 'SilentlyContinue'
                    Start-Process -FilePath $UninstallString -ArgumentList '/quiet' -Wait
                }
                else {
                    Add-Content -Path "${Env:SystemRoot}\FAPS\Uninstall_SOPHOS_div_Unistall_Log.txt" -Value ('{0}    Path: {1}    UninstallString: {2} ' -f ((Get-Date).ToString('yyyy-MM-dd HH:mm:ss')), $TargetPath, $UninstallString) -Encoding 'unicode' -ErrorAction 'SilentlyContinue'
                    Start-Process -FilePath $UninstallString -Wait
                }
            }
        }
    }
}

if (-not (Test-Path -Path 'HKLM:')) {
    New-PSDrive -PSProvider 'Registry' -Root 'HKEY_LOCAL_MACHINE' -Name 'HKLM'
}

if (-not (Test-Path -Path "${Env:SystemRoot}\FAPS")) {
    New-Item -ItemType 'Directory' -Path "${Env:SystemRoot}\FAPS" | Out-Null
}

StopSophosProcesses
UnistallSophos
StopSophosProcesses
UnistallSophos



<#

    foreach ($Path in $RegUninstallPaths) {
        if (Test-Path -Path $Path) {
            Get-ChildItem -Path $Path | Where-Object $UninstallSearchFilter | ForEach-Object { 
                Join-Path -Path $Path -ChildPath $($_.PSChildName) 
                Get-ItemPropertyValue -Path (Join-Path -Path $Path -ChildPath $($_.PSChildName)) -Name 'UninstallString'
            }
        }
    }

#>



# SIG # Begin signature block
# MIIwHgYJKoZIhvcNAQcCoIIwDzCCMAsCAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCA+L6AiOG/vvNM+
# mcVYg3sM6UYEJggQ0IZsAxFn4cIJmqCCKP8wggPDMIICq6ADAgECAgEBMA0GCSqG
# SIb3DQEBCwUAMIGCMQswCQYDVQQGEwJERTErMCkGA1UECgwiVC1TeXN0ZW1zIEVu
# dGVycHJpc2UgU2VydmljZXMgR21iSDEfMB0GA1UECwwWVC1TeXN0ZW1zIFRydXN0
# IENlbnRlcjElMCMGA1UEAwwcVC1UZWxlU2VjIEdsb2JhbFJvb3QgQ2xhc3MgMjAe
# Fw0wODEwMDExMDQwMTRaFw0zMzEwMDEyMzU5NTlaMIGCMQswCQYDVQQGEwJERTEr
# MCkGA1UECgwiVC1TeXN0ZW1zIEVudGVycHJpc2UgU2VydmljZXMgR21iSDEfMB0G
# A1UECwwWVC1TeXN0ZW1zIFRydXN0IENlbnRlcjElMCMGA1UEAwwcVC1UZWxlU2Vj
# IEdsb2JhbFJvb3QgQ2xhc3MgMjCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoC
# ggEBAKpf2htf6HOR5dpc9KLmR+XzaFVgBR0CpLObWfMeiq80rfwNwtlIGe5pj8kg
# /CGqBxntsFysZcdf7QJ8e3wtG9a6uYDCGIIWhPpmsAjGVCOB5M25ST/2T243SCg4
# D8W+52hw/TmXTdLHmJFQqsREsyN9OUfpUmLWEpNetzGWQgX7dqceo/XC/Ol6xWyp
# cU/qy3i8YK/H3vTZy75+M6VulIPwNPohq+qOcqA/pN4wW++GTWqVW0NEqBAVHOUB
# V8WY8eYGKJGqIMW3UyZRQ7ILEZVY4cAPdtnAjXyB83Jwnm/+Go7ZXzXGsm80fL5I
# T+JaOdfYnXien4Y+A14Zi0Si1ccCAwEAAaNCMEAwDwYDVR0TAQH/BAUwAwEB/zAO
# BgNVHQ8BAf8EBAMCAQYwHQYDVR0OBBYEFL9ZIDYAeaCgImuM1fJh0rgsy4JKMA0G
# CSqGSIb3DQEBCwUAA4IBAQAxA6JhCx906HI2xm35TZ76IqjhgVbPzbuf6quRGTiv
# qnwVTfO2o42l9I72RKmn6CGVrT4AYhaI8AK6/GEj5jObMHprNmJ7rQQjhFhl4tsr
# iuclUzdiU1+82gFiKaKmJ3HmOiJ+wW8dlXAgSgc03+r/FYDlutd62Ft1fAV6KUd+
# QKgxE3fNQDu0UUd6LhHjRxHenWbQi9VUZvqDVep8wimJG+lvs87iBYTJLz54hWJu
# yV/BeGN0WMBIGAyZOeukzBq1eVqNFZzYFA32egdXxyKDBS08myUmPRizqUN8yMir
# ZI8Oo7+cG50w29rQGS6qPPH7M4B25M2tGU8FJ44ToW7CMIIFEjCCA/qgAwIBAgIJ
# AOML1fivJdmBMA0GCSqGSIb3DQEBCwUAMIGCMQswCQYDVQQGEwJERTErMCkGA1UE
# CgwiVC1TeXN0ZW1zIEVudGVycHJpc2UgU2VydmljZXMgR21iSDEfMB0GA1UECwwW
# VC1TeXN0ZW1zIFRydXN0IENlbnRlcjElMCMGA1UEAwwcVC1UZWxlU2VjIEdsb2Jh
# bFJvb3QgQ2xhc3MgMjAeFw0xNjAyMjIxMzM4MjJaFw0zMTAyMjIyMzU5NTlaMIGV
# MQswCQYDVQQGEwJERTFFMEMGA1UEChM8VmVyZWluIHp1ciBGb2VyZGVydW5nIGVp
# bmVzIERldXRzY2hlbiBGb3JzY2h1bmdzbmV0emVzIGUuIFYuMRAwDgYDVQQLEwdE
# Rk4tUEtJMS0wKwYDVQQDEyRERk4tVmVyZWluIENlcnRpZmljYXRpb24gQXV0aG9y
# aXR5IDIwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDLYNf/ZqFBzdL6
# h5eKc6uZTepnOVqhYIBHFU6MlbLlz87TV0uNzvhWbBVVdgfqRv3IA0VjPnDUq1SA
# sSOcvjcoqQn/BV0YD8SYmTezIPZmeBeHwp0OzEoy5xadrg6NKXkHACBU3BVfSpbX
# eLY008F0tZ3pv8B3Teq9WQfgWi9sPKUA3DW9ZQ2PfzJt8lpqS2IB7qw4NFlFNkkF
# 2njKam1bwIFrEczSPKiL+HEayjvigN0WtGd6izbqTpEpPbNRXK2oDL6dNOPRDReD
# dcQ5HrCUCxLx1WmOJfS4PSu/wI7DHjulv1UQqyquF5deM87I8/QJB+MChjFGawHF
# EAwRx1npAgMBAAGjggF0MIIBcDAOBgNVHQ8BAf8EBAMCAQYwHQYDVR0OBBYEFJPj
# 2DIm2tXxSqWRSuDqS+KiDM/hMB8GA1UdIwQYMBaAFL9ZIDYAeaCgImuM1fJh0rgs
# y4JKMBIGA1UdEwEB/wQIMAYBAf8CAQIwMwYDVR0gBCwwKjAPBg0rBgEEAYGtIYIs
# AQEEMA0GCysGAQQBga0hgiweMAgGBmeBDAECAjBMBgNVHR8ERTBDMEGgP6A9hjto
# dHRwOi8vcGtpMDMzNi50ZWxlc2VjLmRlL3JsL1RlbGVTZWNfR2xvYmFsUm9vdF9D
# bGFzc18yLmNybDCBhgYIKwYBBQUHAQEEejB4MCwGCCsGAQUFBzABhiBodHRwOi8v
# b2NzcDAzMzYudGVsZXNlYy5kZS9vY3NwcjBIBggrBgEFBQcwAoY8aHR0cDovL3Br
# aTAzMzYudGVsZXNlYy5kZS9jcnQvVGVsZVNlY19HbG9iYWxSb290X0NsYXNzXzIu
# Y2VyMA0GCSqGSIb3DQEBCwUAA4IBAQCHC/8+AptlyFYt1juamItxT9q6Kaoh+UYu
# 9bKkD64ROHk4sw50unZdnugYgpZi20wz6N35at8yvSxMR2BVf+d0a7Qsg9h5a7a3
# TVALZge17bOXrerufzDmmf0i4nJNPoRb7vnPmep/11I5LqyYAER+aTu/de7QCzsa
# zeX3DyJsR4T2pUeg/dAaNH2t0j13s+70103/w+jlkk9ZPpBHEEqwhVjAb3/4ru0I
# Qp4e1N8ULk2PvJ6Uw+ft9hj4PEnnJqinNtgs3iLNi4LY2XjiVRKjO4dEthEL1QxS
# r2mMDwbf0KJTi1eYe8/9ByT0/L3D/UqSApcb8re2z2WKGqK1chk5MIIFjTCCBHWg
# AwIBAgIQDpsYjvnQLefv21DiCEAYWjANBgkqhkiG9w0BAQwFADBlMQswCQYDVQQG
# EwJVUzEVMBMGA1UEChMMRGlnaUNlcnQgSW5jMRkwFwYDVQQLExB3d3cuZGlnaWNl
# cnQuY29tMSQwIgYDVQQDExtEaWdpQ2VydCBBc3N1cmVkIElEIFJvb3QgQ0EwHhcN
# MjIwODAxMDAwMDAwWhcNMzExMTA5MjM1OTU5WjBiMQswCQYDVQQGEwJVUzEVMBMG
# A1UEChMMRGlnaUNlcnQgSW5jMRkwFwYDVQQLExB3d3cuZGlnaWNlcnQuY29tMSEw
# HwYDVQQDExhEaWdpQ2VydCBUcnVzdGVkIFJvb3QgRzQwggIiMA0GCSqGSIb3DQEB
# AQUAA4ICDwAwggIKAoICAQC/5pBzaN675F1KPDAiMGkz7MKnJS7JIT3yithZwuEp
# pz1Yq3aaza57G4QNxDAf8xukOBbrVsaXbR2rsnnyyhHS5F/WBTxSD1Ifxp4VpX6+
# n6lXFllVcq9ok3DCsrp1mWpzMpTREEQQLt+C8weE5nQ7bXHiLQwb7iDVySAdYykt
# zuxeTsiT+CFhmzTrBcZe7FsavOvJz82sNEBfsXpm7nfISKhmV1efVFiODCu3T6cw
# 2Vbuyntd463JT17lNecxy9qTXtyOj4DatpGYQJB5w3jHtrHEtWoYOAMQjdjUN6Qu
# BX2I9YI+EJFwq1WCQTLX2wRzKm6RAXwhTNS8rhsDdV14Ztk6MUSaM0C/CNdaSaTC
# 5qmgZ92kJ7yhTzm1EVgX9yRcRo9k98FpiHaYdj1ZXUJ2h4mXaXpI8OCiEhtmmnTK
# 3kse5w5jrubU75KSOp493ADkRSWJtppEGSt+wJS00mFt6zPZxd9LBADMfRyVw4/3
# IbKyEbe7f/LVjHAsQWCqsWMYRJUadmJ+9oCw++hkpjPRiQfhvbfmQ6QYuKZ3AeEP
# lAwhHbJUKSWJbOUOUlFHdL4mrLZBdd56rF+NP8m800ERElvlEFDrMcXKchYiCd98
# THU/Y+whX8QgUWtvsauGi0/C1kVfnSD8oR7FwI+isX4KJpn15GkvmB0t9dmpsh3l
# GwIDAQABo4IBOjCCATYwDwYDVR0TAQH/BAUwAwEB/zAdBgNVHQ4EFgQU7NfjgtJx
# XWRM3y5nP+e6mK4cD08wHwYDVR0jBBgwFoAUReuir/SSy4IxLVGLp6chnfNtyA8w
# DgYDVR0PAQH/BAQDAgGGMHkGCCsGAQUFBwEBBG0wazAkBggrBgEFBQcwAYYYaHR0
# cDovL29jc3AuZGlnaWNlcnQuY29tMEMGCCsGAQUFBzAChjdodHRwOi8vY2FjZXJ0
# cy5kaWdpY2VydC5jb20vRGlnaUNlcnRBc3N1cmVkSURSb290Q0EuY3J0MEUGA1Ud
# HwQ+MDwwOqA4oDaGNGh0dHA6Ly9jcmwzLmRpZ2ljZXJ0LmNvbS9EaWdpQ2VydEFz
# c3VyZWRJRFJvb3RDQS5jcmwwEQYDVR0gBAowCDAGBgRVHSAAMA0GCSqGSIb3DQEB
# DAUAA4IBAQBwoL9DXFXnOF+go3QbPbYW1/e/Vwe9mqyhhyzshV6pGrsi+IcaaVQi
# 7aSId229GhT0E0p6Ly23OO/0/4C5+KH38nLeJLxSA8hO0Cre+i1Wz/n096wwepqL
# sl7Uz9FDRJtDIeuWcqFItJnLnU+nBgMTdydE1Od/6Fmo8L8vC6bp8jQ87PcDx4eo
# 0kxAGTVGamlUsLihVo7spNU96LHc/RzY9HdaXFSMb++hUD38dglohJ9vytsgjTVg
# HAIDyyCwrFigDkBjxZgiwbJZ9VVrzyerbHbObyMt9H5xaiNrIv8SuFQtJ37YOtnw
# toeW/VvRXKwYw02fc7cBqZ9Xql4o4rmUMIIFrDCCBJSgAwIBAgIHG2O60B4sPTAN
# BgkqhkiG9w0BAQsFADCBlTELMAkGA1UEBhMCREUxRTBDBgNVBAoTPFZlcmVpbiB6
# dXIgRm9lcmRlcnVuZyBlaW5lcyBEZXV0c2NoZW4gRm9yc2NodW5nc25ldHplcyBl
# LiBWLjEQMA4GA1UECxMHREZOLVBLSTEtMCsGA1UEAxMkREZOLVZlcmVpbiBDZXJ0
# aWZpY2F0aW9uIEF1dGhvcml0eSAyMB4XDTE2MDUyNDExMzg0MFoXDTMxMDIyMjIz
# NTk1OVowgY0xCzAJBgNVBAYTAkRFMUUwQwYDVQQKDDxWZXJlaW4genVyIEZvZXJk
# ZXJ1bmcgZWluZXMgRGV1dHNjaGVuIEZvcnNjaHVuZ3NuZXR6ZXMgZS4gVi4xEDAO
# BgNVBAsMB0RGTi1QS0kxJTAjBgNVBAMMHERGTi1WZXJlaW4gR2xvYmFsIElzc3Vp
# bmcgQ0EwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQCdO3kcR94fhsvG
# adcQnjnX2aIw23IcBX8pX0to8a0Z1kzhaxuxC3+hq+B7i4vYLc5uiDoQ7lflHn8E
# UTbrunBtY6C+li5A4dGDTGY9HGRp5ZukrXKuaDlRh3nMF9OuL11jcUs5eutCp5eQ
# aQW/kP+kQHC9A+e/nhiIH5+ZiE0OR41IX2WZENLZKkntwbktHZ8SyxXTP38eVC86
# rpNXp354ytVK4hrl7UF9U1/Isyr1ijCs7RcFJD+2oAsH/U0amgNSoDac3iSHZeTn
# +seWcyQUzdDoG2ieGFmudn730Qp4PIdLsDfPU8o6OBDzy0dtjGQ9PFpFSrrKgHy4
# 8+enTEzNAgMBAAGjggIFMIICATASBgNVHRMBAf8ECDAGAQH/AgEBMA4GA1UdDwEB
# /wQEAwIBBjApBgNVHSAEIjAgMA0GCysGAQQBga0hgiweMA8GDSsGAQQBga0hgiwB
# AQQwHQYDVR0OBBYEFGs6mIv58lOJ2uCtsjIeCR/oqjt0MB8GA1UdIwQYMBaAFJPj
# 2DIm2tXxSqWRSuDqS+KiDM/hMIGPBgNVHR8EgYcwgYQwQKA+oDyGOmh0dHA6Ly9j
# ZHAxLnBjYS5kZm4uZGUvZ2xvYmFsLXJvb3QtZzItY2EvcHViL2NybC9jYWNybC5j
# cmwwQKA+oDyGOmh0dHA6Ly9jZHAyLnBjYS5kZm4uZGUvZ2xvYmFsLXJvb3QtZzIt
# Y2EvcHViL2NybC9jYWNybC5jcmwwgd0GCCsGAQUFBwEBBIHQMIHNMDMGCCsGAQUF
# BzABhidodHRwOi8vb2NzcC5wY2EuZGZuLmRlL09DU1AtU2VydmVyL09DU1AwSgYI
# KwYBBQUHMAKGPmh0dHA6Ly9jZHAxLnBjYS5kZm4uZGUvZ2xvYmFsLXJvb3QtZzIt
# Y2EvcHViL2NhY2VydC9jYWNlcnQuY3J0MEoGCCsGAQUFBzAChj5odHRwOi8vY2Rw
# Mi5wY2EuZGZuLmRlL2dsb2JhbC1yb290LWcyLWNhL3B1Yi9jYWNlcnQvY2FjZXJ0
# LmNydDANBgkqhkiG9w0BAQsFAAOCAQEAgXhFpE6kfw5V8Amxaj54zGg1qRzzlZ4/
# 8/jfazh3iSyNta0+x/KUzaAGrrrMqLGtMwi2JIZiNkx4blDw1W5gjU9SMUOXRnXw
# YuRuZlHBQjFnUOVJ5zkey5/KhkjeCBT/FUsrZpugOJ8Azv2n69F/Vy3ITF/cEBGX
# PpYEAlyEqCk5bJT8EJIGe57u2Ea0G7UDDDjZ3LCpP3EGC7IDBzPCjUhjJSU8entX
# bveKBTjvuKCuL/TbB9VbhBjBqbhLzmyQGoLkuT36d/HSHzMCv1PndvncJiVBby+m
# G/qkE5D6fH7ZC2Bd7L/KQaBh+xFJKdioLXUV2EoY6hbvVTQiGhONBjCCBq4wggSW
# oAMCAQICEAc2N7ckVHzYR6z9KGYqXlswDQYJKoZIhvcNAQELBQAwYjELMAkGA1UE
# BhMCVVMxFTATBgNVBAoTDERpZ2lDZXJ0IEluYzEZMBcGA1UECxMQd3d3LmRpZ2lj
# ZXJ0LmNvbTEhMB8GA1UEAxMYRGlnaUNlcnQgVHJ1c3RlZCBSb290IEc0MB4XDTIy
# MDMyMzAwMDAwMFoXDTM3MDMyMjIzNTk1OVowYzELMAkGA1UEBhMCVVMxFzAVBgNV
# BAoTDkRpZ2lDZXJ0LCBJbmMuMTswOQYDVQQDEzJEaWdpQ2VydCBUcnVzdGVkIEc0
# IFJTQTQwOTYgU0hBMjU2IFRpbWVTdGFtcGluZyBDQTCCAiIwDQYJKoZIhvcNAQEB
# BQADggIPADCCAgoCggIBAMaGNQZJs8E9cklRVcclA8TykTepl1Gh1tKD0Z5Mom2g
# sMyD+Vr2EaFEFUJfpIjzaPp985yJC3+dH54PMx9QEwsmc5Zt+FeoAn39Q7SE2hHx
# c7Gz7iuAhIoiGN/r2j3EF3+rGSs+QtxnjupRPfDWVtTnKC3r07G1decfBmWNlCnT
# 2exp39mQh0YAe9tEQYncfGpXevA3eZ9drMvohGS0UvJ2R/dhgxndX7RUCyFobjch
# u0CsX7LeSn3O9TkSZ+8OpWNs5KbFHc02DVzV5huowWR0QKfAcsW6Th+xtVhNef7X
# j3OTrCw54qVI1vCwMROpVymWJy71h6aPTnYVVSZwmCZ/oBpHIEPjQ2OAe3VuJyWQ
# mDo4EbP29p7mO1vsgd4iFNmCKseSv6De4z6ic/rnH1pslPJSlRErWHRAKKtzQ87f
# SqEcazjFKfPKqpZzQmiftkaznTqj1QPgv/CiPMpC3BhIfxQ0z9JMq++bPf4OuGQq
# +nUoJEHtQr8FnGZJUlD0UfM2SU2LINIsVzV5K6jzRWC8I41Y99xh3pP+OcD5sjCl
# TNfpmEpYPtMDiP6zj9NeS3YSUZPJjAw7W4oiqMEmCPkUEBIDfV8ju2TjY+Cm4T72
# wnSyPx4JduyrXUZ14mCjWAkBKAAOhFTuzuldyF4wEr1GnrXTdrnSDmuZDNIztM2x
# AgMBAAGjggFdMIIBWTASBgNVHRMBAf8ECDAGAQH/AgEAMB0GA1UdDgQWBBS6Ftlt
# TYUvcyl2mi91jGogj57IbzAfBgNVHSMEGDAWgBTs1+OC0nFdZEzfLmc/57qYrhwP
# TzAOBgNVHQ8BAf8EBAMCAYYwEwYDVR0lBAwwCgYIKwYBBQUHAwgwdwYIKwYBBQUH
# AQEEazBpMCQGCCsGAQUFBzABhhhodHRwOi8vb2NzcC5kaWdpY2VydC5jb20wQQYI
# KwYBBQUHMAKGNWh0dHA6Ly9jYWNlcnRzLmRpZ2ljZXJ0LmNvbS9EaWdpQ2VydFRy
# dXN0ZWRSb290RzQuY3J0MEMGA1UdHwQ8MDowOKA2oDSGMmh0dHA6Ly9jcmwzLmRp
# Z2ljZXJ0LmNvbS9EaWdpQ2VydFRydXN0ZWRSb290RzQuY3JsMCAGA1UdIAQZMBcw
# CAYGZ4EMAQQCMAsGCWCGSAGG/WwHATANBgkqhkiG9w0BAQsFAAOCAgEAfVmOwJO2
# b5ipRCIBfmbW2CFC4bAYLhBNE88wU86/GPvHUF3iSyn7cIoNqilp/GnBzx0H6T5g
# yNgL5Vxb122H+oQgJTQxZ822EpZvxFBMYh0MCIKoFr2pVs8Vc40BIiXOlWk/R3f7
# cnQU1/+rT4osequFzUNf7WC2qk+RZp4snuCKrOX9jLxkJodskr2dfNBwCnzvqLx1
# T7pa96kQsl3p/yhUifDVinF2ZdrM8HKjI/rAJ4JErpknG6skHibBt94q6/aesXmZ
# gaNWhqsKRcnfxI2g55j7+6adcq/Ex8HBanHZxhOACcS2n82HhyS7T6NJuXdmkfFy
# nOlLAlKnN36TU6w7HQhJD5TNOXrd/yVjmScsPT9rp/Fmw0HNT7ZAmyEhQNC3EyTN
# 3B14OuSereU0cZLXJmvkOHOrpgFPvT87eK1MrfvElXvtCl8zOYdBeHo46Zzh3SP9
# HSjTx/no8Zhf+yvYfvJGnXUsHicsJttvFXseGYs2uJPU5vIXmVnKcPA3v5gA3yAW
# Tyf7YGcWoWa63VXAOimGsJigK+2VQbc61RWYMbRiCQ8KvYHZE/6/pNHzV9m8BPqC
# 3jLfBInwAM1dwvnQI38AC+R2AibZ8GV2QqYphwlHK+Z/GqSFD/yYlvZVVCsfgPrA
# 8g4r5db7qS9EFUrnEw4d2zc4GqEr9u3WfPwwggbAMIIEqKADAgECAhAMTWlyS5T6
# PCpKPSkHgD1aMA0GCSqGSIb3DQEBCwUAMGMxCzAJBgNVBAYTAlVTMRcwFQYDVQQK
# Ew5EaWdpQ2VydCwgSW5jLjE7MDkGA1UEAxMyRGlnaUNlcnQgVHJ1c3RlZCBHNCBS
# U0E0MDk2IFNIQTI1NiBUaW1lU3RhbXBpbmcgQ0EwHhcNMjIwOTIxMDAwMDAwWhcN
# MzMxMTIxMjM1OTU5WjBGMQswCQYDVQQGEwJVUzERMA8GA1UEChMIRGlnaUNlcnQx
# JDAiBgNVBAMTG0RpZ2lDZXJ0IFRpbWVzdGFtcCAyMDIyIC0gMjCCAiIwDQYJKoZI
# hvcNAQEBBQADggIPADCCAgoCggIBAM/spSY6xqnya7uNwQ2a26HoFIV0MxomrNAc
# VR4eNm28klUMYfSdCXc9FZYIL2tkpP0GgxbXkZI4HDEClvtysZc6Va8z7GGK6aYo
# 25BjXL2JU+A6LYyHQq4mpOS7eHi5ehbhVsbAumRTuyoW51BIu4hpDIjG8b7gL307
# scpTjUCDHufLckkoHkyAHoVW54Xt8mG8qjoHffarbuVm3eJc9S/tjdRNlYRo44DL
# annR0hCRRinrPibytIzNTLlmyLuqUDgN5YyUXRlav/V7QG5vFqianJVHhoV5Pgxe
# ZowaCiS+nKrSnLb3T254xCg/oxwPUAY3ugjZNaa1Htp4WB056PhMkRCWfk3h3cKt
# pX74LRsf7CtGGKMZ9jn39cFPcS6JAxGiS7uYv/pP5Hs27wZE5FX/NurlfDHn88JS
# xOYWe1p+pSVz28BqmSEtY+VZ9U0vkB8nt9KrFOU4ZodRCGv7U0M50GT6Vs/g9Arm
# FG1keLuY/ZTDcyHzL8IuINeBrNPxB9ThvdldS24xlCmL5kGkZZTAWOXlLimQprdh
# ZPrZIGwYUWC6poEPCSVT8b876asHDmoHOWIZydaFfxPZjXnPYsXs4Xu5zGcTB5rB
# eO3GiMiwbjJ5xwtZg43G7vUsfHuOy2SJ8bHEuOdTXl9V0n0ZKVkDTvpd6kVzHIR+
# 187i1Dp3AgMBAAGjggGLMIIBhzAOBgNVHQ8BAf8EBAMCB4AwDAYDVR0TAQH/BAIw
# ADAWBgNVHSUBAf8EDDAKBggrBgEFBQcDCDAgBgNVHSAEGTAXMAgGBmeBDAEEAjAL
# BglghkgBhv1sBwEwHwYDVR0jBBgwFoAUuhbZbU2FL3MpdpovdYxqII+eyG8wHQYD
# VR0OBBYEFGKK3tBh/I8xFO2XC809KpQU31KcMFoGA1UdHwRTMFEwT6BNoEuGSWh0
# dHA6Ly9jcmwzLmRpZ2ljZXJ0LmNvbS9EaWdpQ2VydFRydXN0ZWRHNFJTQTQwOTZT
# SEEyNTZUaW1lU3RhbXBpbmdDQS5jcmwwgZAGCCsGAQUFBwEBBIGDMIGAMCQGCCsG
# AQUFBzABhhhodHRwOi8vb2NzcC5kaWdpY2VydC5jb20wWAYIKwYBBQUHMAKGTGh0
# dHA6Ly9jYWNlcnRzLmRpZ2ljZXJ0LmNvbS9EaWdpQ2VydFRydXN0ZWRHNFJTQTQw
# OTZTSEEyNTZUaW1lU3RhbXBpbmdDQS5jcnQwDQYJKoZIhvcNAQELBQADggIBAFWq
# KhrzRvN4Vzcw/HXjT9aFI/H8+ZU5myXm93KKmMN31GT8Ffs2wklRLHiIY1UJRjkA
# /GnUypsp+6M/wMkAmxMdsJiJ3HjyzXyFzVOdr2LiYWajFCpFh0qYQitQ/Bu1nggw
# CfrkLdcJiXn5CeaIzn0buGqim8FTYAnoo7id160fHLjsmEHw9g6A++T/350Qp+sA
# ul9Kjxo6UrTqvwlJFTU2WZoPVNKyG39+XgmtdlSKdG3K0gVnK3br/5iyJpU4GYhE
# FOUKWaJr5yI+RCHSPxzAm+18SLLYkgyRTzxmlK9dAlPrnuKe5NMfhgFknADC6Vp0
# dQ094XmIvxwBl8kZI4DXNlpflhaxYwzGRkA7zl011Fk+Q5oYrsPJy8P7mxNfarXH
# 4PMFw1nfJ2Ir3kHJU7n/NBBn9iYymHv+XEKUgZSCnawKi8ZLFUrTmJBFYDOA4CPe
# +AOk9kVH5c64A0JH6EE2cXet/aLol3ROLtoeHYxayB6a1cLwxiKoT5u92ByaUcQv
# mvZfpyeXupYuhVfAYOd4Vn9q78KVmksRAsiCnMkaBXy6cbVOepls9Oie1FqYyJ+/
# jbsYXEP10Cro4mLueATbvdH7WwqocH7wl4R44wgDXUcsY6glOJcB0j862uXl9uab
# 3H4szP8XTE0AotjWAQ64i+7m4HJViSwnGWH2dwGMMIIHZzCCBk+gAwIBAgIMJgTt
# aoYGmKtMjK/2MA0GCSqGSIb3DQEBCwUAMIGNMQswCQYDVQQGEwJERTFFMEMGA1UE
# Cgw8VmVyZWluIHp1ciBGb2VyZGVydW5nIGVpbmVzIERldXRzY2hlbiBGb3JzY2h1
# bmdzbmV0emVzIGUuIFYuMRAwDgYDVQQLDAdERk4tUEtJMSUwIwYDVQQDDBxERk4t
# VmVyZWluIEdsb2JhbCBJc3N1aW5nIENBMB4XDTIyMDExNzEzMzIxM1oXDTI1MDEx
# NjEzMzIxM1owgdExCzAJBgNVBAYTAkRFMQ8wDQYDVQQIDAZCYXllcm4xETAPBgNV
# BAcMCEVybGFuZ2VuMTwwOgYDVQQKDDNGcmllZHJpY2gtQWxleGFuZGVyLVVuaXZl
# cnNpdGFldCBFcmxhbmdlbi1OdWVybmJlcmcxDTALBgNVBAsMBEZBUFMxJTAjBgNV
# BEEMHE1pY2hhZWwgTWFzdWNoIC0gQ29kZVNpZ25pbmcxKjAoBgNVBAMMIVBOIC0g
# TWljaGFlbCBNYXN1Y2ggLSBDb2RlU2lnbmluZzCCAiIwDQYJKoZIhvcNAQEBBQAD
# ggIPADCCAgoCggIBANXtZP6ekfKLExpY3jYp9p5W7QTpYmvsq4lbqO9mnvvXvQw6
# vwDlvaNd0D9yPiF6sCYdL3rIXStc7v/lRB+xgsfYJo/fvTOX7GLSBQQzPZ/XWtvF
# w5XTb6C5qQ+iBEukVXzP8gSphNiV2hvyuGE5F2PCOJOPPAbFeT/ZST3QglacmYfi
# jYvWasbUzW+sqyeMgIeP47nTrC8HItU/VH9W2F3Brg5EU9h6DdUzCjhb8KhgApoG
# jTCHcAtVhvwv6XW6uBNSvOGqECK+7L8I5okyaEnNpNOaykQUO6iBtH1yzXLnPNx7
# pDYsV8GbZxB7LFlVyJJcm5vfklju3UDRNgkaUg39yttxNHjQVdQRrhR7Q/uXHPL9
# bqL9Gfp9x4yheTVTyhyOhY9ncKDorunDqykVgIIBT/uBH4kNfLTALO5ujctsuMbz
# 10TATFDRSRZyvmi2NGZtWGiRoT732JYnlTrg3O7UWZ4vVH3MSWU7wUIECfDTQBhM
# h9ikhUhFCkFlOjSDppywvXat/zoQtS2F1t8WjWSFN0CrE2xr8VYizFiaJBkfk7pA
# R4XUcVS0QLa47l6eezITL/fprmD2ogfyGeULzVYA9qsBblXkKpP3dtfBeCx0ggTZ
# OEDdjbEOTdYoneQEr+X61EmNFa7P6UbNLz5pNJ8m7V/S4o4346Kp7ZJP7bohAgMB
# AAGjggJ/MIICezA+BgNVHSAENzA1MA8GDSsGAQQBga0hgiwBAQQwEAYOKwYBBAGB
# rSGCLAEBBAowEAYOKwYBBAGBrSGCLAIBBAowCQYDVR0TBAIwADAOBgNVHQ8BAf8E
# BAMCB4AwEwYDVR0lBAwwCgYIKwYBBQUHAwMwHQYDVR0OBBYEFKTu4u2mMJzXq0QF
# LH7OEemfKkwgMB8GA1UdIwQYMBaAFGs6mIv58lOJ2uCtsjIeCR/oqjt0MFsGA1Ud
# EQRUMFKBGm1pY2hhZWwubWFzdWNoQGZhcHMuZmF1LmRlgRVtaWNoYWVsLm1hc3Vj
# aEBmYXUuZGWBHW1pbWFzdWNoQGZhcHMudW5pLWVybGFuZ2VuLmRlMIGNBgNVHR8E
# gYUwgYIwP6A9oDuGOWh0dHA6Ly9jZHAxLnBjYS5kZm4uZGUvZGZuLWNhLWdsb2Jh
# bC1nMi9wdWIvY3JsL2NhY3JsLmNybDA/oD2gO4Y5aHR0cDovL2NkcDIucGNhLmRm
# bi5kZS9kZm4tY2EtZ2xvYmFsLWcyL3B1Yi9jcmwvY2FjcmwuY3JsMIHbBggrBgEF
# BQcBAQSBzjCByzAzBggrBgEFBQcwAYYnaHR0cDovL29jc3AucGNhLmRmbi5kZS9P
# Q1NQLVNlcnZlci9PQ1NQMEkGCCsGAQUFBzAChj1odHRwOi8vY2RwMS5wY2EuZGZu
# LmRlL2Rmbi1jYS1nbG9iYWwtZzIvcHViL2NhY2VydC9jYWNlcnQuY3J0MEkGCCsG
# AQUFBzAChj1odHRwOi8vY2RwMi5wY2EuZGZuLmRlL2Rmbi1jYS1nbG9iYWwtZzIv
# cHViL2NhY2VydC9jYWNlcnQuY3J0MA0GCSqGSIb3DQEBCwUAA4IBAQBssTheCDKu
# B0VdQDl4L3jaKuP5JJKz2TdAxKoQtRA7t5kwaaMKW98Sl78IZuo7WkUKj1CkCmJN
# TH1QqM6Qlq/eP5eWjejh+KH/q2fkVYyMm76AfOPcz42DSaMTxVIcfOChOnLhdJts
# rMjtsL55ayFtuVfj/iOrKLcC0rswoStXV7C6+cU9uBWjQDOYOJJ8tuB8uIdLbgX4
# Gj10cgmqOaJNQVdz+V4QKmg7utiYwK8lmmpbCy17oo2SrNsRiUwCAzPM+LrZxqzX
# ufpGAHKzHxY18FogR3HcqCmW4tVV2Zow8eylF6chV5w060EyAqfwbpzudw9mI/qp
# iHkTnlPBGncdMYIGdTCCBnECAQEwgZ4wgY0xCzAJBgNVBAYTAkRFMUUwQwYDVQQK
# DDxWZXJlaW4genVyIEZvZXJkZXJ1bmcgZWluZXMgRGV1dHNjaGVuIEZvcnNjaHVu
# Z3NuZXR6ZXMgZS4gVi4xEDAOBgNVBAsMB0RGTi1QS0kxJTAjBgNVBAMMHERGTi1W
# ZXJlaW4gR2xvYmFsIElzc3VpbmcgQ0ECDCYE7WqGBpirTIyv9jANBglghkgBZQME
# AgEFAKCBhDAYBgorBgEEAYI3AgEMMQowCKACgAChAoAAMBkGCSqGSIb3DQEJAzEM
# BgorBgEEAYI3AgEEMBwGCisGAQQBgjcCAQsxDjAMBgorBgEEAYI3AgEVMC8GCSqG
# SIb3DQEJBDEiBCBiHMMP6tNKhASt2c/+CCyymqTIpsVTGJHUFVKqYlbZ5TANBgkq
# hkiG9w0BAQEFAASCAgApaAgHXCE1ivTz5XTvogUQzOn5oGzb5MpPFXOczHegPyBF
# Q/m+C2J5G8k2Pg9JjYauuvRe3mOmoADf+Nwqr05U3iSW4zRVAhuRxdpBNxnLjl7O
# j4ehkJwIKTzFUBSpC6PZ+Ca1woZKUEGEH4othVKtc1CuXYtr2Fkm+u36gtbAEQ+W
# CJvjjZSpiUUM01JvFbKBg5sYvBA07FDgvSKHbWHhA9pEwJgThcEY5kxM/8XUIKx9
# G2pY7DSx6cfDunk29kLUpkIjs6rv4bMAg6RA94njPSg2IRx37ud1OygdKSiy7Lnh
# AO5+i22nJRslVoyZL/PSIQBCOb8vcqjROaKsd+lNeB9jCMIUkFozacqG5XMmW4PO
# 94UehOuJ3/2sBRH0R4ZAP4vrwZM21thIXRjd0wPLlYOs143ykEXU2PU/Twyf0r7c
# ksKBZkahGFTpQs2ZuhPzM2YSLWhB7g3LfrEdWKcF+zhHTowIOk794759NI2vfu4q
# 9OFYJqN7oBdIri0Mix6w85PiZR1QdgOwpqjr+EMuTps+P0CfL/4rqjhXauXb9UWT
# MZ7D7ZNNAMA84v2ZH1E7/j5Qj9lYVjbFNGuRIx6ZgSaEhR4sO4BTLhDLCloa0ukZ
# JFLskC0mKnMw9XFn6n0/KSLUue6j0PrNg/2bJ7HC+hStAkH5IMaLZtxOLclPB6GC
# AyAwggMcBgkqhkiG9w0BCQYxggMNMIIDCQIBATB3MGMxCzAJBgNVBAYTAlVTMRcw
# FQYDVQQKEw5EaWdpQ2VydCwgSW5jLjE7MDkGA1UEAxMyRGlnaUNlcnQgVHJ1c3Rl
# ZCBHNCBSU0E0MDk2IFNIQTI1NiBUaW1lU3RhbXBpbmcgQ0ECEAxNaXJLlPo8Kko9
# KQeAPVowDQYJYIZIAWUDBAIBBQCgaTAYBgkqhkiG9w0BCQMxCwYJKoZIhvcNAQcB
# MBwGCSqGSIb3DQEJBTEPFw0yMzA3MjUyMDEwMzlaMC8GCSqGSIb3DQEJBDEiBCAK
# V5JJ3c042Hi5ypZBVjO0qH8jyxyIovwkrPUFVwa8vjANBgkqhkiG9w0BAQEFAASC
# AgAhVRbu1pHs5BSERjyd9K3PbjRaWLBkm8OgXCY9vkuNG0zKPfbgbTRwsFmAx3by
# +8er2KMVTSPc+sNlcF0GLK5OUDRqJ4MH5I6DuMXAPrJzcqPYaW045wiQQw/D5+Hl
# T6obnKPUiFdpgc4PJC2K9yoj3ZeNu5xXiu02wi3BN/hP+GdfYudEbOJv4nbpoLEJ
# Fp/UVCHvPAgxp63voInMm/4D1A+gK1byC+cdVRaBorupBkG9YhHlHtsmEV9bHyZE
# iQB/ApPf3+oYI1rOf3p/fCIm251QvrcWhDFeebxjMqwuBDVBGqdxXYoqscA5lNYZ
# q0XFt5onImbCf8ZPnV44IFlpEgnCPyz+ltWba+6zlRl6Sa/PH5xOUK/BGH9xronV
# gV1Pe7niDuWhAwtSSZFwmVcywjLAqJ7KedpYXoRjfv9j6Oqjb3GHGH3dnepjIKxS
# vZyN5LbcX3s50lB88hMxZ8zJf789uxyPmH5sxkVx5COhRzUyWUZaC+c0zaxgtZki
# jANlwWJs1stbaSV9a7xuv7W3PoV0w7sh6U+++pcn9hNS91fdIDEMJCSC5SQQXKLm
# cM4RHUtVAIdvVJKapkPVY5RqCvdv5ZuVltUqgErLwpXvF/BlmydNMlizYo2vmaT5
# /q0XbXjnFxKiwHHKkQzh+a2Rx5H1z6aPbNo1ln7MBPrb+g==
# SIG # End signature block
