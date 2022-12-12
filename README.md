# Oculus_PortScanner
Network a Port Scanner pre Powershell 5.1 

## Inštalácia 

Spustíme PowerShell ako administrátor.

Nastavenie pravidiel inštalácie externých modulov ()
```
Set-ExecutionPolicy -ExecutionPolicy RemoteSigned
```

Následne sme schopný importovať modul do PowerShell-u.

1. Zistíme cestu, z ktorej PowerShell načítava moduly.
```
$Env:PSModulePath
```
2. Pridáme cestu k stiahnutej zložke obsahujúcej modul.
```
$Env:PSModulePath + "<path>"
```
3. Načítame modul na použitie do PowerShell-u.
```
Import-Module -Name <path> -Verbose
```

## Použitie
### Get-TargetEnumeration
```
Get-TargetEnumeration -Target <String>
```
#### Parametre
```
-Target 
```
Špecifikuje IP adresu.
```
Type: String
Position: 0
--------
Example: 192.168.150.2
Example: 192.168.150.2-5
Example: 192.168.150.'2,8,11,21'
Example: 192.168.150.0/26
```

### Get-HostDiscovery
```
Get-TargetEnumeration -Target <String>
```
#### Parametre
```
-Target 
```
Špecifikuje IP adresu.
```
Type: String
Position: 0
--------
Example: 192.168.150.2
Example: 192.168.150.2-5
Example: 192.168.150.'2,8,11,21'
Example: 192.168.150.0/26
```

```
-OutTxt
```
Vytvorí súbor formátu .txt, do ktorého sa uloží získaný output funkcie, na zadanej ceste. 
```
Type: String
Position: 2
--------
Example: "C:\Users\Documents"
```

```
-OutCsv
```
Vytvorí súbor formátu .csv, do ktorého sa uloží získaný output funkcie, na zadanej ceste.
```
Type: String
Position: 2
--------
Example: "C:\Users\Documents"
```

```
-OutXml
```
Vytvorí súbor formátu .xml, do ktorého sa uloží získaný output funkcie, na zadanej ceste. 
```
Type: String
Position: 2
--------
Example: "C:\Users\Documents"
```

### Get-TCPConnectScan
```
Get-TargetEnumeration -Target <String> -Port <String>
Get-TargetEnumeration -Target <String> -TopXPorts <Int32>
```
#### Parametre
```
-Target
```
Špecifikuje IP adresu.
```
Type: String
Position: 0
--------
Example: 192.168.150.2
Example: 192.168.150.11, 192.168.120.15
Example: 192.168.150.2-5
Example: 192.168.150.'2,8,11,21'
Example: 192.168.150.0/26
```

```
-Port
```
Špecifikuje číslo portu.
```
Type: String
Position: 1
--------
Example: 21
Example: 21, 80, 5060
```

```
-TopXPorts
```
Špecifikuje koľko najčastejšie dostupných portov má skenovať v rozsahu 1-1000.
```
Type: Int32
Position: 1
--------
Example: 100
Example: 1000
```

```
-OutTxt
```
Vytvorí súbor formátu .txt, do ktorého sa uloží získaný output funkcie, na zadanej ceste. 
```
Type: String
Position: 2
--------
Example: "C:\Users\Documents"
```

```
-OutCsv
```
Vytvorí súbor formátu .csv, do ktorého sa uloží získaný output funkcie, na zadanej ceste.
```
Type: String
Position: 2
--------
Example: "C:\Users\Documents"
```

```
-OutXml
```
Vytvorí súbor formátu .xml, do ktorého sa uloží získaný output funkcie, na zadanej ceste. 
```
Type: String
Position: 2
--------
Example: "C:\Users\Documents"
```
