# Oculus Network Scanner

Oculus Network Scanner is PowerShell module designed for network discovery, port scanning, and OS detection. It includes five core functions that will enable you to easily gather information about your network's infrastructure and open ports on target systems.

## Table of Contents

1. [Prerequisites](#prerequisites)
2. [Installation](#installation)
4. [Functions](#functions)
    * [Get-TargetEnumeration](#get-targetenumeration)
    * [Get-ServiceByPort](#get-servicebyport)
    * [Get-TopXPorts](#get-topxports)
    * [Get-HostDiscovery](#get-hostdiscovery)
    * [Get-ConnectScan](#get-connectscan)
6. [Contributing](#contributing)
7. [License](#license)

## Prerequisites

-PowerShell 5.1 or later
-Internet connection to download dependencies
-Administrator privileges


## Installation

To install the Oculus Network Scanner module, simply download the repository and import the module into your PowerShell session:

```powershell
Import-Module .\OculusNetworkScanner.psm1
```
OR

Run PowerShell as administrator.
Set installation rules for external modules ()
```
Set-ExecutionPolicy -ExecutionPolicy Bypass -Scope Process
```
Next, we are able to import the module into PowerShell.

1. Determine the path from which PowerShell loads modules.
```
$Env:PSModulePath
```
2. Add the path to the downloaded folder containing the module (module folder).
```
$Env:PSModulePath += ";<path>"
```
3. Load the module for use in PowerShell.
```
Import-Module -Name Oculus -Verbose
```

### Functions

#### Get-TargetEnumeration
This function helps you enumerate targets within a specified range of IP addresses. It creates a simplified list of IP addresses from various input formats such as IP address range, IP address enumeration, IP address with CIDR notation, IPv6 addresses and DNS names.

Parameters:

-**Target <IPAddress>**: The remote computer(s) to be scanned. This can be a CIDR notation, range or enumeration of IP addresses, input from a file or a DNS name.

Usage:
  
```powershell
Get-TargetEnumeration -Target <IPAddress> 
```
  
Example:
  
Get all the ip addresses from CIDR notation: 
```powershell
Get-TargetEnumeration -Target "1.1.1.0/26" 
```

#### Get-ServiceByPort
This function takes a port number as input and returns the name of the service that typically uses that port. If the port number is not associated with a known service, the function returns "Unknown".

Parameters:

-**Port <int>**: Specifies the port number to look up. This parameter is mandatory.

Usage:
  
```powershell
Get-ServiceByPort [-Port] <int>
```

Example:
  
```powershell
Get-ServiceByPort -Port 80
``` 
#### Get-TopXPorts
This function returns the top X most commonly used ports on a target.
  
Parameters:

-**X <int>**: Specifies the number of most common open ports to return from top 1000 most common open ports. This parameter is mandatory.
  
Usage:
  
```powershell
Get-TopXPorts -X <NumberOfTopXPorts>
```
Example:
  
```powershell
Get-TopXPorts -X 10
``` 
#### Get-HostDiscovery
*Get-HostDiscovery* is used to find which hosts on the network are up. The function returns a list of the specified host(s) by attempting a TCP three-way handshake.

Parameters:
-**Target <IPAddress>**: The remote computer(s) to be scanned. Possible CIDR notation, range, or enumeration of IP addresses.
  
-**OutputAll <Path>**: Specifies that the result will be written to .txt, .csv, and .xml files and path to where the file will be created.
  
-**OutTxt <Path>**: Specifies that the result will be written to .txt file and path to where the file will be created.
  
-**OutCsv <Path>**: Specifies that the result will be written to .csv file and path to where the file will be created.
  
-**OutXml <Path>**: Specifies that the result will be written to .xml file and path to where the file will be created.
  
-**TraceRoute**: Specifies that the function should also provide traceroute info.
  
-**Threads <int>: Specifies how many threads to scan hosts and ports in parallel should be used to speed up scanning.
  
-**OSdet**: Specifies that function should also provide information about operating system.
  
Usage:
```powershell
Get-HostDiscovery -Target <IPAddress> -Threads <int> -Traceroute -OSDet -OutTxt <Path>
```
  
Example:
```powershell
Get-HostDiscovery -Target 168.192.111.120 -Threads 5 -Traceroute -OSDet -OutTxt "C:\Desktop"
```  

#### Get-ConnectScan
The *Get-ConnectScan* function performs a TCP connection scan on a given set of target IP addresses. The function takes several parameters, including the target IP address, a range of ports to scan, the number of threads to use, whether to perform OS detection and trace routing, and several output options.

Parameters:
  
-**Target <IPAddress>**: The target IP address or addresses to scan. This is a mandatory parameter and must be provided either as a string or an array of strings.
  
-**Port <int>**: The range of ports to scan. This is an optional parameter and defaults to scanning all ports. The parameter can take a single port number or an array of port numbers.
  
-**TopXPorts <int>**: The number of top ports to scan. This is an optional parameter and overrides the Port parameter if both are provided.
  
-**Threads <int>**: The number of threads to use for scanning. This is an optional parameter and defaults to 5.
  
-**OSDet**: A switch parameter to enable OS detection. This is an optional parameter and defaults to false.
  
-**TraceRoute**: A switch parameter to enable trace routing. This is an optional parameter and defaults to false.
  
-**OutputAll <Path>**: The path and name of the file to write all output to. This is an optional parameter and can be a full path or just a file name. If the file already exists, the output will be appended to the end of the file.
  
-**OutTxt <Path>**: The path and name of the file to write the output in text format. This is an optional parameter and can be a full path or just a file name. If the file already exists, the output will be appended to the end of the file.
  
-**OutCsv <Path>**: The path and name of the file to write the output in CSV format. This is an optional parameter and can be a full path or just a file name. If the file already exists, the output will be appended to the end of the file.
  
-**OutXml <Path>**: The path and name of the file to write the output in XML format. This is an optional parameter and can be a full path or just a file name. If the file already exists, the output will be appended to the end of the file.
  
-**Timeout <int>**: The timeout for each connection attempt in milliseconds. This is an optional parameter and defaults to 1000.
  
-**NoPing**: A switch parameter to disable ping before scanning. This is an optional parameter and defaults to false.
  
Usage:
  
```powershell
Get-ConnectScan -Target <IPAddress> -Port <int> -OSDet -TraceRoute -OutAll <Path> -Threads <int> -Timeout <int> -NoPing
```
  
Example:
  
```powershell
Get-ConnectScan -Target "10.10.10.8,9,10" -Port 80, 21 -OSDet -TraceRoute -OutAll "C:\Desktop" -Threads 10 -Timeout 2000 -NoPing
```

### Contributing
If you would like to contribute to the development of the Oculus Network Scanner, please feel free to submit a pull request or open an issue for discussion.

### License
Oculus Network Scanner is released under the [MIT License](LICENSE).

For more information on each function and its parameters, please refer to the inline help documentation using the **Get-Help** cmdlet:

```powershell
Get-Help <functionName> -Full
```
