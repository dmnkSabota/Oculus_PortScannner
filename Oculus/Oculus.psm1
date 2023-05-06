function Get-TargetEnumeration {
    <#
    .SYNOPSIS
        Returns list of IP addresses to be scanned.
    .DESCRIPTION
        Get-TargetEnumeration is function that creates simplified list of IP adresses from various input formats such as IP address range, IP address enumeration, IP address with CIDR notation, IPv6 addresses and DNS names. 
    .PARAMETER Target
        The remote computer(s) to be scanned. 
        Possible CIDR notation, range or enumeration of IP addresses or input from file.
    
    .EXAMPLE
        Get-TargetEnumeration -Target "1.1.1.0/26"

    .EXAMPLE
        Get-TargetEnumeration -Target "1.1.1.1,2,5,9" 
         
    .EXAMPLE
        Get-TargetEnumeration-Target "1.1.1.1-125"  

    .EXAMPLE
        Get-TargetEnumeration -Target "1.1.1.35, 1.1.1.5"   
    
    .EXAMPLE
        Get-TargetEnumeration -Target "2001:0db8:85a3:0000:0000:8a2e:0370:7334"
    
    .EXAMPLE
        Get-TargetEnumeration -Target "example.com"

    .EXAMPLE
        Get-Content -Path <path> | Get-TargetEnumeration
  
    .INPUTS
        System.String
    
    .OUTPUTS
        PSCustomObject
    
    .NOTES
        Author: Dominik Sabota
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true,ValueFromPipeline=$true)]
        [string[]]$Target
    )

    begin {
        $iplist = @()
        $wrongIn = @()
    }

    process {
        foreach ($ip in $Target) {
            try {
                if ($ip -match '^(\d{1,3}\.){3}\d{1,3}$'){
                    $iplist += $ip
                }
                elseif ($ip -match '^(\d{1,3}\.){3}\d{1,3}(-\d{1,3})?$') {
                    $start,$end = $ip.Split('-')
                    $lastDotIndex = $start.LastIndexOf('.')
                    $prefix = $start.Substring(0, $lastDotIndex + 1) 
                    [int]$suffix = $start.Substring($lastDotIndex + 1)

                    for ($suffix  ; $suffix -le $end; $suffix++) {
                        $iplist += $prefix + [string]$suffix 
                    }
                }
                elseif ($ip -match '^(\d{1,3}\.){3}(\d{1,3},)+\d{1,3}$') {
                    $lastDotIndex = $ip.LastIndexOf('.')
                    $prefix,$end = $ip.Substring(0, $lastDotIndex + 1),$ip.Substring($lastDotIndex + 1)
                    $suffixes = $end.Split(",")
                    foreach ($s in $suffixes) {
                        $iplist += $prefix + $s
                    }
                }
                elseif ($ip -match '^(\d{1,3}\.){3}\d{1,3}(/\d{1,2})?$') {
                    $ipadd,$cidr = $ip.Split('/')
                    $lastDotIndex = $ipadd.LastIndexOf('.')
                    $prefix,$suffix = $ipadd.Substring(0, $lastDotIndex + 1),$ipadd.Substring($lastDotIndex + 1)
                    $hostNum = [math]::Pow(2, (32 - $cidr)) - 1
                    for($i = 1; $i -lt $hostNum; $i++){
                        $iplist += $prefix + $i
                    }
                }
                elseif ($ip -match '^([0-9A-Fa-f]{0,4}:){1,7}[0-9A-Fa-f]{0,4}(/(\d{1,2}))?$') {
                    $iplist += $ip
                }
                else{
                    $resolvedIp = [Net.Dns]::GetHostAddresses($ip) | Select-Object -ExpandProperty IPAddressToString
                    $iplist +=  $resolvedIp
                }
            } catch {
                $wrongIn += $ip
            }
        }
    }

    end {
        return @{
            IPs = $iplist
            ErrorValues = $wrongIn
        } 
    }
}

function Get-TopXPorts {
    <#
    .SYNOPSIS
        Returns top 1-1000 most frequently scanned ports.
    .DESCRIPTION
        Get-TopXPorts is helper function that returns list of first x most frequently scanned ports. 
    .PARAMETER X
        Number of first x most frequently scanned ports to return in range 1-1000. 
    
    .EXAMPLE
        Get-TopXPorts -X 13
  
    .INPUTS
        System.Int32
    
    .OUTPUTS
        System.Int32
    
    .NOTES
        Author: Dominik Sabota
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true, Position = 0)]
        [ValidateRange(1,1000)]
        [int]$X
    )

    begin {
        $Top1000Ports= @(1,3,4,6,7,9,13,17,19,20,21,22,23,24,25,26,30,32,33,37,42,43,49,53,70,79,80,81,82,83,84,85,88,89,90,99,100,106,109,110,111,113,119,125,135,139,143,144,146,161,163,179,199,211,212,222,254,255,256,259,264,280,301,306,311,340,366,389,406,407,416,417,425,427,443,444,445,458,464,465,481,497,500,512,513,514,515,524,541,543,544,545,548,554,555,563,587,593,616,617,625,631,636,646,648,666,667,668,683,687,691,700,705,711,714,720,722,726,749,765,777,783,787,800,801,808,843,873,880,888,898,900,901,902,903,911,912,981,987,990,992,993,995,999,1000,1001,1002,1007,1009,1010,1011,1021,1022,1023,1024,1025,1026,1027,1028,1029,1030,1031,1032,1033,1034,1035,1036,1037,1038,1039,1040,1041,1042,1043,1044,1045,1046,1047,1048,1049,1050,1051,1052,1053,1054,1055,1056,1057,1058,1059,1060,1061,1062,1063,1064,1065,1066,1067,1068,1069,1070,1071,1072,1073,1074,1075,1076,1077,1078,1079,1080,1081,1082,1083,1084,1085,1086,1087,1088,1089,1090,1091,1092,1093,1094,1095,1096,1097,1098,1099,1100,1102,1104,1105,1106,1107,1108,1110,1111,1112,1113,1114,1117,1119,1121,1122,1123,1124,1126,1130,1131,1132,1137,1138,1141,1145,1147,1148,1149,1151,1152,1154,1163,1164,1165,1166,1169,1174,1175,1183,1185,1186,1187,1192,1198,1199,1201,1213,1216,1217,1218,1233,1234,1236,1244,1247,1248,1259,1271,1272,1277,1287,1296,1300,1301,1309,1310,1311,1322,1328,1334,1352,1417,1433,1434,1443,1455,1461,1494,1500,1501,1503,1521,1524,1533,1556,1580,1583,1594,1600,1641,1658,1666,1687,1688,1700,1717,1718,1719,1720,1721,1723,1755,1761,1782,1783,1801,1805,1812,1839,1840,1862,1863,1864,1875,1900,1914,1935,1947,1971,1972,1974,1984,1998,1999,2000,2001,2002,2003,2004,2005,2006,2007,2008,2009,2010,2013,2020,2021,2022,2030,2033,2034,2035,2038,2040,2041,2042,2043,2045,2046,2047,2048,2049,2065,2068,2099,2100,2103,2105,2106,2107,2111,2119,2121,2126,2135,2144,2160,2161,2170,2179,2190,2191,2196,2200,2222,2251,2260,2288,2301,2323,2366,2381,2382,2383,2393,2394,2399,2401,2492,2500,2522,2525,2557,2601,2602,2604,2605,2607,2608,2638,2701,2702,2710,2717,2718,2725,2800,2809,2811,2869,2875,2909,2910,2920,2967,2968,2998,3000,3001,3003,3005,3006,3007,3011,3013,3017,3030,3031,3052,3071,3077,3128,3168,3211,3221,3260,3261,3268,3269,3283,3300,3301,3306,3322,3323,3324,3325,3333,3351,3367,3369,3370,3371,3372,3389,3390,3404,3476,3493,3517,3527,3546,3551,3580,3659,3689,3690,3703,3737,3766,3784,3800,3801,3809,3814,3826,3827,3828,3851,3869,3871,3878,3880,3889,3905,3914,3918,3920,3945,3971,3986,3995,3998,4000,4001,4002,4003,4004,4005,4006,4045,4111,4125,4126,4129,4224,4242,4279,4321,4343,4443,4444,4445,4446,4449,4550,4567,4662,4848,4899,4900,4998,5000,5001,5002,5003,5004,5009,5030,5033,5050,5051,5054,5060,5061,5080,5087,5100,5101,5102,5120,5190,5200,5214,5221,5222,5225,5226,5269,5280,5298,5357,5405,5414,5431,5432,5440,5500,5510,5544,5550,5555,5560,5566,5631,5633,5666,5678,5679,5718,5730,5800,5801,5802,5810,5811,5815,5822,5825,5850,5859,5862,5877,5900,5901,5902,5903,5904,5906,5907,5910,5911,5915,5922,5925,5950,5952,5959,5960,5961,5962,5963,5987,5988,5989,5998,5999,6000,6001,6002,6003,6004,6005,6006,6007,6009,6025,6059,6100,6101,6106,6112,6123,6129,6156,6346,6389,6502,6510,6543,6547,6565,6566,6567,6580,6646,6666,6667,6668,6669,6689,6692,6699,6779,6788,6789,6792,6839,6881,6901,6969,7000,7001,7002,7004,7007,7019,7025,7070,7100,7103,7106,7200,7201,7402,7435,7443,7496,7512,7625,7627,7676,7741,7777,7778,7800,7911,7920,7921,7937,7938,7999,8000,8001,8002,8007,8008,8009,8010,8011,8021,8022,8031,8042,8045,8080,8081,8082,8083,8084,8085,8086,8087,8088,8089,8090,8093,8099,8100,8180,8181,8192,8193,8194,8200,8222,8254,8290,8291,8292,8300,8333,8383,8400,8402,8443,8500,8600,8649,8651,8652,8654,8701,8800,8873,8888,8899,8994,9000,9001,9002,9003,9009,9010,9011,9040,9050,9071,9080,9081,9090,9091,9099,9100,9101,9102,9103,9110,9111,9200,9207,9220,9290,9415,9418,9485,9500,9502,9503,9535,9575,9593,9594,9595,9618,9666,9876,9877,9878,9898,9900,9917,9929,9943,9944,9968,9998,9999,10000,10001,10002,10003,10004,10009,10010,10012,10024,10025,10082,10180,10215,10243,10566,10616,10617,10621,10626,10628,10629,10778,11110,11111,11967,12000,12174,12265,12345,13456,13722,13782,13783,14000,14238,14441,14442,15000,15002,15003,15004,15660,15742,16000,16001,16012,16016,16018,16080,16113,16992,16993,17877,17988,18040,18101,18988,19101,19283,19315,19350,19780,19801,19842,20000,20005,20031,20221,20222,20828,21571,22939,23502,24444,24800,25734,25735,26214,27000,27352,27353,27355,27356,27715,28201,30000,30718,30951,31038,31337,32768,32769,32770,32771,32772,32773,32774,32775,32776,32777,32778,32779,32780,32781,32782,32783,32784,32785,33354,33899,34571,34572,34573,35500,38292,40193,40911,41511,42510,44176,44442,44443,44501,45100,48080,49152,49153,49154,49155,49156,49157,49158,49159,49160,49161,49163,49165,49167,49175,49176,49400,49999,50000,50001,50002,50003,50006,50300,50389,50500,50636,50800,51103,51493,52673,52822,52848,52869,54045,54328,55055,55056,55555,55600,56737,56738,57294,57797,58080,60020,60443,61532,61900,62078,63331,64623,64680,65000,65129,65389)
    }

    process {
        return $Top1000Ports[0..($X-1)]
    }

}

function Get-ServiceByPort {
    [CmdletBinding()]
    param (
        [Parameter(Position = 0, Mandatory = $false)]  
        $Port

    )

    $services = @{
        20 = 'FTP Data'
        21 = 'FTP Control'
        22 = 'SSH'
        23 = 'Telnet'
        25 = 'SMTP'
        53 = 'DNS'
        67 = 'DHCP Server'
        68 = 'DHCP Client'
        80 = 'HTTP'
        110 = 'POP3'
        119 = 'NNTP'
        123 = 'NTP'
        135 = 'RPC'
        137 = 'NetBIOS Name Service'
        138 = 'NetBIOS Datagram Service'
        139 = 'NetBIOS Session Service'
        143 = 'IMAP'
        161 = 'SNMP'
        162 = 'SNMP Trap'
        194 = 'IRC'
        389 = 'LDAP'
        443 = 'HTTPS'
        445 = 'SMB'
        465 = 'SMTPS'
        514 = 'Syslog'
        546 = 'DHCPv6 Client'
        547 = 'DHCPv6 Server'
        587 = 'SMTP Submission'
        631 = 'IPP (Internet Printing Protocol)'
        636 = 'LDAPS'
        989 = 'FTPS Data'
        990 = 'FTPS Control'
        993 = 'IMAPS'
        995 = 'POP3S'
        1080 = 'SOCKS Proxy'
        1194 = 'OpenVPN'
        1433 = 'MSSQL'
        1701 = 'L2TP'
        1723 = 'PPTP'
        1812 = 'RADIUS'
        1813 = 'RADIUS Accounting'
        2049 = 'NFS'
        3306 = 'MySQL'
        3389 = 'RDP'
        5060 = 'SIP'
        5061 = 'SIPS'
        5190 = 'ICQ/AOL Instant Messenger'
        5222 = 'XMPP Client'
        5223 = 'XMPP Client SSL'
        5228 = 'Google Cloud Messaging'
        5269 = 'XMPP Server'
        5280 = 'XMPP BOSH'
        5432 = 'PostgreSQL'
        5554 = 'SGSN'
        5555 = 'SGSN'
        5900 = 'VNC'
        6000 = 'X11'
        6346 = 'Gnutella'
        6347 = 'Gnutella'
        7070 = 'RTSP'
        8000 = 'HTTP Alt'
        8080 = 'HTTP Proxy'
        8081 = 'HTTP Proxy Alt'
        8443 = 'HTTPS Alt'
        8888 = 'HTTP Alt'
        9001 = 'Tor ORPort'
        9091 = 'Transmission'
        9200 = 'Elasticsearch'
        9418 = 'Git'
        9999 = 'Urchin'
        10000 = 'Webmin'
        11211 = 'Memcached'
        27017 = 'MongoDB'
        28017 = 'MongoDB Web Status'
        81 = 'HTTP Alternate'
        102 = 'S7comm'
        150 = 'NetBIOS Session Service'
        427 = 'SLP'
        500 = 'ISAKMP'
        524 = 'NCP'
        873 = 'rsync'
        1099 = 'RMI Registry'
        1521 = 'Oracle SQL'
        1589 = 'Cisco VQP'
        1900 = 'UPnP SSDP'
        2000 = 'Cisco SCCP'
        2181 = 'ZooKeeper'
        2375 = 'Docker API'
        2376 = 'Docker API SSL'
        2638 = 'Sybase'
        3260 = 'iSCSI'
        3299 = 'SAPRouter'
        3541 = 'Veeam'
        4848 = 'GlassFish'
        5000 = 'UPnP AV'
        5009 = 'Microsoft Windows Media Encoder'
        5500 = 'VNC Listener'
        5800 = 'VNC Web'
        5901 = 'VNC Alternate'
        6001 = 'X11 Alternate'
        6379 = 'Redis'
        6881 = 'BitTorrent'
        7001 = 'WebLogic'
        7077 = 'Apache Spark'
        8089 = 'Splunk'
        8140 = 'Puppet'
        8500 = 'Consul'
        8600 = 'NSClient++'
        8787 = 'RStudio'
        9300 = 'Elasticsearch Transport'
        10050 = 'Zabbix Agent'
        10051 = 'Zabbix Server'
        27018 = 'MongoDB Shard'
        27019 = 'MongoDB Config'
        88 = 'Kerberos'
        111 = 'RPCBIND'
        120 = 'CFDP'
        175 = 'VMNET'
        210 = 'ANSI Z39.50'
        213 = 'IPX'
        363 = 'RSVP Tunnel'
        383 = 'HP OpenView'
        401 = 'UPS'
        434 = 'MobileIP-Agent'
        444 = 'SNPP'
        464 = 'Kerberos Change/Set password'
        468 = 'DLS / Photuris'
        487 = 'SAFT'
        512 = 'exec / comsat'
        513 = 'Login'
        515 = 'Printer'
        520 = 'EFS'
        593 = 'HTTP RPC Ep Map'
        616 = 'SCO System Administration Server'
        618 = 'SCO Desktop Administration Server'
        623 = 'ASF RMCP'
        626 = 'Serial Number Authority'
        666 = 'Doom'
        749 = 'Kerberos 5 admin/changepw'
        765 = 'Webster'
        767 = 'Phone'
        901 = 'Samba SWAT'
        953 = 'RNDC'
        992 = 'Telnet SSL'
        1311 = 'Dell OpenManage'
        1434 = 'MS SQL Monitor'
        1645 = 'RADIUS Authentication'
        1646 = 'RADIUS Accounting'
        1688 = 'NSI Server'
        1717 = 'H.323'
        1911 = 'Star Paging'
        1985 = 'HSRP'
        1998 = 'Cisco X.25 over TCP (XOT)'
        2288 = 'NetML'
        2366 = 'qip-login'
        2535 = 'MADCAP'
        2746 = 'RSVP'
        3000 = 'Firstclass'
        3128 = 'Squid HTTP Proxy'
        3268 = 'Microsoft Global Catalog'
        3527 = 'Microsoft Message Queue'
        3998 = 'Distributed Nagios Executor'
        4000 = 'Microsoft Message Queue'
        4001 = 'Microsoft Message Queue'
        4094 = 'sysrq daemon'
        4116 = 'SMARTS'
        4125 = 'Microsoft Remote Web Workplace'
        4444 = 'KRB524'
        4500 = 'IPSec NAT Traversal'
        4662 = 'eMule'
    }

    if ($services.ContainsKey($Port)) {
        return $services[$Port]
    } else {
        return "Unknown"
        
    }
}
   
function Get-HostDiscovery{
    <#
    .SYNOPSIS
        Get-HostDiscovery is used to find which hosts on the network are up. 
    
    .DESCRIPTION
        Get-HostDiscovery is a function that returns a list of the specified host(s) by attempting TCP three-way handshake. 
    
    .PARAMETER Target
        The remote computer(s) to be scanned. 
        Possible CIDR notation, range or enumeration of IP addresses.

    .PARAMETER $OutputAll
        Specifies that the result will be written to .txt, .csv and .xml file and path to where the file will be created.

    .PARAMETER OutTxt
        Specifies that the result will be written to .txt file and path to where the file will be created.

    .PARAMETER OutCsv
        Specifies that the result will be written to .csv file and path to where the file will be created.

    .PARAMETER OutXml
        Specifies that the result will be written to .xml file and path to where the file will be created.

    .PARAMETER TraceRoute
        Specifies that the function should also provide traceroute info.

    .PARAMETER Threads
        Specifies how many threads to scan hosts and ports in paralell should be used to speed up scanning.

    .PARAMETER OSdet
        Specifies that function should also provide information about operating system.
    
    .EXAMPLE
        Get-HostDiscovery -Target 1.1.1.0/26 Threads 10

    .EXAMPLE
        Get-HostDiscovery -Target 1.1.1.'1,2,5,9' -Traceroute
         
    .EXAMPLE
        Get-HostDiscovery -Target 1.1.1.1-125 -OutXml "C:\Desktop"  

    .EXAMPLE
        Get-HostDiscovery -Target 1.1.1.35, 1.1.1.5   
    
    .INPUTS
        System.String
    
    .OUTPUTS
        PSCustomObject
    
    .NOTES
        Author: Dominik Sabota
    #>
    [CmdletBinding()]
    param (
        [Parameter(Position = 0, ValueFromPipeline=$true, Mandatory = $true)]
        $Target,

        [Parameter(Position = 1, Mandatory = $false)]
        [switch]$OSDet,

        [Parameter(Position = 2, Mandatory = $false)]
        [Int32]$Threads = 5,

        [Parameter(Position = 3, Mandatory = $false)]
        [switch]$TraceRoute = $false,

        [Parameter(Position = 4, Mandatory = $false)]
        [string]$OutputAll,

        [Parameter(Position = 5, Mandatory = $false)]
        [string]$OutTxt,

        [Parameter(Position =6, Mandatory = $false)]
        [string]$OutCsv,

        [Parameter(Position = 7, Mandatory = $false)]
        [string]$OutXml,

        [Parameter(Position = 8, Mandatory = $false)]
        [Int32]$Timeout = 1000,

        [Parameter(Position = 9, Mandatory = $false)]
        [switch]$Detailed 
    )
        
    begin {
        $date=Get-Date
        "Starting Host Discovery at $date "
        $Targets = Get-TargetEnumeration $Target #creating list of IP addresses
        $IPs = @($($Targets.IPs))
    } 
    
    process {
        $jobs = @()
        $ipScanned = 0
        $ipdown = 0
        foreach ($ip in $IPs) {
            $ipScanned++
            while ($jobs.Count -ge $Threads) {
                $completedJob = Receive-Job -Job $jobs -Wait -AutoRemoveJob
                $completedJob
                $jobs = $jobs | Where-Object { $_.State -ne 'Completed' }
            }

            $pingJobs = @()
            $pingJobs += Start-Job -ScriptBlock {
                param($ip, $Timeout)
                $result = Test-Connection -ComputerName $ip -Quiet -Count 1 -Delay ($Timeout/1000) #pinging IP address

                if ($result) {
                    @{
                        'Host' = $ip
                        'Status' = "Up"
                    }
                }else{
                    @{
                        'Host' = $ip
                        'Status' = "Down"
                    }
                }
            } -ArgumentList $ip, $Timeout

            $pingResults = Receive-Job -Job $pingJobs -Wait -AutoRemoveJob
            
            if ($pingResults.Status -eq "Up") {
                if ($TraceRoute) {
                    $traceJob = Start-Job -ScriptBlock {
                        param($ip, $Timeout)
                        $TraceResult = Test-NetConnection -ComputerName $ip -TraceRoute -WarningAction SilentlyContinue
                        $traceRoute = $TraceResult.TraceRoute | Where-Object { $_.ToString() -ne '::' } | ForEach-Object { $_.ToString() }
                        $traceString = $traceRoute -join ' -> '
                        return $traceString
                    } -ArgumentList $ip, $Timeout
                    $Trace = Receive-Job -Job $traceJob -Wait
                } else {
                    $Trace = $null
                }

                $OS = $null
                if ($OSDet) {
                    $OS = @()
                    $commonPorts = @{
                        'Linux/Unix/BSD' = @(22, 25, 80, 443, 3306, 5432, 548, 631, 8000);
                        'Windows' = @(80, 443, 445, 3389, 1433);
                    }
                
                    $OSjobs = @(
                        # Check for SMB information
                        Start-Job -ScriptBlock {
                            param($ip)
                            try {
                                $SMBInfo = (Get-SmbConnection -CimSession (New-CimSession -ComputerName $ip -SessionOption (New-CimSessionOption -Protocol Dcom) -ErrorAction Stop) -ErrorAction Stop).ServerName
                                if ($SMBInfo) {
                                    return "$($SMBInfo.OperatingSystem) | $($SMBInfo.Version)"
                                }
                            } catch {}
                        } -ArgumentList $ip
                
                        # Check for HTTP header information
                        Start-Job -ScriptBlock {
                            param($ip)
                            try {
                                $HTTPHeader = (Invoke-WebRequest -Uri "http://$ip" -TimeoutSec 5 -UseBasicParsing -ErrorAction Stop).Headers["Server"]
                                if ($HTTPHeader) {
                                    return [regex]::Match($HTTPHeader, '\((.*?)\)').Groups[1].Value
                                }
                            } catch {}
                        } -ArgumentList $ip
                
                        # Check for DNS TXT records
                        Start-Job -ScriptBlock {
                            param($ip)
                            try {
                                $DNSTXT = (Resolve-DnsName -Name $ip -Type TXT -ErrorAction Stop).Strings
                                if ($DNSTXT) {
                                    return "$($DNSTXT -join ' | ')"
                                }
                            } catch {}
                        } -ArgumentList $ip
                
                        # Check for common ports
                        Start-Job -ScriptBlock {
                            param($ip, $commonPorts, $Timeout)
                        
                            $uniquePorts = $commonPorts.Values | ForEach-Object { $_ } | Sort-Object -Unique
                            $portResults = @()
                        
                            foreach ($port in $uniquePorts) {
                                if ($ip -match '^([0-9A-Fa-f]{0,4}:){1,7}[0-9A-Fa-f]{0,4}(/(\d{1,2}))?$'){
                                    $result =  Test-NetConnection -ComputerName $ip -Port $port -WarningAction SilentlyContinue 
                                    if ($result.TcpTestSucceeded) {
                                        $portResults += @{
                                            'Port' = $port
                                            'Status' = "Open"
                                        }
                                    } 
                                }else{
                                    $tcpClient = New-Object System.Net.Sockets.TcpClient
                                    $addresses = [System.Net.Dns]::GetHostAddresses($ip)
                                    foreach ($address in $addresses) {
                                        try {
                                            $connect = $tcpClient.BeginConnect($address, $port, $null, $null)
                                            $waitResult = $connect.AsyncWaitHandle.WaitOne($Timeout, $false)
                        
                                            if ($waitResult) {
                                                $portResults += @{
                                                    'Port'   = $port
                                                    'Status' = "Open"
                                                }
                                                $tcpClient.Close()
                                                break
                                            }
                                        } catch {
                                            continue
                                        }
                                    }
                                }
                            }
                        
                            if ($portResults) {
                                $osEstimations = @{}
                                foreach ($os in $commonPorts.Keys) {
                                    $osEstimations[$os] = ($commonPorts[$os] | Where-Object { $portResults.Port -contains $_ }).Count
                                }
                                $detectedOS = $osEstimations.Keys | Sort-Object { $osEstimations[$_] } -Descending | Select-Object -First 1
                                return $detectedOS
                            }
                        } -ArgumentList $ip, $commonPorts, $Timeout
                        
                    )
                
                    $results = Receive-Job -Job $OSjobs -Wait -AutoRemoveJob
                    foreach ($result in $results) {
                        if ($null -ne $result) {
                            $OS += $result
                        }
                    }
                
                    if ($OS.Count -gt 0) {
                        $OS = ($OS -join ' | ')
                    } else {
                        $OS = "Unknown"
                    }
                }

                $jobs += Start-Job -ScriptBlock {
                    param($ip, $OS, $Trace, $TraceRoute, $OSDet)
                
                    $output = New-Object psobject -Property @{
                        'Target' = $ip
                        'Result' = $pingResults
                    }
                
                    if ($TraceRoute) {
                        $output | Add-Member -MemberType NoteProperty -Name 'TraceRoute' -Value $Trace
                    }
                
                    if ($OSDet) {
                        $output | Add-Member -MemberType NoteProperty -Name 'OS' -Value $OS
                    }
                
                    return $output
                } -ArgumentList $ip, $OS, $Trace, $TraceRoute ,$OSDet  
            }else{
                $ipdown++
            }           
        }
        $Results = Receive-Job -Job $jobs -Wait -AutoRemoveJob    
    }
        
    end {
        foreach ($resultItem in $Results) {
            $report = "`nScan report for $($resultItem.Target):" + [Environment]::NewLine 
                
            if ($resultItem.PSObject.Properties.Name -contains 'OS') {
                $report += "OS: $($resultItem.OS)" + [Environment]::NewLine
            }
    
            if ($resultItem.PSObject.Properties.Name -contains 'TraceRoute') {
                $report += "TraceRoute: $($resultItem.TraceRoute)" + [Environment]::NewLine
            }
    
            $report += ($resultItem.Result | Format-Table -AutoSize | Out-String)
            $report
    
            if ($PSBoundParameters.ContainsKey("OutputAll")) {
                if (-not (Test-Path $OutputAll)) {
                    New-Item -Path $OutputAll -ItemType File -Force | Out-Null
                }
                $report | Out-File -FilePath $OutputAll -Encoding UTF8 -Append
                $resultItem | Export-Csv -Path "${OutputAll}.csv" -Encoding UTF8 -NoTypeInformation -Append
                $resultItem | Export-Clixml -Path "${OutputAll}.xml" -Append
            }
    
            if ($PSBoundParameters.ContainsKey("OutTxt")) {
                if (-not (Test-Path $OutTxt)) {
                    New-Item -Path $OutTxt -ItemType File -Force | Out-Null
                }
                $report | Out-File -FilePath $OutTxt -Encoding UTF8 -Append
            }
            if ($PSBoundParameters.ContainsKey("OutCsv")) {
                if (-not (Test-Path $OutCsv)) {
                    New-Item -Path $OutCsv -ItemType File -Force | Out-Null
                }
                $resultItem | Export-Csv -Path $OutCsv -Encoding UTF8 -NoTypeInformation -Append
            }
            if ($PSBoundParameters.ContainsKey("OutXml")) {
                if (-not (Test-Path $OutXml)) {
                    New-Item -Path $OutXml -ItemType File -Force | Out-Null
                }
                $resultItem | Export-Clixml -Path $OutXml -Append
            }
        }
        "Scanning done: $ipScanned IP addresses scanned."
        "$ipdown hosts are down or filtered." + [Environment]::NewLine
        $endDate = Get-Date
        "End of scanning at $endDate"
        "Timeout: $Timeout"
        if ($PSBoundParameters.ContainsKey("Detailed")) {
            "[ERROR] Wrong type of input: [" + $($Targets.ErrorValues) + "]"
        }
    }
}

function Get-ConnectScan{
    <#
    .SYNOPSIS
        Returns a list of open ports on each scanned host.
    
    .DESCRIPTION
        Get-ConnectScan is a function that returns a list of open ports from
        the specified remote computer(s) by attempting TCP three-way handshake. 
    
    .PARAMETER Target
        The remote computer(s) to be scanned. 
        Possible CIDR notation, range or enumeration of IP addresses.

    .PARAMETER Port
        Specifies port number(s) to be scanned.

    .PARAMETER TopXPorts
        Specifies number of the most used ports to be scanned.

    .PARAMETER OutTxt
        Specifies that the result will be written to .txt file and path to where the file will be created.

    .PARAMETER OutCsv
        Specifies that the result will be written to .csv file and path to where the file will be created.

    .PARAMETER OutXml
        Specifies that the result will be written to .xml file and path to where the file will be created.

    .PARAMETER $OutputAll
        Specifies that the result will be written to .txt, .csv and .xml file and path to where the file will be created.

    .PARAMETER TraceRoute
        Specifies that the function should also provide traceroute info.

    .PARAMETER Threads
        Specifies how many threads to scan hosts and ports in paralell should be used to speed up scanning.

    .PARAMETER OSdet
        Specifies that function should also provide information about operating system.

    .PARAMETER NoPing
        Specifies that function shouldn't check if the target is up.

    .EXAMPLE
         Get-ConnectScan -Target 1.1.1.0/26 -Port 80,100 -NoPing 

    .EXAMPLE
         Get-ConnectScan -Target 1.1.1.'1,2,5,9' -Port 21,22,3066 -OSDet -Threads 10

    .EXAMPLE
         Get-ConnectScan -Target 1.1.1.1-125 -Port 21,22 -OutXml "C:\Desktop"

    .EXAMPLE
         Get-ConnectScan -Target 1.1.1.35, 1.1.1.5 -Port 1,5,30

    
    .EXAMPLE
         Get-ConnectScan -Target 1.1.1.10 -TopXPorts 100 -Traceroute

    
    .INPUTS
        System.String
    
    .OUTPUTS
        PSCustomObject
    
    .NOTES
        Author: Dominik Sabota  
        
    #>
    [CmdletBinding()]
    param (
        [Parameter(Position = 0, ValueFromPipeline=$true, Mandatory = $true)]
        $Target, 

        [Parameter(Position = 1, Mandatory = $false)]
        [ValidateRange(1,65535)]
        [int[]]$Port,

        [Parameter(Position = 2, Mandatory = $false)]
        [Int32]$TopXPorts,

        [Parameter(Position = 3, Mandatory = $false)]
        [switch]$OSDet,

        [Parameter(Position = 4, Mandatory = $false)]
        [Int32]$Threads = 5,

        [Parameter(Position = 5, Mandatory = $false)]
        [switch]$TraceRoute = $false,

        [Parameter(Position = 6, Mandatory = $false)]
        [string]$OutputAll,

        [Parameter(Position = 7, Mandatory = $false)]
        [string]$OutTxt,

        [Parameter(Position = 8, Mandatory = $false)]
        [string]$OutCsv,

        [Parameter(Position = 9, Mandatory = $false)]
        [string]$OutXml,

        [Parameter(Position = 10, Mandatory = $false)]
        [Int32]$Timeout = 1000,

        [Parameter(Position = 11, Mandatory = $false)]
        [switch]$NoPing 
    )

    begin {
        $date = Get-Date
        "Starting TCP Connection Scan at $date"
        $IPs = Get-TargetEnumeration $Target
        if ($PSBoundParameters.ContainsKey("TopXPorts")) {
            $Port = Get-TopXPorts -TopXPorts $TopXPorts
        }
    }
    
    process {
        $jobs = @()
        $ipScanned = 0
        $hostsDown
        foreach ($ip in $IPs) {
            $ipScanned++
            $portJobs = @()
            $traceJob = $null
            $OS = $null

            while ($jobs.Count -ge $Threads) {
                $completedJob = Receive-Job -Job $jobs -Wait -AutoRemoveJob
                $completedJob
                $jobs = $jobs | Where-Object { $_.State -ne 'Completed' }
            }

            if(-not $PSBoundParameters.ContainsKey("NoPing")){
                $ping = Test-Connection -ComputerName $ip -Count 1 -Quiet
            }else{
                $ping = $true
            }
            
            if($ping -eq $true){
                foreach ($num in $Port) {
                    $portJobs += Start-Job -ScriptBlock {
                        param($ip, $num, $Timeout)
                        if ($ip -match '^([0-9A-Fa-f]{0,4}:){1,7}[0-9A-Fa-f]{0,4}(/(\d{1,2}))?$'){
                            $result =  Test-NetConnection -ComputerName $ip -Port $num -WarningAction SilentlyContinue #pinging IP address
                            if ($result.TcpTestSucceeded) {
                                $portResults += @{
                                    'Port' = $num
                                    'Status' = "Open"
                                }
                            } 
                        }else{
                            $tcpClient = New-Object System.Net.Sockets.TcpClient
                            $addresses = [System.Net.Dns]::GetHostAddresses($ip)
                        
                            $success = $false
                            foreach ($address in $addresses) {
                                try {
                                    $connect = $tcpClient.BeginConnect($address, $num, $null, $null)
                                    $waitResult = $connect.AsyncWaitHandle.WaitOne($Timeout, $false)
                        
                                    if ($waitResult) {
                                        $success = $true
                                        break
                                    }
                                } catch {
                                    continue
                                }
                            }
                        
                            $tcpClient.Close()
                        
                            if ($success) {
                                @{
                                    'Port'   = $num
                                    'Status' = "Open"
                                }
                            }
                        }
                    } -ArgumentList $ip, $num, $Timeout
                    
                }
                
                $portResults = Receive-Job -Job $portJobs -Wait -AutoRemoveJob
                $detectedPorts = $portResults | ForEach-Object { $_.Port }

                if ($TraceRoute) {
                    $traceJob = Start-Job -ScriptBlock {
                        param($ip, $Timeout)
                        $TraceResult = Test-NetConnection -ComputerName $ip -TraceRoute -WarningAction SilentlyContinue
                        $traceRoute = $TraceResult.TraceRoute | Where-Object { $_.ToString() -ne '::' } | ForEach-Object { $_.ToString() }
                        $traceString = $traceRoute -join ' -> '
                        return $traceString
                    } -ArgumentList $ip, $Timeout
                }
        
                if ($TraceRoute) {
                    $Trace = Receive-Job -Job $traceJob -Wait    
                }
    
                if ($OSDet) {
                    $OS = @()
                    $commonPorts = @{
                        'Linux/Unix/BSD' = @(22, 25, 80, 443, 3306, 5432, 548, 631, 8000);
                        'Windows' = @(80, 443, 445, 3389, 1433);
                    }
                
                    $OSjobs = @(
                        # Check for SMB information
                        Start-Job -ScriptBlock {
                            param($ip)
                            try {
                                $SMBInfo = (Get-SmbConnection -CimSession (New-CimSession -ComputerName $ip -SessionOption (New-CimSessionOption -Protocol Dcom) -ErrorAction Stop) -ErrorAction Stop).ServerName
                                if ($SMBInfo) {
                                    return "$($SMBInfo.OperatingSystem) | $($SMBInfo.Version)"
                                }
                            } catch {}
                        } -ArgumentList $ip
                
                        # Check for HTTP header information
                        Start-Job -ScriptBlock {
                            param($ip)
                            try {
                                $HTTPHeader = (Invoke-WebRequest -Uri "http://$ip" -TimeoutSec 5 -UseBasicParsing -ErrorAction Stop).Headers["Server"]
                                if ($HTTPHeader) {
                                    return [regex]::Match($HTTPHeader, '\((.*?)\)').Groups[1].Value
                                }
                            } catch {}
                        } -ArgumentList $ip
                
                        # Check for DNS TXT records
                        Start-Job -ScriptBlock {
                            param($ip)
                            try {
                                $DNSTXT = (Resolve-DnsName -Name $ip -Type TXT -ErrorAction Stop).Strings
                                if ($DNSTXT) {
                                    return "$($DNSTXT -join ' | ')"
                                }
                            } catch {}
                        } -ArgumentList $ip
                
                        # Check for common ports
                        Start-Job -ScriptBlock {
                            param($ip, $commonPorts, $detectedPorts, $Timeout)
    
                            $remainingPorts = $commonPorts.Values | ForEach-Object { $_ } | Sort-Object -Unique | Where-Object { -not ($detectedPorts -contains $_) }
                            $portResults = @()
    
                            foreach ($port in $remainingPorts) {
                                if ($ip -match '^([0-9A-Fa-f]{0,4}:){1,7}[0-9A-Fa-f]{0,4}(/(\d{1,2}))?$'){
                                    $result =  Test-NetConnection -ComputerName $ip -Port $port -WarningAction SilentlyContinue 
                                    if ($result.TcpTestSucceeded) {
                                        $portResults += @{
                                            'Port' = $port
                                            'Status' = "Open"
                                        }
                                    } 
                                }else{
                                    $tcpClient = New-Object System.Net.Sockets.TcpClient
                                    $addresses = [System.Net.Dns]::GetHostAddresses($ip)
                                
                                    $success = $false
                                    foreach ($address in $addresses) {
                                        try {
                                            $connect = $tcpClient.BeginConnect($address, $port, $null, $null)
                                            $waitResult = $connect.AsyncWaitHandle.WaitOne($Timeout, $false)
                                
                                            if ($waitResult) {
                                                $success = $true
                                                break
                                            }
                                        } catch {
                                            continue
                                        }
                                    }
                                
                                    $tcpClient.Close()
                                
                                    if ($success) {
                                        $portResults += @{
                                            'Port'   = $port
                                            'Status' = "Open"
                                        } 
                                    }
                                }
                            }
        
                            $allDetectedPorts = $detectedPorts + ($portResults | ForEach-Object { $_.Port })
    
                            if ($allDetectedPorts) {
                                $osEstimations = @{}
                                foreach ($os in $commonPorts.Keys) {
                                    $osEstimations[$os] = ($commonPorts[$os] | Where-Object { $detectedPorts -contains $_ }).Count
                                }
                                $detectedOS = $osEstimations.Keys | Sort-Object { $osEstimations[$_] } -Descending | Select-Object -First 1
                                return $detectedOS
                            }
                        } -ArgumentList $ip, $commonPorts
                    )
                    $results = Receive-Job -Job $OSjobs -Wait -AutoRemoveJob
                    foreach ($result in $results) {
                        if ($null -ne $result) {
                            $OS += $result
                        }
                    }
                
                    if ($OS.Count -gt 0) {
                        $OS = ($OS -join ' | ')
                    } else {
                        $OS = "Unknown"
                    }
                }

                $ipResult = @()
                $ipdown = $Port.Length
                foreach ($portResult in $portResults) {
                    if ($portResult.Status -eq "Open") {
                        $service = Get-ServiceByPort -Port $portResult.Port
                        $ipResult += New-Object psobject -Property ([ordered]@{
                            'Port' = $portResult.Port
                            'Service' = $service
                        })
                        $ipdown--
                    }
                }
                $jobs += Start-Job -ScriptBlock {
                    param($ip, $ipResult, $OS, $ipdown, $Trace, $TraceRoute, $OSDet)
                
                    $output = New-Object psobject -Property @{
                        'Target' = $ip
                        'Result' = $ipResult
                        'ClosedOrFilteredPorts' = $ipdown
                    }
                
                    if ($TraceRoute) {
                        $output | Add-Member -MemberType NoteProperty -Name 'TraceRoute' -Value $Trace
                    }
                
                    if ($OSDet) {
                        $output | Add-Member -MemberType NoteProperty -Name 'OS' -Value $OS
                    }
                
                    return $output
                } -ArgumentList $ip, $ipResult, $OS, $ipdown, $Trace, $TraceRoute, $OSDet 
            }else{ 
                $hostsDown++
            }            
        }
        $IPResults = Receive-Job -Job $jobs -Wait -AutoRemoveJob
    }            
    
    end {
        foreach ($resultItem in $IPResults) {
            $report = "`nScan report for $($resultItem.Target):" + [Environment]::NewLine +
                "$($resultItem.ClosedOrFilteredPorts) ports are closed or filtered." + [Environment]::NewLine
    
            if ($resultItem.PSObject.Properties.Name -contains 'OS') {
                $report += "OS: $($resultItem.OS)" + [Environment]::NewLine
            }
    
            if ($resultItem.PSObject.Properties.Name -contains 'TraceRoute') {
                $report += "TraceRoute: $($resultItem.TraceRoute)" + [Environment]::NewLine
            }
    
            $report += ($resultItem.Result | Format-Table -AutoSize | Out-String)
            $report
    
            if ($PSBoundParameters.ContainsKey("OutputAll")) {
                if (-not (Test-Path $OutputAll)) {
                    New-Item -Path $OutputAll -ItemType File -Force | Out-Null
                }
                $report | Out-File -FilePath $OutputAll -Encoding UTF8 -Append
                $resultItem | Export-Csv -Path "${OutputAll}.csv" -Encoding UTF8 -NoTypeInformation -Append
                $resultItem | Export-Clixml -Path "${OutputAll}.xml" -Append
            }
    
            if ($PSBoundParameters.ContainsKey("OutTxt")) {
                if (-not (Test-Path $OutTxt)) {
                    New-Item -Path $OutTxt -ItemType File -Force | Out-Null
                }
                $report | Out-File -FilePath $OutTxt -Encoding UTF8 -Append
            }
            if ($PSBoundParameters.ContainsKey("OutCsv")) {
                if (-not (Test-Path $OutCsv)) {
                    New-Item -Path $OutCsv -ItemType File -Force | Out-Null
                }
                $resultItem | Export-Csv -Path $OutCsv -Encoding UTF8 -NoTypeInformation -Append
            }
            if ($PSBoundParameters.ContainsKey("OutXml")) {
                if (-not (Test-Path $OutXml)) {
                    New-Item -Path $OutXml -ItemType File -Force | Out-Null
                }
                $resultItem | Export-Clixml -Path $OutXml -Append
            }
        }
        "Scanning done: $ipScanned IP addresses scanned."
        "$hostsDown hosts is/are down."
        $endDate = Get-Date
        "End of scanning at $endDate"
        "Timeout: $Timeout"
    }    
}