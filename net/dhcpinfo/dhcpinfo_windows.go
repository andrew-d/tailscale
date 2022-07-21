package dhcpinfo

/*

TODO:

https://stackoverflow.com/questions/61575474/finding-all-dhcp-and-dns-servers

$DHCPServers = Get-DhcpServerInDC
ForEach ($DHCPServer in $DHCPServers){
   $OSInfo = Get-CIMInstance -ComputerName $DHCPServer.DnsName -ClassName Win32_OperatingSystem
   [pscustomobject]@{
      ServerName = $DHCPServer.DnsName;
      IPAddress=$DHCPServer.IpAddress;
      OS=$OSInfo.Caption
    }
}

ServerName IPAddress    OS
---------- ---------    --
dc2016     192.168.10.1 Microsoft Windows Server 2016 Standard
*/
