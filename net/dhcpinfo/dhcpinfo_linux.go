package dhcpinfo

/*

sudo dhcpcd -o domain_name_servers -T


nmcli dev show eth0 | grep IP4
nmcli dev list iface eth0 | grep IP4
$ nmcli dev show | grep 'DNS'
IP4.DNS[1]:                  208.67.222.222
IP4.DNS[2]:                  208.67.220.220

/var/lib/NetworkManager/dhclient-<interface>.conf


systemd-resolve --status



grep domain-name-servers /var/lib/dhcp/dhclient.leases


*/
