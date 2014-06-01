iptables -A INPUT -i eth0 -p tcp --dport [SSHPORT] -j ACCEPT -m comment --comment "custom ssh port"
iptables -A INPUT -i eth0 -p tcp --dport 443 -j ACCEPT
iptables -A INPUT -i eth0 -p tcp --dport 80 -j ACCEPT

iptables -A INPUT  -p tcp --sport 21 -m state --state NEW,ESTABLISHED -j ACCEPT -m comment --comment "Allow ftp in for pkg updates"
iptables -A INPUT  -p tcp --sport 22 -m state --state NEW,ESTABLISHED -j ACCEPT -m comment --comment "Allow ssh initiated from inside"
iptables -A INPUT  -p tcp --sport 80 -m state --state NEW,ESTABLISHED -j ACCEPT -m comment --comment "Allow outbound wget"

iptables -A INPUT -i eth1 -p tcp -j ACCEPT
iptables -A INPUT -i lo -j ACCEPT
iptables -A OUTPUT -o eth0 -p tcp -m state --state NEW,ESTABLISHED -j ACCEPT
iptables -A OUTPUT -o eth1 -p tcp -m state --state NEW,ESTABLISHED -j ACCEPT
iptables -A OUTPUT -o eth0 -p udp -m state --state NEW,ESTABLISHED -j ACCEPT
iptables -A OUTPUT -o eth1 -p udp -m state --state NEW,ESTABLISHED -j ACCEPT
iptables -A OUTPUT -p udp -s [EXTERNAL_IP] --sport 1024:65535 -d 8.8.8.8 --dport 53 -m state --state NEW,ESTABLISHED -j ACCEPT
iptables -A INPUT -p udp -s 8.8.8.8 --sport 53 -d [EXTERNAL_IP] --dport 1024:65535 -m state --state ESTABLISHED -j ACCEPT -m comment --comment "DNS lookups"
iptables -A OUTPUT -p tcp -s [EXTERNAL_IP] --sport 1024:65535 -d 8.8.8.8 --dport 53 -m state --state NEW,ESTABLISHED -j ACCEPT
iptables -A INPUT -p tcp -s 8.8.8.8 --sport 53 -d [EXTERNAL_IP] --dport 1024:65535 -m state --state ESTABLISHED -j ACCEPT

iptables -A OUTPUT -p udp -s [EXTERNAL_IP] --sport 1024:65535 -d 4.2.2.2 --dport 53 -m state --state NEW,ESTABLISHED -j ACCEPT
iptables -A INPUT -p udp -s 4.2.2.2 --sport 53 -d [EXTERNAL_IP] --dport 1024:65535 -m state --state ESTABLISHED -j ACCEPT
iptables -A OUTPUT -p tcp -s [EXTERNAL_IP] --sport 1024:65535 -d 4.2.2.2 --dport 53 -m state --state NEW,ESTABLISHED -j ACCEPT
iptables -A INPUT -p tcp -s 4.2.2.2 --sport 53 -d [EXTERNAL_IP] --dport 1024:65535 -m state --state ESTABLISHED -j ACCEPT

iptables -N LOGGING
iptables -A INPUT -j LOGGING
iptables -A LOGGING -m limit --limit 2/min -j LOG --log-prefix "IPTables Packet Dropped: " --log-level 7
iptables -A LOGGING -j DROP
