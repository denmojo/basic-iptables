basic-iptables
==============

Starter iptables firewall rule set for a dual network interface (public/private interface) server.

Change the SSH_PORT and EXTERNAL_IP variables. Preferably drop in a common systemwide config location.
Run sudo sh -x iptables.sh to enable

sudo iptables --flush to clear.
Recommend set on startup with a boot startup script.
