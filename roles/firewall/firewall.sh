#!/bin/bash
#
#
# Script is for stoping Portscan and smurf attack

# Ports used to block port scanning
PORTSCAN_PORTS="21 23"

# Countries to block
COUNTRYBLOCK_GEOIP_FILE="/root/firewall/GeoIPCountryWhois.csv"
#COUNTRIES="CN RU TR KP KR IL IN CR VN TW PH"
COUNTRIES=""

### Flush all the iptables Rules
echo "[ FIREWALL ] Flushing iptables rules ..."
iptables -F
iptables -X

# INPUT iptables Rules
# Accept loopback input
echo "[ FIREWALL ] Adding accept for loopback input ..."
iptables -A INPUT -i lo -p all -j ACCEPT

# Allow 3 way handshake
echo "[ FIREWALL ] Allow 3-way handshake ..."
iptables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT

### DROPspoofing packets
echo "[ FIREWALL ] Drop spoofing packets ..."
iptables -A INPUT -s 10.0.0.0/8 -j DROP
iptables -A INPUT -s 169.254.0.0/16 -j DROP
iptables -A INPUT -s 172.16.0.0/12 -j DROP
iptables -A INPUT -s 127.0.0.0/8 -j DROP

iptables -A INPUT -s 224.0.0.0/4 -j DROP
iptables -A INPUT -d 224.0.0.0/4 -j DROP
iptables -A INPUT -s 240.0.0.0/5 -j DROP
iptables -A INPUT -d 240.0.0.0/5 -j DROP
iptables -A INPUT -s 0.0.0.0/8 -j DROP
iptables -A INPUT -d 0.0.0.0/8 -j DROP
iptables -A INPUT -d 239.255.255.0/24 -j DROP
iptables -A INPUT -d 255.255.255.255 -j DROP

# For SMURF attack protection
echo "[ FIREWALL ] Drop SMURF attacks ..."
iptables -A INPUT -p icmp -m icmp --icmp-type address-mask-request -j DROP
iptables -A INPUT -p icmp -m icmp --icmp-type timestamp-request -j DROP
iptables -A INPUT -p icmp -m icmp -m limit --limit 1/second -j ACCEPT

# Droping all invalid packets
echo "[ FIREWALL ] Drop invalid packets ..."
iptables -A INPUT -m state --state INVALID -j DROP
iptables -A FORWARD -m state --state INVALID -j DROP
iptables -A OUTPUT -m state --state INVALID -j DROP

# Flooding of RST packets, smurf attack Rejection
echo "[ FIREWALL ] Limit RST packets to 2/second ..."
iptables -A INPUT -p tcp -m tcp --tcp-flags RST RST -m limit --limit 2/second --limit-burst 2 -j ACCEPT

# Protecting portscans
# Attacking IP will be locked for 24 hours (3600 x 24 = 86400 Seconds)
echo "[ FIREWALL ] Configure port scan rules ..."
iptables -A INPUT -m recent --name portscan --rcheck --seconds 86400 -j DROP
iptables -A FORWARD -m recent --name portscan --rcheck --seconds 86400 -j DROP

# Remove attacking IP after 24 hours
iptables -A INPUT -m recent --name portscan --remove
iptables -A FORWARD -m recent --name portscan --remove

# These rules add scanners to the portscan list, and log the attempt.
for PORT in ${PORTSCAN_PORTS}
do
	echo "[ FIREWALL ] Setting trap on port ${PORT} ..."
	iptables -A INPUT -p tcp -m tcp --dport ${PORT} -m recent --name portscan --set -j LOG --log-prefix "PORTSCAN:"
	iptables -A INPUT -p tcp -m tcp --dport ${PORT} -m recent --name portscan --set -j DROP
	iptables -A FORWARD -p tcp -m tcp --dport ${PORT} -m recent --name portscan --set -j LOG --log-prefix "PORTSCAN:"
	iptables -A FORWARD -p tcp -m tcp --dport ${PORT} -m recent --name portscan --set -j DROP
done

# Allow the following ports through from outside
iptables -A INPUT -m state --state RELATED,ESTABLISHED -j ACCEPT
iptables -A INPUT -p tcp --dport 80 -m state --state NEW -m limit --limit 50/minute --limit-burst 200 -j ACCEPT
iptables -A INPUT -p tcp --dport 443 -m state --state NEW -m limit --limit 50/minute --limit-burst 200 -j ACCEPT
iptables -A INPUT -m state --state RELATED,ESTABLISHED -m limit --limit 50/second --limit-burst 50 -j ACCEPT

iptables -A INPUT -p tcp --dport 22 -m state --state ESTABLISHED,RELATED -j ACCEPT
iptables -A INPUT -p tcp --dport 22 -m state --state NEW -m limit --limit 3/min --limit-burst 3 -j ACCEPT

# Allow ping means ICMP port is open (If you do not want ping replace ACCEPT with REJECT)
iptables -A INPUT -p icmp -m icmp --icmp-type 8 -j ACCEPT

# Lastly reject All INPUT traffic
iptables -A INPUT -j REJECT

################# Below are for OUTPUT iptables rules #############################################

## Allow loopback OUTPUT
iptables -A OUTPUT -o lo -j ACCEPT
iptables -A OUTPUT -m state --state ESTABLISHED,RELATED -j ACCEPT

# Allow the following ports through from outside
# SMTP = 25
# DNS =53
# HTTP = 80
# HTTPS = 443
# SSH = 22
### You can also add or remove port no. as per your requirement

#iptables -A OUTPUT -p tcp -m tcp --dport 25 -j ACCEPT
iptables -A OUTPUT -p tcp -m udp --dport 53 -j ACCEPT
iptables -A OUTPUT -p udp -m udp --dport 53 -j ACCEPT
iptables -A OUTPUT -p tcp -m tcp --dport 80 -j ACCEPT
iptables -A OUTPUT -p tcp -m tcp --dport 443 -j ACCEPT
iptables -A OUTPUT -p tcp -m tcp --dport 22 -j ACCEPT

# Traceroute
iptables -A OUTPUT -o eth0 -p udp --dport 33434:33524 -m state --state NEW -j ACCEPT

# Allow pings
iptables -A OUTPUT -p icmp -m icmp --icmp-type 8 -j ACCEPT

# Lastly Reject all Output traffic
iptables -A OUTPUT -j REJECT

## Reject Forwarding  traffic
iptables -A FORWARD -j REJECT

### Country blocking
for COUNTRY in ${COUNTRIES}
do
	echo "[ FIREWALL ] Blocking country: ${COUNTRY}"

	iptables -N COUNTRY_${COUNTRY}
	iptables -I INPUT 1 -j COUNTRY_${COUNTRY}

	IPS=`cat ${COUNTRYBLOCK_GEOIP_FILE} | grep "${COUNTRY}"`

	for IP in ${IPS}
	do
		IP_START=`echo ${IP} | cut -d',' -f1 | tr -d '"'`
		IP_END=`echo ${IP} | cut -d',' -f2 | tr -d '"'`

		if [[ "${IP_START}" =~ ^([0-9]{1,3})[.]([0-9]{1,3})[.]([0-9]{1,3})[.]([0-9]{1,3})$ && "${IP_END}" =~ ^([0-9]{1,3})[.]([0-9]{1,3})[.]([0-9]{1,3})[.]([0-9]{1,3})$ ]]; then
			iptables -A COUNTRY_${COUNTRY} -m iprange --src-range ${IP_START}-${IP_END} -j DROP
		fi
	done
done

echo "[ FIREWALL ] Allow inbound / outbound traffic from local network without firewall check ..."

iptables -I INPUT 1 -s 192.168.0.0/24 -j ACCEPT
iptables -I OUTPUT 1 -s 192.168.0.0/24 -j ACCEPT

echo "[ FIREWALL ] Saving iptables state ..."
iptables-save > /etc/iptables/rules.v4
echo "[ FIREWALL ] Done!"
