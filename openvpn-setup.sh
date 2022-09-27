#!/bin/bash
# ====================================================
# Desc   : Simple bash script to setup OpenVPN Server
# Author : Wildy Sheverando
# Github : https://github.com/wildysheverando-888
# ====================================================

mode=$1

# >> Export color and information
export RED="\033[0;31m"
export GREEN="\033[0;32m"
export YELLOW="\033[0;33m"
export BLUE="\033[0;34m"
export PURPLE="\033[0;35m"
export CYAN="\033[0;36m"
export LIGHT="\033[0;37m"
export NC="\033[0m"
export ERROR="[${RED} ERROR ${NC}]"
export INFO="[${YELLOW} INFO ${NC}]"
export FAIL="[${RED} FAIL ${NC}]"
export OKEY="[${GREEN} OKEY ${NC}]"
export PENDING="[${YELLOW} PENDING ${NC}]"
export SEND="[${YELLOW} SEND ${NC}]"
export RECEIVE="[${YELLOW} RECEIVE ${NC}]"
export RED_BG="\e[41m"
export BOLD="\e[1m"
export WARNING="${RED}\e[5m"
export UNDERLINE="\e[4m"

# >> Client IPv4 and IPv6
Public_IPv4=$( curl -s http://v4.ipv6-test.com/api/myip.php )
Public_IPv6=$( curl -s http://v6.ipv6-test.com/api/myip.php )

# >> Check root access
if [[ $(whoami) != 'root' ]]; then
    clear; echo -e "${FAIL} Root access required for this process !"; exit 1
fi

# >> Check Arcitecture Support
if [[ $(uname -m ) != 'x86_64' ]]; then
    clear; echo -e "${FAIL} Only Supported 64Bit System !"; exit 1
fi

# >> Check Command
if [[ $( cat /etc/os-release | grep -w ID | sed 's/ //g' | sed 's/=//g' | sed 's/"//g' | sed 's/ID//g' ) == "ubuntu" ]]; then
    echo -e "${INFO} Ubuntu Detected"
elif [[ $( cat /etc/os-release | grep -w ID | sed 's/ //g' | sed 's/=//g' | sed 's/"//g' | sed 's/ID//g' ) == "debian" ]]; then
    echo -e "${INFO} Debian Detected"
else
    clear; echo -e "${FAIL} Operating System not Supported !"; exit 1
fi

# >> Check curl packages
if ! command -V curl > /dev/null 2>&1; then
    clear; read -p "$(echo -e "${INFO} Curl not installed, press enter to install : ")" enter
    apt update -y; apt upgrade -y; apt install curl -y
fi

function install() {

# >> Configuration
if [[ $( curl --silent --ipv6 ipv6.icanhazip.com ) =~ ^([0-9a-fA-F]{0,4}:){1,7}[0-9a-fA-F]{0,4}$ ]]; then
    clear; read -p "$( echo -e "${INFO} IPv6 detected, want enable it ? [ ${YELLOW}Default${NC} : ${YELLOW}Y${NC} ] | (Y/N) : " ) " ipv6_enable
    if [[ $ipv6_enable == "Y" ]]; then
        IPV6='true'
    elif [[ $ipv6_enable == "y" ]]; then
        IPV6='true'
    elif [[ $ipv6_enable == "N" ]]; then
        IPV6='false'
    elif [[ $ipv6_enable == 'N' ]]; then
        IPV6='false'
    else
        IPV6='true' # >> if user no input a valid options then select true, because from default ipv6 is enabled
    fi
fi 

# >> Configure DNS
clear
echo "1). Google DNS"
echo "2). CloudFlare DNS"
echo "3). Verisign DNS"
echo "4). Manual"
read -p "Choose one [1-4] : " choose
if [[ $choose == "1" ]]; then
DNS1_V4='8.8.8.8'
DNS2_V4='8.8.4.4'
    if [[ $IPV6 == "true" ]]; then
    DNS1_V6='2001:4860:4860::8888'
    DNS2_V6='2001:4860:4860::8844'
    fi
elif [[ $choose == "2" ]]; then
DNS1_V4='1.1.1.1'
DNS2_V4='1.0.0.1'
    if [[ $IPV6 == "true" ]]; then
    DNS1_V6='2606:4700:4700::1111'
    DNS2_V6='2606:4700:4700::1001'
    fi
elif [[ $choose == "3" ]]; then
DNS1_V4='64.6.64.6'
DNS2_V4='64.6.65.6'
    if [[ $IPV6 == "true" ]]; then
    DNS1_V6='2620:74:1b::1:1'
    DNS2_V6='2620:74:1c::2:2'
    fi
elif [[ $choose == "4" ]]; then
read -p "IPv4 DNS Primary   : " primary_v4
read -p "IPv4 DNS Secondary : " secondary_v4
    if [[ $IPV6 == "true" ]]; then
    read -p "IPv6 DNS Primary   : " primary_v6
    read -p "IPv6 DNS Secondary : " secondary_v6
    fi
if [[ ! $primary_v4 =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
    clear; echo -e "${INFO} Input an valid IPv4 Primary DNS to contitune !"; exit 1 
fi
if [[ ! $secondary_v4 =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
    clear; echo -e "${INFO} Input an valid IPv4 Secondary DNS to contitune !"; exit 1 
fi
if [[ $IPV6 == 'true' ]]; then
    if [[ ! $primary_v6 =~ ^([0-9a-fA-F]{0,4}:){1,7}[0-9a-fA-F]{0,4}$ ]]; then
        clear; -e echo "${INFO} Input an valid IPv6 Primary DNS to contitune !"; exit 1 
    fi
    if [[ ! $secondary_v6 =~ ^([0-9a-fA-F]{0,4}:){1,7}[0-9a-fA-F]{0,4}$ ]]; then
        clear; -e echo "${INFO} Input an valid IPv6 Secondary DNS to contitune !"; exit 1 
    fi
fi
DNS1_V4="${primary_v4}"
DNS2_V4="${secondary_v4}"
if [[ $IPV6 == "true" ]]; then
DNS1_V6="${primary_v6}"
DNS2_V6="${secondary_v6}"
fi
else
DNS1_V4='8.8.8.8'
DNS2_V4='8.8.4.4'
if [[ $IPV6 == "true" ]]; then
DNS1_V6='2001:4860:4860::8888'
DNS2_V6='2001:4860:4860::8844'
fi
fi

# >> Save dns to resolv
if [[ $IPV6 == "true" ]]; then
cat > /etc/resolv.conf << END
# Configure by OpenVPN Script
# Author : Wildy Sheverando

# >> IPv4 DNS
nameserver ${DNS1_V4}
nameserver ${DNS2_V4}

# >> IPv6 DNS
nameserver ${DNS1_V6}
nameserver ${DNS2_V6}
END
else
cat > /etc/resolv.conf << END
# Configure by OpenVPN Script
# Author : Wildy Sheverando

# >> IPv4 DNS
nameserver ${DNS1_V4}
nameserver ${DNS2_V4}
END
fi

# >> Install OpenVPN
clear
echo "1). TCP - Port 1194"
echo "2). UDP - Port 1194"
read -p "Choose one (1-2) : " choosemu

if [[ $choosemu == "1" ]]; then
cat > /tmp/server.conf << END
port 1194
proto tcp
dev tun
ca /etc/openvpn/ca.crt
cert /etc/openvpn/server.crt
key /etc/openvpn/server.key
dh /etc/openvpn/dh2048.pem
plugin /usr/lib/openvpn/openvpn-plugin-auth-pam.so login
verify-client-cert none
username-as-common-name
topology subnet
local $Public_IPv4
server 123.123.123.0 255.255.255.0
END
if [[ $IPV6 == "true" ]]; then
cat >> /tmp/server.conf << END
server-ipv6 fddd:1194:1194:1194::/64
push "redirect-gateway def1 ipv6 bypass-dhcp"
END
fi
cat >> /tmp/server.conf << END
ifconfig-pool-persist ipp.txt
push "dhcp-option DNS $DNS1_V4"
push "dhcp-option DNS $DNS2_V4"
push "block-outside-dns"
persist-key
persist-tun
verb 3
status /etc/openvpn/login.log
END
elif [[ $choosemu == "2" ]]; then
cat > /tmp/server.conf << END
port 1194
proto udp
dev tun
ca /etc/openvpn/ca.crt
cert /etc/openvpn/server.crt
key /etc/openvpn/server.key
dh /etc/openvpn/dh2048.pem
plugin /usr/lib/openvpn/openvpn-plugin-auth-pam.so login
verify-client-cert none
username-as-common-name
topology subnet
local $Public_IPv4
server 123.123.123.0 255.255.255.0
END
if [[ $IPV6 == "true" ]]; then
cat >> /tmp/server.conf << END
server-ipv6 fddd:1194:1194:1194::/64
push "redirect-gateway def1 ipv6 bypass-dhcp"
END
fi
cat >> /tmp/server.conf << END
ifconfig-pool-persist ipp.txt
push "dhcp-option DNS $DNS1_V4"
push "dhcp-option DNS $DNS2_V4"
push "block-outside-dns"
persist-key
persist-tun
verb 3
status /etc/openvpn/login.log
explicit-exit-notify
END
fi

# >> Install OpenVPN and configure
apt update -y; apt upgrade -y; apt dist-upgrade -y; apt autoremove -y; apt clean -y
apt install openvpn unzip openssl iptables iptables-persistent jq nano wget curl -y
mkdir -p /usr/lib/openvpn/; cp /usr/lib/x86_64-linux-gnu/openvpn/plugins/openvpn-plugin-auth-pam.so /usr/lib/openvpn/openvpn-plugin-auth-pam.so
sed -i 's/#AUTOSTART="all"/AUTOSTART="all"/g' /etc/default/openvpn

# >> Download certificate
rm -rf /etc/openvpn; mkdir -p /etc/openvpn; cd /etc/openvpn
curl -s https://raw.githubusercontent.com/wildysheverando-888/openvpn-setup/main/assets/cert.zip -o cert.zip
unzip -o cert.zip > /dev/null 2>&1

# >> Remove exist service and replace with systemd
rm -f /lib/systemd/system/openvpn*; rm -rf /etc/init.d/openvpn > /dev/null 2>&1
curl -s https://raw.githubusercontent.com/wildysheverando-888/openvpn-setup/main/assets/openvpn.service -o /etc/systemd/system/openvpn.service
curl -s https://raw.githubusercontent.com/wildysheverando-888/openvpn-setup/main/assets/openvpn-iptables.service -o /etc/systemd/system/openvpn-iptables.service

# >> Copy config file to openvpn main directory
mv /tmp/server.conf /etc/openvpn/server.conf

# >> Restarting service
systemctl daemon-reload; systemctl stop openvpn; systemctl disable openvpn; systemctl enable openvpn; systemctl start openvpn

# >> Download OpenVPN Client config
if [[ $choosemu == "1" ]]; then
curl -s https://raw.githubusercontent.com/wildysheverando-888/openvpn-setup/main/assets/client-tcp.ovpn -o /etc/openvpn/client.conf
else
curl -s https://raw.githubusercontent.com/wildysheverando-888/openvpn-setup/main/assets/client-udp.ovpn -o /etc/openvpn/client.conf
fi

# >> Adding Certificate to client configuration
cd /etc/openvpn
sed -i "s/ipnya/${Public_IPv4}/g" client.conf
echo "<ca>" >> client.conf; cat /etc/openvpn/ca.crt >> client.conf; echo '</ca>' >> client.conf

mv  client.conf /root/client.ovpn

cd /root/

echo '#!/bin/bash
# ====================================================
# Desc   : Simple bash script to add openvpn iptables
# Author : Wildy Sheverando
# Github : https://github.com/wildysheverando-888
# ====================================================

Public_IPv4=$( curl -s http://v4.ipv6-test.com/api/myip.php )
Public_IPv6=$( curl -s http://v6.ipv6-test.com/api/myip.php )

iptables -t nat -A POSTROUTING -s 123.123.123.0/24 ! -d 123.123.123.0/24 -j SNAT --to $Public_IPv4
iptables -I INPUT -p udp --dport 1194 -j ACCEPT
iptables -I FORWARD -s 123.123.123.0/24 -j ACCEPT
iptables -I FORWARD -m state --state RELATED,ESTABLISHED -j ACCEPT

if [[ $Public_IPv6 ]]; then
ip6tables -t nat -A POSTROUTING -s fddd:1194:1194:1194::/64 ! -d fddd:1194:1194:1194::/64 -j SNAT --to $Public_IPv6
ip6tables -I FORWARD -s fddd:1194:1194:1194::/64 -j ACCEPT
ip6tables -I FORWARD -m state --state RELATED,ESTABLISHED -j ACCEPT
fi' > /usr/bin/add-openvpn-iptables; chmod +x /usr/bin/add-openvpn-iptables

echo '#!/bin/bash
# ====================================================
# Desc   : Simple bash script to del openvpn iptables
# Author : Wildy Sheverando
# Github : https://github.com/wildysheverando-888
# ====================================================

Public_IPv4=$( curl -s http://v4.ipv6-test.com/api/myip.php )
Public_IPv6=$( curl -s http://v6.ipv6-test.com/api/myip.php )

iptables -t nat -D POSTROUTING -s 123.123.123.0/24 ! -d 123.123.123.0/24 -j SNAT --to $Public_IPv4
iptables -D INPUT -p udp --dport 1194 -j ACCEPT
iptables -D FORWARD -s 123.123.123.0/24 -j ACCEPT
iptables -D FORWARD -m state --state RELATED,ESTABLISHED -j ACCEPT

if [[ $Public_IPv6 ]]; then
ip6tables -t nat -D POSTROUTING -s fddd:1194:1194:1194::/64 ! -d fddd:1194:1194:1194::/64 -j SNAT --to $Public_IPv6
ip6tables -D FORWARD -s fddd:1194:1194:1194::/64 -j ACCEPT
ip6tables -D FORWARD -m state --state RELATED,ESTABLISHED -j ACCEPT
fi' > /usr/bin/del-openvpn-iptables; chmod +x /usr/bin/del-openvpn-iptables

systemctl enable openvpn-iptables
systemctl stop openvpn-iptables
systemctl start openvpn-iptables

echo 'net.ipv4.ip_forward=1
net.ipv6.conf.all.forwarding=1' > /etc/sysctl.conf

sysctl -p 

clear
echo -e "${INFO} OpenVPN Server has installed !"
echo "Type: openvpn-setup --adduser to create a user"
}

function add_user() {
clear
read -p "Username  : " user
read -p "Password  : " pass

if [[ $user == "" ]]; then
    clear; echo -e "${FAIL} Input a valid username to contitune !"; exit 1
fi
if [[ $pass == "" ]]; then
    clear; echo -e "${FAIL} Input a valid password to contitune !"; exit 1
fi

useradd -s /bin/false -M $user
echo -e "$pass\n$pass\n" | passwd $user &> /dev/null

clear
echo "Done !
============================
Username : $user
Password : $pass
============================"
}

function del_user() {
clear
read -p "Username   : " user
if [[ $user == "" ]]; then
    clear; echo -e "${FAIL} Input a valid username to contitune !"; exit 1
fi
userdel -f $user

clear
echo -e "${INFO} $user has been deleted !"
}

function _main_() {
    if [[ $mode == "--install" ]]; then
        install
    elif [[ $mode == "--adduser" ]]; then
        add_user
    elif [[ $mode == "--deluser" ]]; then
        del_user
    else
        clear
        echo -e "Command: "
        echo -e "         openvpn-setup --install : install openvpn"
        echo -e "         openvpn-setup --adduser : create new user"
        echo -e "         openvpn-setup --deluser : delete an exist user"
        exit 1
    fi
}

_main_
