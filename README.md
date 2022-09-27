# openvpn-setup
Simple bash script to setup OpenVPN Server

# Setup
curl -s https://raw.githubusercontent.com/wildysheverando-888/openvpn-setup/main/openvpn-setup.sh -o /usr/bin/openvpn-setup; chmod +x /usr/bin/openvpn-setup

# Installation
openvpn-setup --install

# Create User
openvpn-setup --adduser

# Delete User
openvpn-setup --deluser
