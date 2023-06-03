#!/bin/bash

### 
# Script purpose:
# 1. Setup and configure Linux with minor changes, including 910GB monthly traffic limit
#
# 2. Setup automatic updates
#
# 3. Optionally install and auto configure Tor to run as an Obfs4proxy Bridge
#
#
# Generate & Verify a host's ed25519 keypair
#       ssh-keygen -t ed25519 -f /etc/ssh/ssh_host_ed25519_key
#       ssh-keygen -l -f /etc/ssh/ssh_host_ed25519_key.pub
#
## See Readme for variables
# 
# Authors: https://github.com/theodorerambert/obfuscated-tor-bridge/graphs/contributors
# Project site: https://github.com/theodorerambert/obfuscated-tor-bridge
#
# The MIT License (MIT)
# Copyright (c) 2017 Theodore Rambert
#
# Revised 6/2/2023
#
###


LINUX_VERSION=bullseye
PREFIX=00000
ALLOWUSERS="AllowUsers root@*.*.*.*"
SSH_PUB_KEY="ssh-ed25519 ..."
SSH_PORT=922
NICKNAME=`echo $PREFIX$HOSTNAME|sed 's/-//g'`
PKGS_BASE="apt-transport-https unattended-upgrades vnstat"

PKGS_TO_RM="apache* bind9* samba*"
PKGS_TOR="tor deb.torproject.org-keyring obfs4proxy"


server_update() {

    echo "##################################################"
    echo "Update Server"

    apt-get update
    apt-get -y upgrade

    return 0
}

server_install_base_packages() {

    echo "##################################################"
    echo "Install base software"

    server_update

    apt-get -y install $PKGS_BASE

    return 0
}

server_install_tor_packages() {

    echo "##################################################"
    echo "Add Tor repository"

    cat <<-EOF >> /etc/apt/sources.list.d/tor.list
deb [signed-by=/usr/share/keyrings/tor-archive-keyring.gpg] https://deb.torproject.org/torproject.org $LINUX_VERSION main
deb-src [signed-by=/usr/share/keyrings/tor-archive-keyring.gpg] https://deb.torproject.org/torproject.org $LINUX_VERSION main
EOF

    echo "##################################################"
    echo "Enable backports"

    cat <<-EOF >> /etc/apt/sources.list
deb https://deb.debian.org/debian $LINUX_VERSION-backports main
deb-src https://deb.debian.org/debian $LINUX_VERSION-backports main
EOF

    echo "##################################################"
    echo "Retrieve Tor GPG Keys & Install Tor"

    wget -qO- https://deb.torproject.org/torproject.org/A3C4F0F979CAA22CDBA8F512EE8CBC9E886DDD89.asc | gpg --dearmor | tee /usr/share/keyrings/tor-archive-keyring.gpg >/dev/null

    server_update

    apt-get -y install $PKGS_TOR

    #Install obfs4proxy from backports
    apt install -t bullseye-backports obfs4proxy

    echo "##################################################"
    echo "Configuring Tor"

    cp -a /etc/tor/torrc /etc/tor/torrc.orig

    cat <<-EOF > /etc/tor/torrc
BridgeRelay 1
ORPort 80 IPv4Only
ServerTransportPlugin obfs4 exec /usr/bin/obfs4proxy
ServerTransportListenAddr obfs4 0.0.0.0:443
ExtORPort auto
Exitpolicy reject *:*
Nickname $NICKNAME

#AccountingStart week 1 12:00
#AccountingMax 240 GBytes
EOF

    #Additional permissions for Tor below port 1024
    setcap cap_net_bind_service=+ep /usr/bin/obfs4proxy

    echo "##################################################"
    echo "Additional privileges for Tor in systemd"

    sed -i 's/NoNewPrivileges=yes/NoNewPrivileges=no/' /lib/systemd/system/tor@default.service
    sed -i 's/NoNewPrivileges=yes/NoNewPrivileges=no/' /lib/systemd/system/tor@.service

    systemctl daemon-reload

    echo "##################################################"
    echo "Restarting Tor"
    service tor restart

    return 0
}

config_add_repos() {

    echo "##################################################"
    echo "Modifying Repository Sources"

    cp /etc/apt/sources.list /etc/apt/sources.list.orig

    cat <<-EOF > /etc/apt/sources.list
# Debian packages for $LINUX_VERSION
deb $APT_MIRROR_HTTP $LINUX_VERSION main
deb $APT_MIRROR_HTTP $LINUX_VERSION-updates main
# Security updates for $LINUX_VERSION
deb http://security.debian.org/ $LINUX_VERSION/updates main
EOF

    cat <<-EOF > /etc/apt/apt.conf.d/00aptitude
#Ignore translations
Acquire::Languages "none";
EOF

    return 0
}

config_add_repos_https() {

    echo "##################################################"
    echo "Modifying Repository Sources"

    cp /etc/apt/sources.list /etc/apt/sources.list.orig

    cat <<-EOF > /etc/apt/sources.list
    # Debian packages for $LINUX_VERSION
    deb $APT_MIRROR_HTTPS $LINUX_VERSION main
    deb $APT_MIRROR_HTTPS $LINUX_VERSION-updates main
    # Security updates for $LINUX_VERSION
    deb http://security.debian.org/ $LINUX_VERSION/updates main
EOF

    return 0
}

config_mandatory() {

    echo "##################################################"
    echo "Fixing locale issue"

    cat <<-EOF >> /etc/locale.gen
en_US.UTF-8 UTF-8
EOF

    locale-gen

    echo "##################################################"
    echo "Setting Timezone"

    cat <<-EOF > /etc/timezone
America/New_York
EOF

    timedatectl set-timezone America/New_York

    return 0
}

config_misc_bandwidth() {

    echo "##################################################"
    echo "Adding bandwidth check to cron"

    cat <<-'EOF' > /root/bwcheck.sh
[ $(vnstat --oneline | cut -d \; -f 11 | sed '/[kKM]iB/s,.*,0,;s,\..*,,') -gt 910 ] && poweroff
EOF

    cat <<-EOF >> /etc/crontab
*/5 * * * * root /root/bwcheck.sh
EOF

    return 0
}
  
config_misc_ipv6() {

    echo "##################################################"
    echo "Disable IPv6"

    cat <<-EOF > /etc/sysctl.d/disableipv6.conf
net.ipv6.conf.all.disable_ipv6=1
EOF

    return 0
}

config_misc_permissions() {

    echo "##################################################"
    echo "Specific File Permissions"

    chmod 0400 /etc/shadow
    chmod 0700 /etc/crontab
    chmod 0400 /etc/ssh/*

    return 0
}
config_misc_postfix() {

    echo "##################################################"
    echo "Bind Postfix to localhost"

    sed -i 's/inet_interfaces = all/inet_interfaces = 127.0.0.1/g' /etc/postfix/main.cf

    echo "##################################################"
    echo "Restart Postfix"
    service postfix restart

    return 0
}

config_misc_ssh() {

    echo "##################################################"
    echo "Adding SSH Banner"

    cat <<-EOF > /etc/issue.net
*************************************************************
This service is restricted to authorized users only.
*************************************************************
EOF

    echo "##################################################"
    echo "Remove motd"
    rm -f /etc/motd


    echo "##################################################"
    echo "SSH Configuration"
    cp /etc/ssh/sshd_config /etc/ssh/sshd_config.orig

    cat <<-EOF > /etc/ssh/sshd_config
#Base Configuration Section:
Port $SSH_PORT
AddressFamily inet

#ListenAddress 0.0.0.0
Protocol 2

#HostKeys for protocol version 2
HostKey /etc/ssh/ssh_host_ed25519_key

#Logging
SyslogFacility AUTH
LogLevel INFO

#Ciphers
Ciphers chacha20-poly1305@openssh.com

#MACs
MACs hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com

#Key Exchange Algorithms
KexAlgorithms curve25519-sha256@libssh.org

#Authentication Section:
#Enable PAM authentication (non key authentication)
UsePAM no
#The server disconnects after this time if the user has not successfully logged in.
LoginGraceTime 120
#Permits root login
PermitRootLogin yes
#Permits root login only with a key
PermitRootLogin without-password

#Checks ownership of the user's files and home directory before accepting login.
StrictModes yes

#Allows only these users to connect
$ALLOWUSERS
#Number of authentications attempts per connection, increase to allow trying multiple key types
MaxAuthTries 3
#Number of open sessions per connection
MaxSessions 1

#(start:rate:full)
MaxStartups 1:100:1

#Password Section
PermitEmptyPasswords no

#Change to yes to enable challenge-response passwords (beware issues with some PAM modules and threads)
ChallengeResponseAuthentication no

#Change to no to disable tunneled clear text passwords
PasswordAuthentication no

#Key Authentication Section:
#Version 2
PubkeyAuthentication yes

#Don't read the user's ~/.rhosts and ~/.shosts files
IgnoreRhosts yes
#For this to work you will also need host keys in /etc/ssh_known_hosts(v1 only)
#RhostsRSAAuthentication no
#Similar for protocol version 2
HostbasedAuthentication no
#Uncomment if you don't trust ~/.ssh/known_hosts for RhostsRSAAuthentication
IgnoreUserKnownHosts yes

#Other Authentication Options:
KerberosAuthentication no
GSSAPIAuthentication no

#Further Restrictions Section:
#Timeout interval, requests data from client
ClientAliveInterval 5
ClientAliveCountMax 3
    
X11Forwarding no
AllowAgentForwarding no
PrintMotd no
PrintLastLog yes
#Device forwarding
PermitTunnel no

#Compression
Compression no

#chroot directory
ChrootDirectory none

#send TCP keepalive messages to the other side (spoofable)
TCPKeepAlive no

Banner /etc/issue.net

Subsystem sftp /usr/lib/openssh/sftp-server
EOF

    echo "##################################################"
    echo "Adding Pub Key"

    mkdir -p ~/.ssh

    cat <<-EOF >> ~/.ssh/authorized_keys
$SSH_PUB_KEY
EOF

    echo "##################################################"
    echo "Removing other keys"
    rm -rf /etc/ssh/ssh_host_*dsa*
    rm -rf /etc/ssh/ssh_host_r*
    rm -rf /etc/ssh/ssh_host_key*

    echo "##################################################"
    echo "Restarting SSH"
    service ssh restart

    return 0
}

config_misc_unattended_upgrades() {

    echo "##################################################"
    echo "Configuring Unattended Upgrades"
    cat <<-EOF > /etc/apt/apt.conf.d/10periodic
APT::Periodic::Download-Upgradeable-Packages "1";
APT::Periodic::Unattended-Upgrade "1";
APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Enable "1";
EOF

    #Create apt file if it doesn't exist
    touch /etc/cron.daily/apt
    chmod +x /etc/cron.daily/apt

    return 0
}

misc_pull_repos() {

    echo "##################################################"
    echo "Refresh Repos"

    apt-get update

    return 0
}

misc_remove_extras() {

    echo "##################################################"
    echo "Removing Apache, Bind, Sendmail & Samba"

    apt-get -y purge $PKGS_TO_RM

    return 0
}

base_install() {

    echo "##################################################"
    echo "Base Install Starting"

    echo "Disabling ufw"
    ufw disable

    config_mandatory

    #config_add_repos
    server_update
    server_install_base_packages
    #config_add_repos_https
    server_update
    misc_remove_extras
    config_misc_bandwidth
    config_misc_ipv6
    config_misc_permissions
    #config_misc_postfix
    config_misc_ssh
    config_misc_unattended_upgrades

    echo "##################################################"
    echo "Base Install Complete"

    return 0
}

tor_install() {

    echo "##################################################"
    echo "Tor Install Starting"

    server_install_tor_packages

    echo "##################################################"
    echo "Tor Install Complete"

    return 0
}


echo "Choose 1 for the Base install, 2 for Tor or 3 for Both"
read -p "Select an option [1-3]: " OPTION
    case $OPTION in
    1)
    base_install
        echo "Base is installed"
        exit
    ;;
    2)
        tor_install
        echo "Tor is installed"
        exit
    ;;
    3)
        base_install
        tor_install
        echo "Both base & Tor are installed"
        exit
    ;;
    esac
