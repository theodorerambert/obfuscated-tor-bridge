#!/bin/bash

### 
# Script scope:
# 1. Harden the config of a traditional Debian (VPS) install.
#	* Using the lug.mtu.edu repo for authenticated and encrypted communication (TLSv1.2, AES-GCM).
#		* https://www.ssllabs.com/ssltest/analyze.html?d=lug.mtu.edu&latest
#	* Recommendations for a more secure baseline configuration.
#	* It is highly advised that you regen SSH keys (See instructions below).
#
# 2. Setup automatic updates.
#
# 3. Optionally install and autoconfigure Tor to run as an Obfs[3|4]proxy Bridge.
#
#
# Generate & Verify a host's RSA keypair
#	ssh-keygen -t rsa -b 8192 -f /etc/ssh/ssh_host_rsa_key
#	ssh-keygen -l -f /etc/ssh/ssh_host_rsa_key.pub
#
# Generate & Verify a host's ed25519 keypair
#	ssh-keygen -t ed25519 -f /etc/ssh/ssh_host_ed25519_key
#	ssh-keygen -l -f /etc/ssh/ssh_host_ed25519_key.pub
#
# See Readme for variables
# 
# Authors: https://github.com/theodorerambert/obfuscated-tor-bridge/graphs/contributors
# Project site: https://github.com/theodorerambert/obfuscated-tor-bridge
#
# The MIT License (MIT)
# Copyright (c) 2015 Theodore Rambert
#
# Revised 2/18/2016
#
###


DEBIAN_VERSION=jessie
PREFIX=0000
#ALLOWUSERS="AllowUsers root@*.*.*.*"
#SSH_PUB_KEY="ssh-rsa ..."
SSH_PORT=22
NICKNAME=`echo $PREFIX$HOSTNAME|sed 's/-//g'`


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

	apt-get -y install apt-transport-https unattended-upgrades vim vnstat

	return 0
}

server_install_tor_packages() {

	echo "##################################################"
	echo "Add Tor repository"

	cat <<-EOF >> /etc/apt/sources.list
	deb https://deb.torproject.org/torproject.org $DEBIAN_VERSION main
	deb https://deb.torproject.org/torproject.org obfs4proxy main
EOF

	echo "##################################################"
	echo "Retrieve Tor GPG Keys & Install Tor"

	gpg --keyserver keys.gnupg.net --recv 886DDD89
	gpg --export A3C4F0F979CAA22CDBA8F512EE8CBC9E886DDD89 | apt-key add -
	
	server_update

	apt-get -y install deb.torproject.org-keyring tor obfs4proxy

	echo "##################################################"
	echo "Configuring Tor"

	cp -a /etc/tor/torrc /etc/tor/torrc.orig

	cat <<-EOF > /etc/tor/torrc
	SocksPort 0
	ORPort 443
	BridgeRelay 1
	Exitpolicy reject *:*
	Nickname $NICKNAME
	ServerTransportPlugin obfs3,obfs4 exec /usr/bin/obfs4proxy
	ExtORPort auto
	BandwidthRate 512 KB
	BandwidthBurst 1024 KB
EOF


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
	# Debian packages for $DEBIAN_VERSION
	deb http://lug.mtu.edu/debian/ $DEBIAN_VERSION main
	deb http://lug.mtu.edu/debian/ $DEBIAN_VERSION-updates main
	# Security updates for $DEBIAN_VERSION
	deb http://security.debian.org/ $DEBIAN_VERSION/updates main
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
	# Debian packages for $DEBIAN_VERSION
	deb https://lug.mtu.edu/debian/ $DEBIAN_VERSION main
	deb https://lug.mtu.edu/debian/ $DEBIAN_VERSION-updates main
	# Security updates for $DEBIAN_VERSION
	deb http://security.debian.org/ $DEBIAN_VERSION/updates main
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
	echo "Permissions Section"

	echo "Change shells"
	chsh -s /usr/sbin/nologin games
	chsh -s /usr/sbin/nologin games
	chsh -s /usr/sbin/nologin nobody
	chsh -s /usr/sbin/nologin proxy
	chsh -s /usr/sbin/nologin www-data
	chsh -s /usr/sbin/nologin libuuid
	chsh -s /usr/sbin/nologin gnats
	chsh -s /usr/sbin/nologin irc
	chsh -s /usr/sbin/nologin uucp
	chsh -s /usr/sbin/nologin mail
	chsh -s /usr/sbin/nologin lp
	chsh -s /usr/sbin/nologin man
	chsh -s /usr/sbin/nologin sync
	chsh -s /usr/sbin/nologin sys
	chsh -s /usr/sbin/nologin bin
	chsh -s /usr/sbin/nologin news
	chsh -s /usr/sbin/nologin list
	chsh -s /usr/sbin/nologin backup
	chsh -s /usr/sbin/nologin daemon

	echo "Chmod common commands"

	chmod 0700 /usr/bin/vi
	chmod 0700 /usr/bin/yes
	chmod 0700 /bin/ping
	chmod 0700 /usr/bin/apt-get
	chmod 0700 /sbin/ifconfig
	chmod 0700 /sbin/ifup
	chmod 0700 /sbin/ifdown
	chmod 0700 /usr/sbin/service
	chmod 0400 /usr/bin/ssh
	chmod 0500 /usr/bin/sftp
	chmod 0400 /bin/ypdomainname
	chmod 0400 /usr/bin/scp
	chmod 0500 /usr/bin/wget
	chmod 0400 /usr/sbin/rmt-tar
	chmod 0500 /usr/bin/wall

	echo "Special File Permissions"

	chmod 0400 /etc/shadow
	chmod 0700 /etc/crontab
	chmod 0400 /etc/ssh/*

	return 0
}

config_misc_ssh() {

	echo "##################################################"
	echo "Adding SSH Banner"

	cat <<-EOF > /etc/issue.net
	*************************************************************
	This service is restricted to authorized users only.
	All activities on this system are logged. Unauthorized
	access will be investigated and reported to law enforcement.
	*************************************************************
EOF

	echo "##################################################"
	echo "Remove motd"
	rm -f /etc/motd


	echo "##################################################"
	echo "SSH Configuration"
	cp /etc/ssh/sshd_config /etc/ssh/sshd_config.orig

	cat <<-EOF > /etc/ssh/sshd_config
	#IP, Port, Crypto, Logging Section:
	Port $SSH_PORT
	AddressFamily inet

	#ListenAddress 0.0.0.0
	Protocol 2

	#HostKeys for protocol version 2
	#HostKey /etc/ssh/ssh_host_ed25519_key
	HostKey /etc/ssh/ssh_host_rsa_key

	#Privilege Separation is turned on for security
	UsePrivilegeSeparation yes

	#Logging
	SyslogFacility AUTH
	LogLevel INFO

	#Ciphers
	#Ciphers chacha20-poly1305@openssh.com,aes128-gcm@openssh.com,aes128-ctr
	Ciphers aes128-ctr,aes256-ctr

	#MACs
	#MACs hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com,hmac-sha2-512,hmac-sha2-256
	MACs hmac-sha2-512,hmac-sha2-256

	#Key Exchange Algorithms
	#KexAlgorithms curve25519-sha256@libssh.org,ecdh-sha2-nistp521
	KexAlgorithms ecdh-sha2-nistp521,ecdh-sha2-nistp384


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
	#Number of authentications attempts per connection
	MaxAuthTries 1
	#Number of open sessions per connection
	MaxSessions 1

	#(start:rate:full)
	MaxStartups 1:100:1

	#Password Section
	PermitEmptyPasswords no

	#Change to yes to enable challenge-response passwords (beware issues with some PAM modules and threads)
	ChallengeResponseAuthentication no

	#Change to no to disable tunneled clear text passwords
	PasswordAuthentication yes


	#Key Authentication Section:
	#Version 1 only
	RSAAuthentication no
	#Version 2
	PubkeyAuthentication yes

	#Don't read the user's ~/.rhosts and ~/.shosts files
	IgnoreRhosts yes
	#For this to work you will also need host keys in /etc/ssh_known_hosts(v1 only)
	RhostsRSAAuthentication no
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
	#Command never used for remote sessions
	UseLogin no

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
	echo "Restarting SSH"
	service ssh restart

	return 0
}

config_misc_unattended_upgrades() {

	echo "##################################################"
	echo "Configuring Unattended Upgrades"
	cat <<-EOF > /etc/apt/apt.conf.d/02periodic
	APT::Periodic::Download-Upgradeable-Packages "1";
	APT::Periodic::Unattended-Upgrade "1";
	APT::Periodic::Update-Package-Lists "1";
    APT::Periodic::Enable "1";
EOF

        cat <<-EOF > /etc/apt/apt.conf.d/00https
        Acquire::https::Verify-Host "true";
        Acquire::https::SslForceVersion "TLSv1.2";
EOF

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
	echo "Removing Apache, Bind, Sendmail & Samba to reduce attack surface"

	apt-get -y remove apache2 apache2-doc apache2-mpm-prefork apache2-utils apache2.2-bin apache2.2-common \
    bind9 bind9-host bind9utils libbind9-80 rpcbind samba samba-common

	return 0
}

base_install() {

	echo "##################################################"
	echo "Base Install Starting"

	config_mandatory
	config_add_repos
	server_update
	server_install_base_packages
	config_add_repos_https
	server_update
	misc_remove_extras
	config_misc_ipv6
	config_misc_permissions
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
