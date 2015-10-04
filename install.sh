#Summary
#Installs & Configures an obfuscated Tor Bridge
#Sets up automatic updates
#Misc Config settings for server
#MIT License


#Before or after running the script
#Regen SSH Keys

#rm -rf /etc/ssh/ssh_host*
#ssh-keygen -t rsa -b 8192 -f /etc/ssh/ssh_host_rsa_key
#ssh-keygen -l -f /etc/ssh/ssh_host_rsa_key.pub

#Fancy Twisted Edwards curve
#ssh-keygen -t ed25519 -f /etc/ssh/ssh_host_ed25519_key
#ssh-keygen -l -f /etc/ssh/ssh_host_ed25519_key.pub


#service ssh start
#bash -n script.sh

#Variables

#Debian Version
VERSION=jessie

PREFIX=0000
#ALLOWUSERS="AllowUsers root@*.*.*.*"

#SSH_PUB_KEY="ssh-rsa ..."

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
	#apt-get -y install apt-transport-https netselect-apt unattended-upgrades vim vnstat

	return 0
}

server_install_tor_packages() {

	echo "##################################################"
	echo "Add Tor repository"

	{
		echo "deb https://deb.torproject.org/torproject.org $VERSION main"
		echo "deb https://deb.torproject.org/torproject.org obfs4proxy main"
	} >> /etc/apt/sources.list

	echo "##################################################"
	echo "Retrieve Tor GPG Keys & Install Tor"

	gpg --keyserver keys.gnupg.net --recv 886DDD89
	gpg --export A3C4F0F979CAA22CDBA8F512EE8CBC9E886DDD89 | apt-key add -
	
	server_update

	apt-get -y install deb.torproject.org-keyring tor obfs4proxy

	echo "##################################################"
	echo "Configuring Tor"

	#Generate Nickname
	nickname=`echo $PREFIX$HOSTNAME|sed 's/-//g'`

	cp -a /etc/tor/torrc /etc/tor/torrc.orig

	{
		echo "SocksPort 0"
		echo "ORPort 443"
		echo "BridgeRelay 1"
		echo "Exitpolicy reject *:*"
		echo "Nickname $nickname"
		echo "ServerTransportPlugin obfs3,obfs4 exec /usr/bin/obfs4proxy"
		echo "ExtORPort auto"
		echo "BandwidthRate 512 KB"
		echo "BandwidthBurst 1024 KB"
	} > /etc/tor/torrc

	echo "##################################################"
	echo "Restarting Tor"
	service tor restart

	return 0
}

config_add_repos() {

	echo "##################################################"
	echo "Modifying Repository Sources"

	cp /etc/apt/sources.list /etc/apt/sources.list.orig

	{
		echo "# Debian packages for $VERSION"
		echo "deb http://lug.mtu.edu/debian/ $VERSION main"
		echo "deb http://lug.mtu.edu/debian/ $VERSION-updates main"
		echo "# Security updates for $VERSION"
		echo "deb http://security.debian.org/ $VERSION/updates main"
	} > /etc/apt/sources.list

	#Ignore translations
	{

		echo "Acquire::Languages \"none\";"
	} > /etc/apt/apt.conf.d/00aptitude
	return 0
}

config_add_repos_https() {

	echo "##################################################"
	echo "Modifying Repository Sources"

	cp /etc/apt/sources.list /etc/apt/sources.list.orig

	{
		echo "# Debian packages for $VERSION"
		echo "deb https://lug.mtu.edu/debian/ $VERSION main"
		echo "deb https://lug.mtu.edu/debian/ $VERSION-updates main"
		echo "# Security updates for $VERSION"
		echo "deb http://security.debian.org/ $VERSION/updates main"
	} > /etc/apt/sources.list

	return 0
}

config_mandatory() {

	#echo "##################################################"
	#echo "Fixing locale issue"

	echo "en_US.UTF-8 UTF-8" >> /etc/locale.gen
	locale-gen

	echo "##################################################"
	echo "Setting Timezone"
	echo "America/New_York" > /etc/timezone

	return 0
}


config_misc_ipv6() {

	echo "##################################################"
	echo "Disable IPv6"
	echo "net.ipv6.conf.all.disable_ipv6=1" > /etc/sysctl.d/disableipv6.conf

	return 0
}

config_misc_netselect_apt() {

	echo "##################################################"
	echo "Selecting the Best Repository Sources"

	cp /etc/apt/sources.list /etc/apt/sources.list.bak
	netselect-apt -c US -o /etc/apt/sources.list
	sed -i 's/stable/$VERSION/g' /etc/apt/sources.list

	server_update

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

	{
		echo "*************************************************************"
		echo "This service is restricted to authorized users only."
		echo "All activities on this system are logged. Unauthorized"
		echo "access will be investigated and reported to law enforcement."
		echo "*************************************************************"
	} > /etc/issue.net

	echo "##################################################"
	echo "Remove motd"
	rm -f /etc/motd


	echo "##################################################"
	echo "SSH Configuration"
	cp /etc/ssh/sshd_config /etc/ssh/sshd_config.orig

	echo "" > /etc/ssh/sshd_config


echo "#IP, Port, Key, Logging Section:
        Port 922
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
        KexAlgorithms ecdh-sha2-nistp521,ecdh-sha2-nistp384,ecdh-sha2-nistp256

#Authentication Section:
#Enable PAM authentication (non key authentication)
        UsePAM no
#The server disconnects after this time if the user has not successfully logged in. 
        LoginGraceTime 120
#Permits root login
        PermitRootLogin yes
#checks ownership of the user's files and home directory before accepting login.
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

# Change to yes to enable challenge-response passwords (beware issues with some PAM modules and threads)
        ChallengeResponseAuthentication no

# Change to no to disable tunneled clear text passwords
        PasswordAuthentication yes


#Key Authentication Section:
        #Version 1 only
        RSAAuthentication no
        #Version 2
        PubkeyAuthentication yes

# Don't read the user's ~/.rhosts and ~/.shosts files
        IgnoreRhosts yes
# For this to work you will also need host keys in /etc/ssh_known_hosts(v1 only)
        RhostsRSAAuthentication no
# similar for protocol version 2
        HostbasedAuthentication no
# Uncomment if you don't trust ~/.ssh/known_hosts for RhostsRSAAuthentication
        IgnoreUserKnownHosts yes


#Other Authentication Options:
        KerberosAuthentication no
        GSSAPIAuthentication no

#Timeout interval, requests data from client
        ClientAliveInterval 5
        ClientAliveCountMax 3


#Further Restrictions Section:
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

        Subsystem sftp /usr/lib/openssh/sftp-server" > /etc/ssh/sshd_config


	echo "##################################################"
	echo "Adding Pub Key"
	mkdir -p ~/.ssh
	echo $SSH_PUB_KEY > ~/.ssh/authorized_keys


	echo "##################################################"
	echo "Restarting SSH"
	service ssh restart

	return 0
}

config_misc_unattended_upgrades() {

	echo "##################################################"
	echo "Configuring Unattended Upgrades"

	{
		echo "APT::Periodic::Download-Upgradeable-Packages \"1\";"
		echo "APT::Periodic::Unattended-Upgrade \"1\";"
		echo "APT::Periodic::Update-Package-Lists \"1\";"
	} > /etc/apt/apt.conf.d/10periodic

	{
		echo "Unattended-Upgrade::Origins-Pattern {"
		echo "        \"o=Debian,n=$VERSION\";"
		echo "        \"o=Debian,n=$VERSION-updates\";"
		echo "        \"o=Debian,n=$VERSION,l=Debian-Security\";"
		echo "};"
	} > /etc/apt/apt.conf.d/50unattended-upgrades

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
	echo "Removing Apache, Bind & Samba"

	apt-get -y remove apache2 apache2-doc apache2-mpm-prefork apache2-utils apache2.2-bin apache2.2-common bind9 bind9-host bind9utils libbind9-80 rpcbind samba samba-common sendmail sendmail-base sendmail-bin sendmail-cf sendmail-doc

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
	#config_misc_netselect_apt
	config_misc_permissions
	config_misc_ssh
	config_misc_unattended_upgrades

	echo "##################################################"
	echo "Base Install Complete (Ideally)"

	return 0
}

tor_install() {

	echo "##################################################"
	echo "Tor Install Starting"

	server_install_tor_packages

	echo "##################################################"
	echo "Tor Install Complete (Ideally)"

	return 0
}

echo "##################################################"
echo "Hellos"

echo "Choose 1 for a Base, 2 for Tor or 3 for Both"
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