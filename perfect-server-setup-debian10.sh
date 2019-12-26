#!/bin/bash

apt update && apt upgrade -y
apt install -y ssh openssh-server nano vim-nox ntp postfix postfix-mysql postfix-doc mariadb-client mariadb-server openssl getmail4 rkhunter binutils dovecot-imapd dovecot-pop3d dovecot-mysql dovecot-sieve dovecot-lmtpd sudo amavisd-new spamassassin clamav clamav-daemon unzip bzip2 arj nomarch lzop cabextract p7zip p7zip-full unrar lrzip apt-listchanges libnet-ldap-perl libauthen-sasl-perl clamav-docs daemon libio-string-perl libio-socket-ssl-perl libnet-ident-perl zip libnet-dns-perl libdbd-mysql-perl postgrey apache2 apache2-doc apache2-utils libapache2-mod-php php7.3 php7.3-common php7.3-gd php7.3-mysql php7.3-imap php7.3-cli php7.3-cgi libapache2-mod-fcgid apache2-suexec-pristine php-pear mcrypt  imagemagick libruby libapache2-mod-python php7.3-curl php7.3-intl php7.3-pspell php7.3-recode php7.3-sqlite3 php7.3-tidy php7.3-xmlrpc php7.3-xsl memcached php-memcache php-imagick php-gettext php7.3-zip php7.3-mbstring memcached libapache2-mod-passenger php7.3-soap php7.3-fpm php7.3-opcache php-apcu mailman pure-ftpd-common pure-ftpd-mysql quota quotatool bind9 dnsutils haveged webalizer awstats geoip-database libclass-dbi-mysql-perl libtimedate-perl build-essential autoconf automake libtool flex bison debhelper fail2ban ufw 

echo "mysql soft nofile 65535" >> /etc/security/limits.conf
echo "mysql hard nofile 65535" >> /etc/security/limits.conf

mkdir -p /etc/systemd/system/mysql.service.d/
echo "[Service]" > /etc/systemd/system/mysql.service.d/limits.conf
echo "LimitNOFILE=infinity" >> /etc/systemd/system/mysql.service.d/limits.conf

mysql_secure_installation

systemctl daemon-reload
systemctl restart mariadb
systemctl stop spamassassin
systemctl disable spamassassin

netstat -tap | grep mysql
sleep 5

a2enmod suexec rewrite ssl actions include dav_fs dav auth_digest cgi headers actions proxy_fcgi alias

echo "<IfModule mod_headers.c>" > /etc/apache2/conf-available/httpoxy.conf
echo "    RequestHeader unset Proxy early" >> /etc/apache2/conf-available/httpoxy.conf
echo "</IfModule>" >> /etc/apache2/conf-available/httpoxy.conf

a2enconf httpoxy
systemctl restart apache2

cd /usr/local/bin
wget https://dl.eff.org/certbot-auto
chmod a+x certbot-auto
./certbot-auto --install-only

newlist mailman
ln -s /etc/mailman/apache.conf /etc/apache2/conf-enabled/mailman.conf
