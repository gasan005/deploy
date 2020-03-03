#!/bin/bash

mkdir ~/backup

echo "Enter your domain name."

read servername

echo "Yor domain name - $servername"

echo "$servername" > /etc/hostname



apt-get update
apt-get -y upgrade
apt-get install -y mc net-tools nginx fcgiwrap ocserv letsencrypt rsync apache2-utils

cp /etc/ocserv/ocserv.conf ~/backup/ocserv.conf
cp /etc/nginx/nginx.conf ~/backup/nginx.conf
cp /etc/nginx/fastcgi_params ~/backup/fastcgi_params
cp /etc/sysctl.conf ~/backup/sysctl.conf
cat fastcgi_params > /etc/nginx/fastcgi_params

echo "net.ipv4.ip_forward=1" >> /etc/sysctl.conf
echo "net.ipv6.conf.all.forwarding=1" >> /etc/sysctl.conf

cat > /etc/ocserv/ocserv.conf << EOL

auth = "plain[/etc/ocserv/ocpasswd]"
# TCP and UDP port number
tcp-port = 443
udp-port = 443
run-as-user = nobody
run-as-group = daemon
socket-file = /var/run/ocserv-socket
server-cert = /etc/letsencrypt/live/$servername/fullchain.pem
server-key = /etc/letsencrypt/live/$servername/privkey.pem
ca-cert = /etc/ssl/certs/ssl-cert-snakeoil.pem
isolate-workers = true
max-clients = 16
max-same-clients = 1
keepalive = 32400
dpd = 90
mobile-dpd = 1800
try-mtu-discovery = true
cert-user-oid = 0.9.2342.19200300.100.1.1
compression = true
tls-priorities = "NORMAL:%SERVER_PRECEDENCE:%COMPAT:-VERS-SSL3.0:-VERS-TLS1.1:-VERS-TLS1.2"
#tls-priorities = "NORMAL:%SERVER_PRECEDENCE:%COMPAT:-VERS-SSL3.0"
auth-timeout = 240
min-reauth-time = 3
max-ban-score = 50
ban-reset-time = 300
cookie-timeout = 300
deny-roaming = false
rekey-time = 172800
rekey-method = ssl
use-utmp = true
use-occtl = true
pid-file = /var/run/ocserv.pid
device = vpns
predictable-ips = false
default-domain = vpn.$servername
ipv4-network = 10.1.0.0/24
# The IPv6 subnet that leases will be given from.
ipv6-network = fef4:db8:1000:1001::/64 
dns = 8.8.8.8
dns = 7.7.7.7
ping-leases = false
cisco-client-compat = true
dtls-legacy = true

EOL



iptables -t nat -A POSTROUTING -s 10.1.0.0/24 -o eth0 -m policy --dir out --pol ipsec -j ACCEPT
iptables -t nat -A POSTROUTING -s 10.1.0.0/24 -o eth0 -j MASQUERADE

iptables-save > /etc/iptables.rules

echo 'pre-up iptables-restore < /etc/iptables.rules' >>  /etc/network/interfaces.d/eth0

systemctl stop nginx


rm -f /etc/nginx/sites-enabled/default

cat > /etc/nginx/sites-enabled/fcgiwrap << EOL
server {

    server_name         $servername;
    ssl_certificate     /etc/letsencrypt/live/$servername/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/$servername/privkey.pem;
  listen 8300 ssl;
  error_log /var/log/nginx/8300-error.log;
  access_log /var/log/nginx/8300.log combined;

  proxy_connect_timeout       600;
  proxy_send_timeout          600;
  proxy_read_timeout          600;
  send_timeout                600;

location /cgi-bin/ {
auth_basic "Administrator’s Area";
auth_basic_user_file /etc/apache2/.htpasswd;
gzip off;

  root  /var/www;

fastcgi_buffer_size 10240k;
fastcgi_buffers 4 10240k;
  fastcgi_pass  unix:/var/run/fcgiwrap.socket;

  include /etc/nginx/fastcgi_params;

  fastcgi_param SCRIPT_FILENAME  /var/www$fastcgi_script_name;
        }
}

EOL

letsencrypt certonly --standalone --email root@$servername -d $servername --rsa-key-size 4096

echo "Enter Username and password for web login (WEB)"

echo " Username:"
read user
echo " Password:"
read pass
mkdir /etc/apache2	
htpasswd -b -c /etc/apache2/.htpasswd $user $pass
chown www-data:www-data  /etc/ocserv/
mkdir /var/www/cgi-bin/
cp index /var/www/cgi-bin/index
cp edit /var/www/cgi-bin/edit
chown www-data:www-data -R  /var/www/cgi-bin

service ocserv restart
reboot
