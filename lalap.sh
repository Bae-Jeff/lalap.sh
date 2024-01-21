#!/bin/bash
# Linux + Apache + Laravel + Postgresql
pache_location=/home


_red(){
	printf '\033[1;31;31m%b\033[0m' "$1"
	printf "\n"
}

_green(){
	printf '\033[1;31;32m%b\033[0m' "$1"
}

_yellow(){
	printf '\033[1;31;33m%b\033[0m' "$1"
	printf "\n"
}
_printargs(){
	printf -- "%s" "[$(date)] "
	printf -- "%s" "$1"
	printf "\n"
}

_info(){
	_printargs "$@"
}

_error() {
	printf -- "%s" "[$(date)] "
	_red "$1"
	exit 1
}

install_check_acme(){
	if [ -s "/etc/httpd/acme.sh/acme.sh" ]; then
		_info "/etc/httpd/acme.sh/acme.sh [found]"
	else
		wget --no-check-certificate -qO- https://github.com/acmesh-official/acme.sh/tarball/master | tar xz
		cd acmesh-* || _error "Error: Download acme.sh failed, Please check it and try again"
		./acme.sh --install --log --home /etc/httpd/acme.sh --certhome /home/${domain}_ssl
		cd .. && rm -rf acmesh-*
		sed -i 's/cat "\$CERT_PATH"$/#cat "\$CERT_PATH"/g' /etc/httpd/acme.sh/acme.sh
		cat > /etc/httpd/acme.sh/upgrade.sh<<EOF
#!/bin/bash
. /etc/httpd/acme.sh/acme.sh.env
/etc/httpd/acme.sh/acme.sh --upgrade
sed -i 's/cat "\\\$CERT_PATH"\$/#cat "\\\$CERT_PATH"/g' /etc/httpd/acme.sh/acme.sh
EOF
		chmod +x /etc/httpd/acme.sh/upgrade.sh
		if crontab -l | grep -q "/etc/httpd/acme.sh/upgrade.sh"; then
			_info "acme.sh upgrade crontab rule is existed"
		else
			(crontab -l ; echo '0 3 */7 * * /etc/httpd/acme.sh/upgrade.sh') | crontab -
			_info "create cron job for automatic upgrade acme.sh success"
		fi
	fi
	[ ! -d "/home/${domain}_ssl" ] && mkdir -p "/home/${domain}_ssl"
}
create_ssl_htaccess(){
    cat > ${website_root}/.htaccess << EOF
<IfModule mod_rewrite.c>
RewriteEngine On
RewriteCond %{HTTPS} off
RewriteRule ^(.*)$ https://%{HTTP_HOST}%{REQUEST_URI} [R,L]
</IfModule>
EOF
}
add_ssl_memu(){
	_info "$(_green 1). Use your own SSL Certificate and Key"
	_info "$(_green 2). Use Let's Encrypt CA to create SSL Certificate and Key"
	_info "$(_green 3). Use Buypass.com CA to create SSL Certificate and Key"

	while true; do
		read -p "[$(date)] Please enter 1 or 2 or 3: " ssl_pick
		if [ "${ssl_pick}" = "1" ]; then
			while true; do
				read -p "[$(date)] Please enter full path to SSL Certificate file: " ssl_certificate
				if [ -z "${ssl_certificate}" ]; then
					_info "$(_red "Error: SSL Certificate file can not be empty")"
				elif [ -s "${ssl_certificate}" ]; then
					break
				else
					_info "$(_red "Error: ${ssl_certificate} does not exist or is not a file")"
				fi
			done

			while true; do
				read -p "[$(date)] Please enter full path to SSL Certificate Key file: " ssl_certificate_key
				if [ -z "${ssl_certificate_key}" ]; then
					_info "$(_red "Error: SSL Certificate Key file can not be empty")"
				elif [ -s "${ssl_certificate_key}" ]; then
					break
				else
					_info "$(_red "Error: ${ssl_certificate_key} does not exist or is not a file")"
				fi
			done
			break
		elif [ "${ssl_pick}" = "2" ]; then
			_info "You chosen Let's Encrypt CA, and it will be processed automatically"
			break
		elif [ "${ssl_pick}" = "3" ]; then
			_info "You chosen Buypass.com CA, and it will be processed automatically"
			break
		else
			_info "$(_red "Error: Please only enter 1 or 2 or 3")"
		fi
	done

	read -p "[$(date)] Do you want force redirection from HTTP to HTTPS? [y/n]: " force_ssl
	if [ "${force_ssl}" = "y" ] || [ "${force_ssl}" = "Y" ]; then
		_info "You chosen force redirection from HTTP to HTTPS, and it will be processed automatically"
	else
		_info "Do not force redirection from HTTP to HTTPS"
	fi
}

add_buypass(){
	if [ -d "${ssl_folder}" ]; then
		_info "Removing exist domain certificate..."
		rm -rf "${ssl_folder}"
	fi
	challenge_path="/home/${domain}/public"
	_info "Starting create Buypass.com SSL Certificate..."
	. /etc/httpd/acme.sh/acme.sh.env
	/etc/httpd/acme.sh/acme.sh -m ${email} --issue --server buypass --domain ${domain} -w ${challenge_path} --days 170
	if [ $? -eq 0 ]; then
		ssl_certificate="${apache_location}/conf/ssl/${domain}/fullchain.cer"
		ssl_certificate_key="${apache_location}/conf/ssl/${domain}/${domain}.key"
		_info "Created Buypass.com SSL Certificate success"
	else
		_error "Error: Create Buypass.com SSL Certificate failed"
	fi
}
add_letsencrypt(){
    if [ -d "${ssl_folder}" ]; then
        _info "Removing exist domain certificate..."
        rm -rf ${ssl_folder}
    fi
    challenge_path="/home/${domain}/public"
    _info "Starting create Let's Encrypt SSL Certificate..."
    . /etc/httpd/acme.sh/acme.sh.env
    /etc/httpd/acme.sh/acme.sh --issue --server letsencrypt --domain ${domain} -w ${challenge_path}
    if [ $? -eq 0 ]; then
        ssl_certificate="${apache_location}/conf/ssl/${domain}/fullchain.cer"
        ssl_certificate_key="${apache_location}/conf/ssl/${domain}/${domain}.key"
        _info "Created Let's Encrypt SSL Certificate success"
    else
        _error "Error: Create Let's Encrypt SSL Certificate failed"
    fi
}
create_ssl_config(){ 
	cat >> /etc/httpd/conf.d/${domain}.conf << EOF
<VirtualHost *:443>
	ServerAdmin ${email}
	DocumentRoot ${website_root}
	ServerName ${domain}
	ServerAlias ${server_names}
	SSLEngine on
	SSLCertificateFile ${ssl_certificate}
	SSLCertificateKeyFile ${ssl_certificate_key}
	<Directory ${website_root}>
		SetOutputFilter DEFLATE
		Options FollowSymLinks
		AllowOverride All
		Order Deny,Allow
		Require all granted
		DirectoryIndex index.php index.html index.htm
	</Directory>
	Header always set Strict-Transport-Security "max-age=31536000; preload"
	Header always edit Set-Cookie ^(.*)$ $1;HttpOnly;Secure
	Header always set X-Content-Type-Options nosniff
	Header always set X-Frame-Options SAMEORIGIN
	ErrorLog /home/${domain}_logs/ssl_error.log
	CustomLog /home/${domain}_logs/ssl_access.log combined
</VirtualHost>
EOF
}
add_ssl_cert(){
	read -p "Enter your email : " email
	read -p "Enter your domain : " domain
	website_root="/home/${domain}"
	ssl_folder="/home/${domain}_ssl"
	if [ ! -d "$ssl_folder" ]; then
	    echo "$ssl_folder does not exist. Creating the folder..."
	    mkdir "$ssl_folder"
	    echo "Folder $ssl_folder created."
	fi
	
	if [ -z "${email}" ] || [ -z "${website_root}" ]; then
		_error "Error: parameters must be specified"
	fi
	if [ ! -d "${website_root}" ]; then
		_error "Error: ${website_root} does not exist or is not a directory"
	fi 
 
	install_check_acme

	if [ "${ssl_pick}" = "2" ]; then
		add_letsencrypt
	elif [ "${ssl_pick}" = "3" ]; then
		add_buypass
	fi

	create_ssl_config
	[ "${force_ssl}" = "y" -o "${force_ssl}" = "Y" ] && create_ssl_htaccess
	_info "Added SSL certificate for virtual host [$(_green ${domain})] success"
}
if [ "$1" = "setup" ]; then
	echo "[-> Start Setup Linux + Apache + Laravel + Postgresql Environment."
	echo "+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+" 
	sudo dnf install wget -y
	sudo yum -y install wget git 
	sudo yum update -y
	
	echo "[-> YUM Updated."
	echo "+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+"
	sudo yum install httpd -y
	sudo systemctl enable httpd.service
	sudo systemctl restart httpd.service
	
	echo "[-> HTTP Installed."
	echo "+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+"
	sudo dnf install -y https://dl.fedoraproject.org/pub/epel/epel-release-latest-8.noarch.rpm -y
	sudo dnf install -y https://rpms.remirepo.net/enterprise/remi-release-8.rpm -y
	
	sudo dnf module enable php:remi-8.2
	sudo dnf install -y php php-cli php-common php-fpm php-json php-mysqlnd php-zip php-devel php-gd php-mbstring php-curl php-xml php-pear php-pgsql php-soap php-opcache php-mcrypt mod_ssl unzip socat
	
	echo "[-> PHP Installed."
	echo "+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+" 
	sudo yum -y install supervisor
	# Configure Supervisor
	# /etc/supervisord.conf 
	systemctl start supervisord
	systemctl enable supervisord
	
	echo "[-> Supervisor Installed."
	echo "+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+" 
	sudo wget https://getcomposer.org/installer -O composer-setup.php
	sudo php composer-setup.php --install-dir=/usr/local/bin --filename=composer 
	
	echo "[-> Composer Installed."
	echo "+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+" 
	dnf install firewalld -y
	systemctl start firewalld
	systemctl enable firewalld
	firewall-cmd --permanent --add-port=5432/tcp
	firewall-cmd --permanent --add-port=80/tcp
	firewall-cmd --permanent --add-port=443/tcp
	firewall-cmd --reload

	echo "[-> Firewall Installed and added 80 443 5432 port."
	echo "+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+" 
	dnf install -y postgresql-server postgresql-contrib
	
	# Initialize and start PostgreSQL service
	/usr/bin/postgresql-setup --initdb
	systemctl start postgresql
	systemctl enable postgresql
	
	# Create PostgreSQL user and database
	su - postgres -c "psql -c \"CREATE USER jeff WITH PASSWORD 'dkfaustj';\""
	su - postgres -c "psql -c \"CREATE DATABASE doo_cms WITH OWNER jeff;\""
	su - postgres -c "psql -c \"CREATE SCHEMA doo_cms_schema AUTHORIZATION jeff;\""
	
	# Grant schema privileges to the user
	su - postgres -c "psql -c \"GRANT ALL PRIVILEGES ON SCHEMA doo_cms_schema TO jeff;\""


	# Enable password authentication in PostgreSQL
	# PG_HBA_FILE=$(find / -name pg_hba.conf)
	# echo "local   all			 all									 md5"  sudo tee -a $PG_HBA_FILE
	# echo "host	all			 all			 127.0.0.1/32			md5"  sudo tee -a $PG_HBA_FILE
	# echo "host	all			 all			 ::1/128				 md5"  sudo tee -a $PG_HBA_FILE
	# Replace ident with md5 in pg_hba.conf
	# Modify /var/lib/pgsql/data/pg_hba.conf file to change "ident" to "md5" for local addresses
	
	# Find the path of pg_hba.conf
	pg_hba_file=$(find / -name pg_hba.conf 2>/dev/null)
	
	if [[ -z $pg_hba_file ]]; then
	  echo "[->pg_hba.conf file not found." 
	fi

	sudo sed -i 's/ident/md5/g' "$pg_hba_file"
	
	echo "[-> pg_hba.conf file updated."
	
	# Restart PostgreSQL service
	sudo systemctl restart postgresql
	
	echo "[-> Postgres Installed."
	echo "+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+" 
	 
	# /var/lib/pgsql/data/postgresql.conf
	# listen_addresses = 'localhost, 172.30.1.92' <- Specify your address here
	# PostgreSQL service restart
	# systemctl restart postgresql

	echo "+-+-+-+-+-+-+-+-+-+ Setup Finished +-+-+-+-+-+-+-+-+-+-+" 
	httpd -V
	php --version
	composer --version 
elif [ "$1" = "add" ]; then
	if [ -z "$2" ]; then
		echo "[-> Tool.sh add [도메인명] - 도메인 을 입력하세요."
	else
		domain="$2"
		echo "[-> Running add command for $domain" 
		
		mkdir /home/$domain
		mkdir /home/${domain}_logs
		mkdir /home/${domain}_ssl
#		mkdir /home/$domain/public
		cd /home
		composer create-project laravel/laravel $domain
		chown -R apache:apache /home/$domain
		
		cat > /etc/httpd/conf.d/$domain.conf <<EOF
<VirtualHost *:80>
	ServerName $domain
	ServerAlias www.$domain
	DocumentRoot /home/$domain/public

	<Directory /home/$domain/public>
		Options FollowSymLinks
		AllowOverride All
		Require all granted
	</Directory>

	ErrorLog /home/${domain}_logs/error.log
	CustomLog /home/${domain}_logs/access.log combined
</VirtualHost>
#
#<VirtualHost *:443>
#	ServerName $domain
#	ServerAlias www.$domain
#	DocumentRoot /home/$domain/public
#
#	<Directory /home/$domain/public>
#		Options FollowSymLinks
#		AllowOverride All
#		Require all granted
#	</Directory>
#
#	SSLEngine on
#	SSLCertificateFile /home/$domain/ssl/$domain.crt
#	SSLCertificateKeyFile /home/$domain/ssl/$domain.key
#
#	ErrorLog /home/${domain}_logs/ssl_error.log
#	CustomLog /home/${domain}_logs/ssl_access.log combined
#</VirtualHost>
EOF
		
		systemctl restart httpd
	fi
elif [ "$1" = "ssl" ]; then
	add_ssl_memu
	add_ssl_cert
else
	echo "1. Example: Tool.sh setup - Initial setup"
	echo "2. Example: Tool.sh add [domain] - Add a host"
fi

