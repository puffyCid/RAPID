#!/bin/bash

# Exit the script if one of the commands fails
set -e

# Directory where entire Django application is located
APPLICATION_DIR="/vagrant"

# Default external configuration files
CELERY_CONFIGS_DIR="$APPLICATION_DIR/external_configs/celery"
APACHE_CONFIGS_DIR="$APPLICATION_DIR/external_configs/apache2"

# Update package list and upgrade all packages
apt-get update
apt-get -y upgrade

# Install dependency packages for application
apt-get install -y whois
apt-get install -y rabbitmq-server
apt-get install -y python3-all-dev
apt-get install -y python3-pip
apt-get install -y libpq-dev

apt-get install -y libxml2-dev
apt-get install -y libxslt-dev
apt-get install -y lib32z1-dev
apt-get install -y python3-lxml
apt-get build-dep -y python3-lxml

echo "Prerequisites installed"

cd $APPLICATION_DIR
pip3 install -r requirements.txt
echo "Python package requirements installed"

# Install Apache
apt-get install -y apache2
apt-get install -y libapache2-mod-wsgi-py3
echo "Apache installed"

# Install Postgres
apt-get install -y postgresql postgresql-contrib
echo "Postgres installed"

# Set up Celery configuration files and scripts
getent group celery &>/dev/null || groupadd celery
id -u celery &>/dev/null || useradd -g celery celery
echo "Created celery user"

cp -f $CELERY_CONFIGS_DIR/celery_beat /etc/default/celery_beat
chown root:root /etc/default/celery_beat
chmod 640 /etc/default/celery_beat

cp -f $CELERY_CONFIGS_DIR/celery_daemon /etc/default/celery_daemon
chown root:root /etc/default/celery_daemon
chmod 640 /etc/default/celery_daemon

cp -f $CELERY_CONFIGS_DIR/celery_pivoteer /etc/default/celery_pivoteer
chown root:root /etc/default/celery_pivoteer
chmod 640 /etc/default/celery_pivoteer
echo "copies celery configs"

cp -f $CELERY_CONFIGS_DIR/celery_beat.sh /etc/init.d/celery_beat
cp -f $CELERY_CONFIGS_DIR/celery_daemon.sh /etc/init.d/celery_daemon
cp -f $CELERY_CONFIGS_DIR/celery_pivoteer.sh /etc/init.d/celery_pivoteer
echo "copied celery services"

#Application config
touch $APPLICATION_DIR/RAPID.log
chmod 777 $APPLICATION_DIR/RAPID.log
echo "Created RAPID application log"

pushd $APPLICATION_DIR/core/
if [ ! -f "GeoLite2-City.mmdb" ]
then
	wget "http://geolite.maxmind.com/download/geoip/database/GeoLite2-City.mmdb.gz"
	gunzip GeoLite2-City.mmdb.gz
	echo "Downloaded and extracted Maxmind DB"
fi
popd
