sudo apt-get install memcached

sudo nano /etc/memcached.conf
 - Use this to modify memory, port, connection limit and so on

sudo systemctl stop memcached

sudo systemctl start memcached

sudo systemctl restart memcached

sudo systemctl status memcached