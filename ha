# /etc/rsyslog.d/49-haproxy.conf
# Receive HAProxy logs on UDP 127.0.0.1:514 and write them to /var/log/haproxy.log
module(load="imudp")
input(type="imudp" address="127.0.0.1" port="514")
 
local2.*    /var/log/haproxy.log
& stop
 
