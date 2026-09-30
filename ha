#---------------------------------------------------------------------
# HAProxy 2.8
# Logging: local2 -> rsyslog (UDP 127.0.0.1:514) -> /var/log/haproxy.log
#          see /etc/rsyslog.d/49-haproxy.conf
#---------------------------------------------------------------------

#---------------------------------------------------------------------
# Global settings
#---------------------------------------------------------------------
global
    log         127.0.0.1 local2

    chroot      /var/lib/haproxy
    pidfile     /var/run/haproxy.pid
    maxconn     4000
    user        haproxy
    group       haproxy
    daemon

    # stats / runtime API sockets (Roxy-WI)
    stats socket /var/lib/haproxy/stats
    stats socket *:1999 level admin
    stats socket /var/run/haproxy.sock mode 600 level admin
    server-state-file /etc/haproxy/haproxy.state

    # utilize system-wide crypto-policies
    ssl-default-bind-ciphers PROFILE=SYSTEM
    ssl-default-server-ciphers PROFILE=SYSTEM

#---------------------------------------------------------------------
# HTTP defaults - applies to the proxies up to the next defaults block
#---------------------------------------------------------------------
defaults
    mode                    http
    log                     global
    option                  httplog
    option                  dontlognull
    option http-server-close
    option forwardfor       except 127.0.0.0/8
    option                  redispatch
    retries                 3
    timeout http-request    10s
    timeout queue           1m
    timeout connect         10s
    timeout client          1m
    timeout server          1m
    timeout http-keep-alive 10s
    timeout check           10s
    maxconn                 3000

#---------------------------------------------------------------------
# main frontend which proxys to the backends
#---------------------------------------------------------------------
frontend main
    bind *:5000
    acl url_static       path_beg       -i /static /images /javascript /stylesheets
    acl url_static       path_end       -i .jpg .gif .png .css .js

    use_backend static          if url_static
    default_backend             app

backend static
    balance     roundrobin
    server      static 127.0.0.1:4331 check

backend app
    balance     roundrobin
    server  app1 127.0.0.1:5001 check
    server  app2 127.0.0.1:5002 check
    server  app3 127.0.0.1:5003 check
    server  app4 127.0.0.1:5004 check

listen stats
    bind *:8085
    mode http
    maxconn 10

    timeout client  100s
    timeout server  100s
    timeout connect 100s
    timeout queue   100s

    stats enable
    stats hide-version
    stats refresh 30s
    stats show-node
    stats auth admin:HemmingWay2010
    stats uri /stats
    stats admin if TRUE

#---------------------------------------------------------------------
# TCP defaults - applies to all RDP listeners below
#---------------------------------------------------------------------
defaults
    mode                    tcp
    log                     global
    option                  tcplog
    option                  dontlognull
    option                  redispatch
    retries                 3
    timeout queue           1m
    timeout connect         10s
    timeout client          1m
    timeout server          1m
    timeout check           10s
    maxconn                 3000

listen rdfarm19
    bind 10.50.40.140:3389
    maxconn 22000
    balance roundrobin
    server 10.50.40.111 10.50.40.111:3389 check

listen rdfarm19-mfa
    bind 10.50.40.140:4000
    maxconn 22000
    balance roundrobin
    server 10.50.40.111-mfa 10.50.40.111:4000 check

listen rdfarm19365
    bind 10.50.40.30:3389
    maxconn 22000
    balance roundrobin
    server 10.50.40.133 10.50.40.133:3389 check
    server 10.50.40.134 10.50.40.134:3389 check
    server 10.50.40.135 10.50.40.135:3389 check
    server 10.50.40.138 10.50.40.138:3389 check
    server 10.50.40.139 10.50.40.139:3389 check
    server 10.50.40.141 10.50.40.141:3389 check
    server 10.50.40.142 10.50.40.142:3389 check
    server 10.50.40.143 10.50.40.143:3389 check
    server 10.50.40.144 10.50.40.144:3389 check
    server 10.50.40.145 10.50.40.145:3389 check
    server 10.50.40.146 10.50.40.146:3389 check

listen rdfarm19365mfa
    bind 10.50.40.30:4000
    maxconn 22000
    balance roundrobin
    server 10.50.40.133-mfa 10.50.40.133:4000 check
    server 10.50.40.134-mfa 10.50.40.134:4000 check
    server 10.50.40.135-mfa 10.50.40.135:4000 check
    server 10.50.40.138-mfa 10.50.40.138:4000 check
    server 10.50.40.139-mfa 10.50.40.139:4000 check
    server 10.50.40.141-mfa 10.50.40.141:4000 check
    server 10.50.40.142-mfa 10.50.40.142:4000 check
    server 10.50.40.143-mfa 10.50.40.143:4000 check
    server 10.50.40.144-mfa 10.50.40.144:4000 check
    server 10.50.40.145-mfa 10.50.40.145:4000 check
    server 10.50.40.146-mfa 10.50.40.146:4000 check

listen RDFarmSXA
    bind 10.50.40.120:3389
    maxconn 22000
    balance roundrobin
    server 10.50.40.121 10.50.40.121:3389 check
    server 10.50.40.122 10.50.40.122:3389 check
    server 10.50.40.123 10.50.40.123:3389 check

listen RDFarmSXAmfa
    bind 10.50.40.120:4000
    maxconn 22000
    balance roundrobin
    server 10.50.40.121-mfa 10.50.40.121:4000 check
    server 10.50.40.122-mfa 10.50.40.122:4000 check
    server 10.50.40.123-mfa 10.50.40.123:4000 check

listen RDFarm22SXA
    bind 10.50.40.150:3389
    maxconn 22000
    balance roundrobin
    server 10.50.40.124 10.50.40.124:3389 check

listen RDFarm22SXAmfa
    bind 10.50.40.150:4000
    maxconn 22000
    balance roundrobin
    server 10.50.40.124-mfa 10.50.40.124:4000 check

listen RDFarm365
    bind 10.50.40.130:3389
    maxconn 22000
    balance roundrobin
    server 10.50.40.161 10.50.40.161:3389 check

listen RDFarm365mfa
    bind 10.50.40.130:4000
    maxconn 22000
    balance roundrobin
    server 10.50.40.161-mfa 10.50.40.161:4000 check

listen RDFarm01
    bind 10.50.40.100:3389
    maxconn 22000
    balance roundrobin
    server 10.50.40.101 10.50.40.101:3389 check

listen RDFarm01mfa
    bind 10.50.40.100:4000
    maxconn 22000
    balance roundrobin
    server 10.50.40.101-mfa 10.50.40.101:4000 check
