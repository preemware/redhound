package main

import (
	"strings"
)

func detectServiceFromBanner(service *Service, banner string) {
	bannerLower := strings.ToLower(banner)

	switch {
	// SSH services
	case strings.Contains(bannerLower, "ssh"):
		service.Name = "ssh"
		if strings.Contains(bannerLower, "openssh") {
			service.Product = "OpenSSH"
		} else if strings.Contains(bannerLower, "dropbear") {
			service.Product = "Dropbear"
		} else if strings.Contains(bannerLower, "libssh") {
			service.Product = "libssh"
		}

	// HTTP services
	case strings.Contains(bannerLower, "http"):
		service.Name = "http"
		if strings.Contains(bannerLower, "apache") {
			service.Product = "Apache"
		} else if strings.Contains(bannerLower, "nginx") {
			service.Product = "nginx"
		} else if strings.Contains(bannerLower, "iis") {
			service.Product = "IIS"
		} else if strings.Contains(bannerLower, "lighttpd") {
			service.Product = "lighttpd"
		} else if strings.Contains(bannerLower, "jetty") {
			service.Product = "Jetty"
		} else if strings.Contains(bannerLower, "tomcat") {
			service.Product = "Tomcat"
		} else if strings.Contains(bannerLower, "cherrypy") {
			service.Product = "CherryPy"
		} else if strings.Contains(bannerLower, "tornado") {
			service.Product = "Tornado"
		}

	// FTP services
	case strings.Contains(bannerLower, "ftp"):
		service.Name = "ftp"
		if strings.Contains(bannerLower, "vsftpd") {
			service.Product = "vsftpd"
		} else if strings.Contains(bannerLower, "proftpd") {
			service.Product = "ProFTPD"
		} else if strings.Contains(bannerLower, "pureftpd") {
			service.Product = "Pure-FTPd"
		} else if strings.Contains(bannerLower, "filezilla") {
			service.Product = "FileZilla Server"
		}

	// Mail services
	case strings.Contains(bannerLower, "smtp"):
		service.Name = "smtp"
		if strings.Contains(bannerLower, "postfix") {
			service.Product = "Postfix"
		} else if strings.Contains(bannerLower, "sendmail") {
			service.Product = "Sendmail"
		} else if strings.Contains(bannerLower, "exim") {
			service.Product = "Exim"
		}
	case strings.Contains(bannerLower, "pop3"):
		service.Name = "pop3"
		if strings.Contains(bannerLower, "dovecot") {
			service.Product = "Dovecot"
		}
	case strings.Contains(bannerLower, "imap"):
		service.Name = "imap"
		if strings.Contains(bannerLower, "dovecot") {
			service.Product = "Dovecot"
		} else if strings.Contains(bannerLower, "courier") {
			service.Product = "Courier"
		}

	// Database services
	case strings.Contains(bannerLower, "mysql"):
		service.Name = "mysql"
		service.Product = "MySQL"
	case strings.Contains(bannerLower, "postgresql"):
		service.Name = "postgresql"
		service.Product = "PostgreSQL"
	case strings.Contains(bannerLower, "oracle"):
		service.Name = "oracle"
		service.Product = "Oracle"
	case strings.Contains(bannerLower, "mssql") || strings.Contains(bannerLower, "sql server"):
		service.Name = "mssql"
		service.Product = "Microsoft SQL Server"
	case strings.Contains(bannerLower, "mongodb"):
		service.Name = "mongodb"
		service.Product = "MongoDB"
	case strings.Contains(bannerLower, "redis"):
		service.Name = "redis"
		service.Product = "Redis"
	case strings.Contains(bannerLower, "elasticsearch"):
		service.Name = "elasticsearch"
		service.Product = "Elasticsearch"
	case strings.Contains(bannerLower, "cassandra"):
		service.Name = "cassandra"
		service.Product = "Apache Cassandra"
	case strings.Contains(bannerLower, "couchdb"):
		service.Name = "couchdb"
		service.Product = "Apache CouchDB"
	case strings.Contains(bannerLower, "influxdb"):
		service.Name = "influxdb"
		service.Product = "InfluxDB"
	case strings.Contains(bannerLower, "memcached"):
		service.Name = "memcached"
		service.Product = "Memcached"

	// Remote access
	case strings.Contains(bannerLower, "telnet"):
		service.Name = "telnet"
	case strings.Contains(bannerLower, "vnc"):
		service.Name = "vnc"
		if strings.Contains(bannerLower, "realvnc") {
			service.Product = "RealVNC"
		} else if strings.Contains(bannerLower, "tightvnc") {
			service.Product = "TightVNC"
		} else if strings.Contains(bannerLower, "ultravnc") {
			service.Product = "UltraVNC"
		}

	// Directory services
	case strings.Contains(bannerLower, "ldap"):
		service.Name = "ldap"
		if strings.Contains(bannerLower, "openldap") {
			service.Product = "OpenLDAP"
		} else if strings.Contains(bannerLower, "active directory") {
			service.Product = "Microsoft Active Directory"
		}

	// Network services
	case strings.Contains(bannerLower, "snmp"):
		service.Name = "snmp"
	case strings.Contains(bannerLower, "ntp"):
		service.Name = "ntp"
	case strings.Contains(bannerLower, "dhcp"):
		service.Name = "dhcp"
	case strings.Contains(bannerLower, "dns"):
		service.Name = "dns"
		if strings.Contains(bannerLower, "bind") {
			service.Product = "BIND"
		}

	// Application servers
	case strings.Contains(bannerLower, "jboss"):
		service.Name = "jboss"
		service.Product = "JBoss"
	case strings.Contains(bannerLower, "weblogic"):
		service.Name = "weblogic"
		service.Product = "Oracle WebLogic"
	case strings.Contains(bannerLower, "websphere"):
		service.Name = "websphere"
		service.Product = "IBM WebSphere"
	case strings.Contains(bannerLower, "glassfish"):
		service.Name = "glassfish"
		service.Product = "GlassFish"
	case strings.Contains(bannerLower, "wildfly"):
		service.Name = "wildfly"
		service.Product = "WildFly"

	// Proxy and load balancers
	case strings.Contains(bannerLower, "squid"):
		service.Name = "squid"
		service.Product = "Squid Proxy"
	case strings.Contains(bannerLower, "haproxy"):
		service.Name = "haproxy"
		service.Product = "HAProxy"
	case strings.Contains(bannerLower, "varnish"):
		service.Name = "varnish"
		service.Product = "Varnish"

	// Monitoring and management
	case strings.Contains(bannerLower, "zabbix"):
		service.Name = "zabbix"
		service.Product = "Zabbix"
	case strings.Contains(bannerLower, "nagios"):
		service.Name = "nagios"
		service.Product = "Nagios"
	case strings.Contains(bannerLower, "prometheus"):
		service.Name = "prometheus"
		service.Product = "Prometheus"
	case strings.Contains(bannerLower, "grafana"):
		service.Name = "grafana"
		service.Product = "Grafana"

	// Virtualization
	case strings.Contains(bannerLower, "vmware"):
		service.Name = "vmware"
		service.Product = "VMware"
	case strings.Contains(bannerLower, "docker"):
		service.Name = "docker"
		service.Product = "Docker"
	case strings.Contains(bannerLower, "kubernetes"):
		service.Name = "kubernetes"
		service.Product = "Kubernetes"

	// Security appliances
	case strings.Contains(bannerLower, "fortinet") || strings.Contains(bannerLower, "fortigate"):
		service.Name = "fortigate"
		service.Product = "Fortinet FortiGate"
	case strings.Contains(bannerLower, "palo alto"):
		service.Name = "paloalto"
		service.Product = "Palo Alto Networks"
	case strings.Contains(bannerLower, "checkpoint"):
		service.Name = "checkpoint"
		service.Product = "Check Point"

	// Media services
	case strings.Contains(bannerLower, "rtsp"):
		service.Name = "rtsp"
	case strings.Contains(bannerLower, "rtmp"):
		service.Name = "rtmp"
	case strings.Contains(bannerLower, "sip"):
		service.Name = "sip"

	// File sharing
	case strings.Contains(bannerLower, "samba") || strings.Contains(bannerLower, "smb"):
		service.Name = "smb"
		service.Product = "Samba"
	case strings.Contains(bannerLower, "nfs"):
		service.Name = "nfs"
	case strings.Contains(bannerLower, "afp"):
		service.Name = "afp"
		service.Product = "Apple Filing Protocol"

	// Development tools
	case strings.Contains(bannerLower, "jenkins"):
		service.Name = "jenkins"
		service.Product = "Jenkins"
	case strings.Contains(bannerLower, "gitlab"):
		service.Name = "gitlab"
		service.Product = "GitLab"
	case strings.Contains(bannerLower, "sonarqube"):
		service.Name = "sonarqube"
		service.Product = "SonarQube"
	case strings.Contains(bannerLower, "nexus"):
		service.Name = "nexus"
		service.Product = "Sonatype Nexus"

	// Generic patterns
	case strings.Contains(bannerLower, "microsoft"):
		service.Product = "Microsoft"
	case strings.Contains(bannerLower, "cisco"):
		service.Product = "Cisco"
	case strings.Contains(bannerLower, "linux"):
		service.Product = "Linux"
	case strings.Contains(bannerLower, "windows"):
		service.Product = "Windows"
	case strings.Contains(bannerLower, "ubuntu"):
		service.Product = "Ubuntu"
	case strings.Contains(bannerLower, "centos"):
		service.Product = "CentOS"
	case strings.Contains(bannerLower, "debian"):
		service.Product = "Debian"
	case strings.Contains(bannerLower, "redhat"):
		service.Product = "Red Hat"

	// Response codes for specific services
	case strings.Contains(bannerLower, "220"):
		if service.Port == 21 {
			service.Name = "ftp"
		} else if service.Port == 25 {
			service.Name = "smtp"
		}
	case strings.Contains(bannerLower, "331"):
		if service.Port == 21 {
			service.Name = "ftp"
		}
	case strings.Contains(bannerLower, "+ok"):
		if service.Port == 110 {
			service.Name = "pop3"
		}
	case strings.Contains(bannerLower, "* ok"):
		if service.Port == 143 {
			service.Name = "imap"
		}
	}
}

func detectServiceByPort(port uint16) string {
	switch port {
	// Basic network services
	case 21:
		return "ftp"
	case 22:
		return "ssh"
	case 23:
		return "telnet"
	case 25:
		return "smtp"
	case 49:
		return "tacacs+"
	case 53:
		return "dns"
	case 67:
		return "dhcp"
	case 68:
		return "dhcp-client"
	case 69:
		return "tftp"
	case 79:
		return "finger"
	case 80:
		return "http"
	case 88:
		return "kerberos"
	case 110:
		return "pop3"
	case 111:
		return "sunrpc"
	case 123:
		return "ntp"
	case 135:
		return "msrpc"
	case 137:
		return "netbios-ns"
	case 138:
		return "netbios-dgm"
	case 139, 445:
		return "smb"
	case 143:
		return "imap"
	case 161:
		return "snmp"
	case 162:
		return "snmp-trap"
	case 389:
		return "ldap"
	case 443:
		return "https"
	case 464:
		return "kpasswd"
	case 514:
		return "syslog"
	case 548:
		return "afp"
	case 636:
		return "ldaps"
	case 873:
		return "rsync"
	case 993:
		return "imaps"
	case 995:
		return "pop3s"

	// Extended web services
	case 280:
		return "http-mgmt"
	case 591:
		return "filemaker"
	case 593:
		return "ms-http-rpc"
	case 631:
		return "ipp"
	case 808:
		return "ccproxy-http"
	case 832:
		return "vatp"
	case 981:
		return "unknown"
	case 1010:
		return "surf"
	case 1099:
		return "java-rmi"
	case 1311:
		return "rxmon"
	case 2301:
		return "compaq-https"
	case 2381:
		return "compaq-https"
	case 2809:
		return "corba-iiop"
	case 3000, 3001:
		return "node-js"
	case 3128:
		return "squid-proxy"
	case 3333:
		return "dec-notes"
	case 4243:
		return "docker"
	case 4567:
		return "tram"
	case 4711, 4712:
		return "unknown"
	case 4993:
		return "unknown"
	case 5000, 5001:
		return "flask/upnp"
	case 5104:
		return "unknown"
	case 5108:
		return "unknown"
	case 5800:
		return "vnc-http"
	case 6543:
		return "mythtv"
	case 7000, 7001, 7002:
		return "cassandra/weblogic"
	case 7070:
		return "realserver"
	case 7396:
		return "rtsp-alt"
	case 7474:
		return "neo4j"
	case 8000, 8001:
		return "http-alt"
	case 8005:
		return "tomcat"
	case 8006:
		return "http-alt"
	case 8008, 8009:
		return "http-alt"
	case 8014:
		return "unknown"
	case 8042:
		return "fs-agent"
	case 8069:
		return "openstack"
	case 8080, 8081:
		return "http-proxy"
	case 8083:
		return "us-srv"
	case 8088:
		return "radan-http"
	case 8090, 8091:
		return "jboss"
	case 8118:
		return "privoxy"
	case 8123:
		return "polipo"
	case 8172:
		return "unknown"
	case 8181:
		return "intermapper"
	case 8222:
		return "unknown"
	case 8243:
		return "unknown"
	case 8280, 8281:
		return "unknown"
	case 8333:
		return "bitcoin"
	case 8443:
		return "https-alt"
	case 8500:
		return "fmtp"
	case 8834:
		return "unknown"
	case 8880:
		return "cddbp-alt"
	case 8888:
		return "sun-answerbook"
	case 8983:
		return "solr"
	case 9000:
		return "cslistener"
	case 9043:
		return "websphere"
	case 9060:
		return "websphere"
	case 9080:
		return "glrpc"
	case 9090, 9091:
		return "xml-dtd"
	case 9443:
		return "tungsten-https"
	case 9800:
		return "unknown"
	case 9981:
		return "unknown"
	case 9999:
		return "abyss"
	case 10001:
		return "scp-config"
	case 11371:
		return "hkp"
	case 34573:
		return "unknown"
	case 55555:
		return "unknown"

	// Database services
	case 1433:
		return "mssql"
	case 1434:
		return "mssql-monitor"
	case 1521:
		return "oracle"
	case 1830:
		return "oracle"
	case 2100:
		return "amiganetfs"
	case 2483, 2484:
		return "oracle"
	case 3050:
		return "firebird"
	case 3306:
		return "mysql"
	case 3351:
		return "pervasive"
	case 4505, 4506:
		return "saltstack"
	case 5432, 5433:
		return "postgresql"
	case 5984:
		return "couchdb"
	case 6379, 6380:
		return "redis"
	case 8086:
		return "influxdb"
	case 8087:
		return "unknown"
	case 9042:
		return "cassandra"
	case 9160:
		return "cassandra-thrift"
	case 9200:
		return "elasticsearch"
	case 9300:
		return "elasticsearch"
	case 11211:
		return "memcached"
	case 27017, 27018, 27019:
		return "mongodb"
	case 28017:
		return "mongodb-web"
	case 50070:
		return "hadoop"

	// Remote access and management
	case 902, 903:
		return "vmware"
	case 1723:
		return "pptp"
	case 1801:
		return "msmq"
	case 2000:
		return "cisco-sccp"
	case 2049:
		return "nfs"
	case 2121:
		return "ccproxy-ftp"
	case 2375, 2376:
		return "docker"
	case 3389:
		return "rdp"
	case 4440:
		return "unknown"
	case 4848:
		return "appserver"
	case 4899:
		return "radmin"
	case 5040:
		return "unknown"
	case 5060, 5061:
		return "sip"
	case 5357:
		return "wsdapi"
	case 5480:
		return "vmware-vsphere"
	case 5500:
		return "fcp-addr-srvr1"
	case 5631:
		return "pcanywheredata"
	case 5666:
		return "nrpe"
	case 5900, 5901, 5902, 5903, 5904, 5905, 5906:
		return "vnc"
	case 5938:
		return "teamviewer"
	case 5985:
		return "winrm-http"
	case 5986:
		return "winrm-https"
	case 6000, 6001, 6002, 6003, 6004, 6005, 6006, 6007:
		return "x11"
	case 6080:
		return "x11"
	case 6346, 6347:
		return "gnutella"
	case 6443:
		return "kubernetes"
	case 8649:
		return "unknown"
	case 9001:
		return "tor-orport"
	case 9030:
		return "tor-dir"
	case 9990:
		return "osm-appsrvr"
	case 10000:
		return "snet-sensor-mgmt"
	case 10250:
		return "kubernetes-kubelet"
	case 20000:
		return "unknown"

	// Mail services
	case 220:
		return "imap3"
	case 465:
		return "smtps"
	case 587:
		return "smtp-submission"
	case 1109:
		return "kpop"
	case 2525:
		return "ms-v-worlds"
	case 4190:
		return "sieve"

	// Network infrastructure
	case 500:
		return "isakmp"
	case 1645, 1646:
		return "radius-alt"
	case 1701:
		return "l2tp"
	case 1812:
		return "radius"
	case 1813:
		return "radius-acct"
	case 4500:
		return "ipsec-nat-t"
	case 5353:
		return "mdns"
	case 10443:
		return "unknown"

	// File sharing and storage
	case 115:
		return "sftp"
	case 3260:
		return "iscsi"

	// Enterprise and directory services
	case 1024, 1025:
		return "blackjack"
	case 3268:
		return "msft-gc"
	case 3269:
		return "msft-gc-ssl"
	case 5722:
		return "msft-dfs"
	case 9389:
		return "adws"

	// Monitoring and logging
	case 1514:
		return "ica"
	case 2003, 2004:
		return "cfinger"
	case 5044:
		return "lxi-evntsvc"
	case 5140:
		return "unknown"
	case 5601:
		return "esmagent"
	case 6514:
		return "syslog-tls"
	case 8125, 8126:
		return "unknown"
	case 10050:
		return "zabbix-agent"
	case 10051:
		return "zabbix-trapper"

	// Gaming and media
	case 1935:
		return "rtmp"
	case 3478, 3479:
		return "turn"
	case 5004, 5005:
		return "rtp"
	case 6970:
		return "realserver"
	case 7777:
		return "cbt"
	case 8767:
		return "unknown"
	case 27015, 27016:
		return "steam"

	// IoT and embedded devices
	case 81:
		return "hosts2-ns"
	case 554:
		return "rtsp"
	case 1900:
		return "upnp"
	case 8554:
		return "rtsp-alt"
	case 49152:
		return "unknown"

	// Industrial and specialized
	case 102:
		return "iso-tsap"
	case 502:
		return "modbus"
	case 789:
		return "unknown"
	case 1089:
		return "ff-annunc"
	case 1091:
		return "ff-sm"
	case 1911:
		return "mtp"
	case 2222:
		return "ssh-alt"
	case 2404:
		return "iec-104"
	case 4000:
		return "terabase"
	case 4840:
		return "opcua"
	case 44818:
		return "eticontrol"
	case 47808:
		return "bacnet"
	case 50000:
		return "ibm-db2"

	default:
		return "unknown"
	}
}
