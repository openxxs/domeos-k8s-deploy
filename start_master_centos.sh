#!/bin/sh

# install and start kubernetes master on centos system
# xiaoshengxu@sohu-inc.com
# update 2016-04-21: add cluster DNS nameserver and search into top of resolv.conf; format output; fix some bugs; change install package url

# sudo sh start_master_centos.sh --kube-apiserver-port <kube_apiserver_port> --etcd-servers <etcd_servers> --service-cluster-ip-range <service_cluster_ip_range> --flannel-network-ip-range <flannel_network_ip_range> --flannel-subnet-len <flannel_subnet_len> --cluster-dns <cluster_dns> --cluster-domain <cluster_domain> --insecure-bind-address <insecure_bind_address> --insecure-port <insecure_port> --secure-bind-address <secure_bind_address> --secure-port <secure_port> --authorization-mode <authorization_mode> --authorization-policy-file <authorization_policy_file> --basic-auth-file <basic_auth_file> --docker-graph-path <docker_graph_path> --insecure-docker-registry <insecure_docker_registry> --secure-docker-registry <secure_docker_registry> --docker-registry-crt <docker_registry_crt>

# example01 -- simple command, use default parameters: sudo sh start_master_centos.sh --etcd-servers http://10.11.151.97:4012,http://10.11.151.100:4012,http://10.11.151.101:4012 --insecure-docker-registry 10.11.150.76:5000

# example02 -- http for kube-apiserver; http for docker registry: sudo sh start_master_centos.sh --etcd-servers http://10.11.151.97:4012,http://10.11.151.100:4012,http://10.11.151.101:4012 --insecure-bind-address 0.0.0.0 --insecure-port 8080 --insecure-docker-registry 10.11.150.76:5000

# example03 -- https for kube-apiserver; http for docker registry: sudo sh start_master_centos.sh --etcd-servers http://10.11.151.97:4012,http://10.11.151.100:4012,http://10.11.151.101:4012 --secure-bind-address 0.0.0.0 --secure-port 6443 --authorization-mode ABAC --authorization-policy-file /opt/domeos/openxxs/k8s-1.1.7-flannel/authorization --basic-auth-file /opt/domeos/openxxs/k8s-1.1.7-flannel/authentication.csv --insecure-docker-registry 10.11.150.76:5000

# example04 -- http and https for kube-apiserver; http for docker registry: sudo sh start_master_centos.sh --etcd-servers http://10.11.151.97:4012,http://10.11.151.100:4012,http://10.11.151.101:4012 --insecure-bind-address 0.0.0.0 --insecure-port 8080 --secure-bind-address 0.0.0.0 --secure-port 6443 --authorization-mode ABAC --authorization-policy-file /opt/domeos/openxxs/k8s-1.1.7-flannel/authorization --basic-auth-file /opt/domeos/openxxs/k8s-1.1.7-flannel/authentication.csv --insecure-docker-registry 10.11.150.76:5000

# example05 -- complete command, http and https for kube-apiserver; http and https for docker registry: sudo sh start_master_centos.sh --kube-apiserver-port 8080 --etcd-servers http://10.11.151.97:4012,http://10.11.151.100:4012,http://10.11.151.101:4012 --service-cluster-ip-range 172.16.0.0/13 --flannel-network-ip-range 172.24.0.0/13 --flannel-subnet-len 22 --cluster-dns 172.16.40.1 --cluster-domain domeos.local --insecure-bind-address 0.0.0.0 --insecure-port 8080 --secure-bind-address 0.0.0.0 --secure-port 6443 --authorization-mode ABAC --authorization-policy-file /opt/domeos/openxxs/k8s-1.1.7-flannel/authorization --basic-auth-file /opt/domeos/openxxs/k8s-1.1.7-flannel/authentication.csv --docker-graph-path /opt/domeos/openxxs/docker --insecure-docker-registry 10.11.150.76:5000 --secure-docker-registry https://private-registry.sohucs.com --docker-registry-crt /opt/domeos/openxxs/k8s-1.1.7-flannel/registry.crt

# STEP 01: check arguments
OPTS=$(getopt -o : --long kube-apiserver-port:,etcd-servers:,service-cluster-ip-range:,flannel-network-ip-range:,flannel-subnet-len:,cluster-dns:,cluster-domain:,insecure-bind-address:,insecure-port:,secure-bind-address:,secure-port:,authorization-mode:,authorization-policy-file:,basic-auth-file:,docker-graph-path:,insecure-docker-registry:,secure-docker-registry:,docker-registry-crt: -- "$@")
if [ $? != 0 ]
then
  echo -e "\033[31m[ERROR] start_master_centos.sh argument is illegal\033[0m"
  exit 1
fi
eval set -- "$OPTS"
kube_apiserver_port=
etcd_servers=
service_cluster_ip_range=
flannel_network_ip_range=
flannel_subnet_len=
cluster_dns=
cluster_domain=
insecure_bind_address=
insecure_port=
secure_bind_address=
secure_port=
authorization_mode=
authorization_policy_file=
basic_auth_file=
docker_graph_path=
insecure_docker_registry=
secure_docker_registry=
docker_registry_crt=
while true ; do
  case "$1" in
    --kube-apiserver-port) kube_apiserver_port=$2; shift 2;;
    --etcd-servers) etcd_servers=$2; shift 2;;
    --service-cluster-ip-range) service_cluster_ip_range=$2; shift 2;;
    --flannel-network-ip-range) flannel_network_ip_range=$2; shift 2;;
    --flannel-subnet-len) flannel_subnet_len=$2; shift 2;;
    --cluster-dns) cluster_dns=$2; shift 2;;
    --cluster-domain) cluster_domain=$2; shift 2;;
    --insecure-bind-address) insecure_bind_address=$2; shift 2;;
    --insecure-port) insecure_port=$2; shift 2;;
    --secure-bind-address) secure_bind_address=$2; shift 2;;
    --secure-port) secure_port=$2; shift 2;;
    --authorization-mode) authorization_mode=$2; shift 2;;
    --authorization-policy-file) authorization_policy_file=$2; shift 2;;
    --basic-auth-file) basic_auth_file=$2; shift 2;;
    --docker-graph-path) docker_graph_path=$2; shift 2;;
    --insecure-docker-registry) insecure_docker_registry=$2; shift 2;;
    --secure-docker-registry) secure_docker_registry=$2; shift 2;;
    --docker-registry-crt) docker_registry_crt=$2; shift 2;;
    --) shift; break;;
  esac
done
if [ "$kube_apiserver_port" == "" ]; then
  echo -e "\033[36m[INFO] --kube-apiserver-port is absent, default '8080'\033[0m"
  kube_apiserver_port=8080
else
  echo "--kube-apiserver-port: $kube_apiserver_port"
fi
if [ "$etcd_servers" == "" ]; then
  # TODO start a single node etcd
  echo -e "\033[31m[ERROR] --etcd-servers is absent\033[0m"
  exit 1
else
  echo "--etcd-servers: $etcd_servers"
fi
if [ "$service_cluster_ip_range" == "" ]; then
  echo -e "\033[36m[INFO] --service-cluster-ip-range is absent, default '172.16.0.0/13'\033[0m"
  service_cluster_ip_range='172.16.0.0/13'
else
  echo "--service-cluster-ip-range: $service_cluster_ip_range"
fi
if [ "$flannel_network_ip_range" == "" ]; then
  echo -e "\033[36m[INFO] --flannel-network-ip-range is absent, default '172.24.0.0/13'\033[0m"
  flannel_network_ip_range='172.24.0.0/13'
else
  echo "--flannel-network-ip-range: $flannel_network_ip_range"
fi
if [ "$flannel_subnet_len" == "" ]; then
  echo -e "\033[36m[INFO] --flannel-subnet-len is absent, default '22'\033[0m"
  flannel_subnet_len=22
else
  echo "--flannel-subnet-len: $flannel_subnet_len"
fi
if [ "$cluster_dns" == "" ]; then
  echo -e "\033[36m[INFO] --cluster-dns is absent, default '172.16.40.1'\033[0m"
  cluster_dns='172.16.40.1'
else
  echo "--cluster-dns: $cluster_dns"
fi
if [ "$cluster_domain" ]; then
  echo -e "\033[36m[INFO] --cluster-domain is absent, default 'domeos.local'\033[0m"
  cluster_domain='domeos.local'
else
  echo "--cluster-domain: $cluster_domain"
fi
if [ "$insecure_bind_address" == "" ]; then
  echo -e "\033[36m[INFO] --insecure-bind-address is absent, default '0.0.0.0'\033[0m"
  insecure_bind_address='0.0.0.0'
else
  echo "--insecure-bind-address: $insecure_bind_address"
fi
if [ "$insecure_port" == "" ]; then
  echo -e "\033[36m[INFO] --insecure-port is absent, default '8080'\033[0m"
  insecure_port=8080
else
  echo "--insecure-port: $insecure_port"
fi
if [ "$secure_bind_address" == "" ]; then
  echo -e "\033[36m[INFO] --secure-bind-address is absent, default '0.0.0.0'\033[0m"
  secure_bind_address='0.0.0.0'
else
  echo "--secure-bind-address: $secure_bind_address"
fi
if [ "$secure_port" == "" ]; then
  echo -e "\033[36m[INFO] --secure-port is absent, default '6443'\033[0m"
  secure_port=6443
else
  echo "--secure-port: $secure_port"
fi
echo "--authorization-mode: " $authorization_mode
if [ "$authorization_policy_file" != "" ]; then
  if [ -f $authorization_policy_file ]; then
    echo "--authorization-policy-file: $authorization_policy_file"
  else
    echo -e "\033[31m[ERROR] $authorization_policy_file is not exist or permission denied\033[0m"
    exit 1
  fi
fi
if [ "$basic_auth_file" != "" ]; then
  if [ -f $basic_auth_file ]; then
    echo "--basic-auth-file: $basic_auth_file"
  else
    echo -e "\033[31m[ERROR] $basic_auth_file is not exist or permission denied\033[0m"
    exit 1
  fi
fi
if [ "$docker_graph_path" != "" ]; then
  echo -e "\033[36m[INFO] --docker-graph-path is absent, default '$(pwd)/docker-graph'\033[0m"
  docker_graph_path=$(pwd)/docker-graph
else
  echo "--docker-graph-path: $docker_graph_path"
fi
echo "--insecure-docker-registry: $insecure_docker_registry"
if [ "$secure_docker_registry" != "" ]; then
  echo "--secure-docker-registry: " $secure_docker_registry
  if [ "$docker_registry_crt" != "" ] && [ -f $docker_registry_crt ]; then
    echo "--docker-registry-crt: $docker_registry_crt"
  else
    echo -e "\033[31m[ERROR] docker registry certificate $docker_registry_crt is not exist or permission denied\033[0m"
    exit 1
  fi
fi
echo -e "\033[32m[OK] check start_master_centos.sh arguments\033[0m"

# STEP 02: assign append arguments
flannel_opts=
docker_opts="--log-level=warn"
kube_apiserver_opts="--v=0"
kube_controller_manager_opts="--v=0"
kube_scheduler_opts="--v=0"
kube_proxy_opts="--masquerade-all=true --v=0"
master_package_url="http://domeos-script.bjctc.scs.sohucs.com/domeos-k8s-master.tar.gz"
docker_url="https://get.docker.com/"
registry_crt_path="/etc/docker/certs.d"
flannel_prefix="/flannel/network"
cloud_provider=
proxy_mode="iptables"
resolv_file="/etc/resolv.conf"

command_exists() {
  command -v "$@" > /dev/null 2>&1
}
current_path=$(pwd)
host_ips=(`ip addr show | grep inet | grep -v inet6 | grep brd | awk '{print $2}' | cut -f1 -d '/'`)
if [ "$host_ips" == "" ]; then
  echo -e "\033[31m[ERROR] get host ip address error\033[0m"
  exit 1
fi
host_ip=
for i in ${host_ips[@]}
do
  ip_parts=(${i//./ })
  if [ ${ip_parts[0]} -eq 10 ]; then
    host_ip=$i
    break
  fi
  if [ ${ip_parts[0]} -eq 172 ] && [ ${ip_parts[1]} -ge 16 ]; then
    host_ip=$i
    break
  fi
  if [ ${ip_parts[0]} -eq 192 ] && [ ${ip_parts[1]} -eq 168 ]; then
    host_ip=$i
    break
  fi
done
if [ "$host_ip" == "" ]; then
  host_ip=${host_ips[0]}
fi
echo -e "\033[36m[INFO] use host IP address: $host_ip\033[0m"

# STEP 03: check hostname (DNS roles)
host_hostname=`hostname`
hostname_cnt=`echo $host_hostname | grep '^[0-9a-zA-Z-]*$' | wc | awk '{print $3}'`
if [ $hostname_cnt -le 0 ]; then
  echo -e "\033[31m[ERROR] host hostname is illegal (^[0-9a-zA-Z-]*$), you can use change_hostname.sh to assign a new hostname for host\033[0m"
  exit 1
else
  if [ $hostname_cnt -ge 64 ]; then
    echo -e "\033[31m[ERROR] node hostname is longer than 63 chars\033[0m"
    exit 1
  fi
fi
echo -e "\033[32m[OK] check node hostname\033[0m"

# STEP 04: download and decompress install package
# TODO network offline
curl -o domeos-k8s-master.tar.gz $master_package_url
tar -zxvf domeos-k8s-master.tar.gz
chmod +x $current_path/flanneld
chmod +x $current_path/kube-apiserver
chmod +x $current_path/kube-controller-manager
chmod +x $current_path/kube-scheduler
chmod +x $current_path/kube-proxy
chmod +x $current_path/mk-docker-opts.sh
mkdir -p $current_path/logs

# STEP 05: check iface for flannel
flannel_iface=(`ip addr show | grep $host_ip | awk '{print $7}'`)
if [ "$flannel_iface" == "" ]; then
  echo -e "\033[31m[ERROR] get ip iface error\033[0m"
  exit 1
else
  flannel_iface=${flannel_iface[0]}
  echo -e "\033[36m[INFO] use flannel iface: $flannel_iface\033[0m"
fi

# STEP 06: add DNS server into resolv.conf 
echo -e "\033[36m[INFO] cluster DNS nameserver and search will be added into top of $resolv_file\033[0m"
echo "You may press Ctrl+C now to abort this script."
echo "waitting for 10 seconds..."
sleep 10
cluster_dns_search="default.svc.$cluster_domain svc.$cluster_domain $cluster_domain"
host_self_dns=
host_self_dns_p=0
while IFS='' read -r line || [[ -n "$line" ]]; do
  name_tmp=$(echo $line | cut -f1 -d ' ')
  value_tmp=$(echo $line | cut -f2- -d ' ')
  if [ "$name_tmp" == "nameserver" ]; then
    if [ "$cluster_dns" != "$value_tmp" ]; then
      host_self_dns[$host_self_dns_p]="$line"
      ((host_self_dns_p++))
    fi
  elif [ "$name_tmp" == "search" ]; then
    if [ "$cluster_dns_search" != "$value_tmp" ]; then
      host_self_dns[$host_self_dns_p]="$line"
      ((host_self_dns_p++))
    fi
  else
    host_self_dns[$host_self_dns_p]="$line"
    ((host_self_dns_p++))
  fi
done < $resolv_file
chattr -i $resolv_file
echo "search $cluster_dns_search" > $resolv_file
echo "nameserver $cluster_dns" >> $resolv_file
for i in "${host_self_dns[@]}"
do
  echo $i >> $resolv_file
done

# STEP 07: add hostname and IP address to /etc/hosts
exist_hosts=0
while IFS='' read -r line || [[ -n "$line" ]]; do
  ip_tmp=$(echo $line | cut -f1 -d ' ')
  hostname_tmp=$(echo $line | cut -f2 -d ' ')
  if [ "$host_ip" == "$ip_tmp" ]; then
    if [ "$host_hostname" == "$hostname_tmp" ]; then
      exist_hosts=1
      break
    fi
  fi
done < /etc/hosts
if [ $exist_hosts -eq 0 ]; then
  echo "$host_ip $host_hostname" >> /etc/hosts
fi

# STEP 08: set flannel parameters in etcd; install and configure flannel
flannel_k8s_config="{\"Network\": \"${flannel_network_ip_range}\", \"SubnetLen\": ${flannel_subnet_len}, \"Backend\": {\"Type\": \"vxlan\", \"VNI\": 1}}"
single_etcd_server=$(echo $etcd_servers | cut -f1 -d ',')
curl -L $single_etcd_server/v2/keys$flannel_prefix/config -XPUT -d value="${flannel_k8s_config}"
if command_exists flanneld && [ -e /usr/libexec/flannel/mk-docker-opts.sh ]; then
  echo -e "\033[36m[INFO] flanneld command already exists on this system.\033[0m"
  echo "/etc/sysconfig/flanneld /usr/lib/systemd/system/docker.service.d/flannel.conf and /lib/systemd/system/flanneld.service files will be reset"
  echo "You may press Ctrl+C now to abort this script."
  echo "waitting for 10 seconds..."
  sleep 10
else
  mkdir -p /usr/libexec/flannel
  mkdir -p /run/flannel
  mkdir -p /usr/lib/systemd/system/docker.service.d
  mv $current_path/flanneld /usr/bin/flanneld
  mv $current_path/mk-docker-opts.sh /usr/libexec/flannel/mk-docker-opts.sh
fi
  # check http:// prefix of etcd address
flannel_etcd_servers=
flannel_etcds=(${etcd_servers//,/ })
for i in ${flannel_etcds[@]}
do
  if [[ $i =~ "http://" ]] || [[ $i =~ "https://" ]]; then
    if [ "$flannel_etcd_servers" == "" ]; then
      flannel_etcd_servers="$i"
    else
      flannel_etcd_servers="$flannel_etcd_servers,$i"
    fi
  else
    if [ "$flannel_etcd_servers" == "" ]; then
      flannel_etcd_servers="http://$i"
    else
      flannel_etcd_servers="$flannel_etcd_servers,http://$i"
    fi
  fi
done
echo "FLANNEL_ETCD=\"$flannel_etcd_servers\"
FLANNEL_ETCD_KEY=\"$flannel_prefix\"
FLANNEL_OPTIONS=\"$flannel_opts -iface=$flannel_iface\"
" > /etc/sysconfig/flanneld
echo "[Service]
EnvironmentFile=-/run/flannel/docker" > /usr/lib/systemd/system/docker.service.d/flannel.conf
echo "[Unit]
Description=Flanneld overlay address etcd agent
After=network.target
After=network-online.target
Wants=network-online.target
After=etcd.service
Before=docker.service

[Service]
Type=notify
EnvironmentFile=/etc/sysconfig/flanneld
EnvironmentFile=-/etc/sysconfig/docker-network
ExecStart=/usr/bin/flanneld -etcd-endpoints=\${FLANNEL_ETCD} -etcd-prefix=\${FLANNEL_ETCD_KEY} \$FLANNEL_OPTIONS
ExecStartPost=/usr/libexec/flannel/mk-docker-opts.sh -k DOCKER_NETWORK_OPTIONS -d /run/flannel/docker
Restart=always

[Install]
WantedBy=multi-user.target
RequiredBy=docker.service
" > /lib/systemd/system/flanneld.service
if command_exists flanneld && [ -e /usr/libexec/flannel/mk-docker-opts.sh ]; then
  echo -e "\033[32m[OK] flannel environment is ready\033[0m"
else
  echo -e "\033[31m[ERROR] flannel environment is not ready\033[0m"
  exit 1
fi

# STEP 09: install and configure docker
if command_exists docker; then
  echo -e "\033[36m[INFO] docker command alrealy exists on this system.\033[0m"
  echo "/etc/sysconfig/docker and /lib/systemd/system/docker.service files will be reset."
  echo "You may press Ctrl+C now to abort this script."
  echo "waitting for 10 seconds..."
  sleep 10
else
  # TODO network offline
  #yum install -y docker-engine-selinux-1.10.2-1.el7.centos.noarch.rpm
  #yum install -y docker-engine-1.10.2-1.el7.centos.x86_64.rpm
  curl -sSL $docker_url | sh
fi
docker_opts="DOCKER_OPTS=\"$docker_opts\""
echo $docker_opts > /etc/sysconfig/docker
if [ "$insecure_docker_registry" != "" ]; then
  insecure_docker_registry=$(echo $insecure_docker_registry | sed -e 's/https:\/\///g')
  insecure_docker_registry=$(echo $insecure_docker_registry | sed -e 's/http:\/\///g')
  insecure_docker_registry="INSECURE_REGISTRY=\"--insecure-registry $insecure_docker_registry\""
  echo $insecure_docker_registry >> /etc/sysconfig/docker
fi
if [ "$docker_graph_path" != "" ]; then
  docker_storage_options="DOCKER_STORAGE_OPTIONS=\"--graph $docker_graph_path\""
  echo $docker_storage_options >> /etc/sysconfig/docker
fi
if [ "$secure_docker_registry" != "" ]; then
  secure_docker_registry=$(echo $secure_docker_registry | sed -e 's/https:\/\///g')
  secure_docker_registry=$(echo $secure_docker_registry | sed -e 's/http:\/\///g')
  mkdir -p $registry_crt_path/$secure_docker_registry
  cp $docker_registry_crt $registry_crt_path/$secure_docker_registry/registry.crt
  if [ -f $registry_crt_path/$secure_docker_registry/registry.crt ]; then
    echo -e "\033[32m[OK] install docker secure registry certification\033[0m"
  else
    echo -e "\033[31m[ERROR] install docker secure registry certification failed\033[0m"
    exit 1
  fi
  echo -e "\033[32m[OK] install docker registry certification\033[0m"
fi
echo "[Unit]
Description=Docker Application Container Engine
Documentation=https://docs.docker.com

[Service]
Type=notify
EnvironmentFile=/etc/sysconfig/docker
ExecStart=/usr/bin/docker daemon \$DOCKER_OPTS \\
\$DOCKER_STORAGE_OPTIONS \\
\$DOCKER_NETWORK_OPTIONS \\
\$ADD_REGISTRY \\
\$BLOCK_REGISTRY \\
\$INSECURE_REGISTRY

MountFlags=slave
LimitNOFILE=1048576
LimitNPROC=1048576
LimitCORE=infinity

[Install]
WantedBy=multi-user.target
" > /lib/systemd/system/docker.service
if command_exists docker ; then
  echo -e "\033[32m[OK] docker environment is ready\033[0m"
else
  echo -e "\033[31m[ERROR] docker environment is not ready\033[0m"
  exit 1
fi

# STEP 10: start flannel
systemctl stop docker
systemctl stop flanneld
ip link delete docker0
ip link delete flannel.1
systemctl disable iptables-services firewalld
systemctl stop iptables-services firewalld
systemctl daemon-reload
systemctl start flanneld
sleep 5
systemctl status -l flanneld

# STEP 11: start docker
systemctl start docker
sleep 10
systemctl status -l docker

# STEP 12: start kube-apiserver
systemctl stop kube-apiserver
echo "# configure file for kube-apiserver

# --etcd-servers
ETCD_SERVERS='--etcd-servers=$etcd_servers'
# --log-dir
LOG_DIR='--log-dir=$current_path/logs'
# --service-cluster-ip-range
SERVICE_CLUSTER_IP_RANGE='--service-cluster-ip-range=$service_cluster_ip_range'
# --insecure-bind-address
INSECURE_BIND_ADDRESS='--insecure-bind-address=$insecure_bind_address'
# --insecure-port
INSECURE_PORT='--insecure-port=$insecure_port'
# --bind-address
BIND_ADDRESS='--bind-address=$secure_bind_address'
# --secure-port
SECURE_PORT='--secure-port=$secure_port'
" > /etc/sysconfig/kube-apiserver
if [ "$authorization_mode" != "" ]; then
echo "# --authorization-mode
AUTHORIZATION_MODE='--authorization-mode=$authorization_mode'
" >> /etc/sysconfig/kube-apiserver
fi
if [ "$authorization_policy_file" != "" ]; then
echo "# --authorization-policy-file
AUTHORIZATION_FILE='--authorization-policy-file=$authorization_policy_file'
" >> /etc/sysconfig/kube-apiserver
fi
if [ "$basic_auth_file" != "" ]; then
echo "# --basic-auth-file
BASIC_AUTH_FILE='--basic-auth-file=$basic_auth_file'
" >> /etc/sysconfig/kube-apiserver
fi
echo "# other parameters
KUBE_APISERVER_OPTS='$kube_apiserver_opts'
" >> /etc/sysconfig/kube-apiserver
echo "[Unit]
Description=kube-apiserver

[Service]
EnvironmentFile=/etc/sysconfig/kube-apiserver
ExecStart=$current_path/kube-apiserver \$ETCD_SERVERS \\
          \$LOG_DIR \\
          \$SERVICE_CLUSTER_IP_RANGE \\
          \$INSECURE_BIND_ADDRESS \\
          \$INSECURE_PORT \\
          \$BIND_ADDRESS \\
          \$SECURE_PORT \\
          \$AUTHORIZATION_MODE \\
          \$AUTHORIZATION_FILE \\
          \$BASIC_AUTH_FILE \\
          \$KUBE_APISERVER_OPTS
Restart=always
" > /lib/systemd/system/kube-apiserver.service
systemctl daemon-reload
systemctl start kube-apiserver
sleep 10
systemctl status -l kube-apiserver

# STEP 13: start kube-controller-manager
systemctl stop kube-controller
echo "# configure file for kube-controller-manager

# --master
KUBE_MASTER='--master=http://$host_ip:$kube_apiserver_port'
# --log-dir
LOG_DIR='--log-dir=$current_path/logs'
# --cloud-provider
CLOUD_PROVIDER='--cloud-provider=$cloud_provider'
# other parameters
KUBE_CONTROLLER_OPTS='$kube_controller_manager_opts'
" > /etc/sysconfig/kube-controller
echo "[Unit]
Description=kube-controller-manager
After=kube-apiserver.service
Wants=kube-apiserver.service

[Service]
EnvironmentFile=/etc/sysconfig/kube-controller
ExecStart=$current_path/kube-controller-manager \$KUBE_MASTER \\
          \$LOG_DIR \\
          \$CLOUD_PROVIDER \\
          \$KUBE_CONTROLLER_OPTS
Restart=always
" > /lib/systemd/system/kube-controller.service
systemctl daemon-reload
systemctl start kube-controller
sleep 5
systemctl status -l kube-controller

# STEP 14: start kube-scheduler
systemctl stop kube-scheduler
echo "# configure file for kube-scheduler

# --master
KUBE_MASTER='--master=http://$host_ip:$kube_apiserver_port'
# --log-dir
LOG_DIR='--log-dir=$current_path/logs'
# other parameters
KUBE_SCHEDULER_OPTS='$kube_scheduler_opts'
" > /etc/sysconfig/kube-scheduler
echo "[Unit]
Description=kube-scheduler
After=kube-apiserver.service
Wants=kube-apiserver.service

[Service]
EnvironmentFile=/etc/sysconfig/kube-scheduler
ExecStart=$current_path/kube-scheduler \$KUBE_MASTER \\
          \$LOG_DIR \\
          \$KUBE_SCHEDULER_OPTS
Restart=always
" > /lib/systemd/system/kube-scheduler.service
systemctl daemon-reload
systemctl start kube-scheduler
sleep 5
systemctl status -l kube-scheduler

# STEP 15: start kube-proxy
systemctl stop kube-proxy
echo "# configure file for kube-proxy
# --master
KUBE_MASTER='--master=http://$host_ip:$kube_apiserver_port'
# --proxy-mode
PROXY_MODE='--proxy-mode=$proxy_mode'
# --log-dir
LOG_DIR='--log-dir=$current_path/logs'
# other parameters
KUBE_PROXY_OPTS='$kube_proxy_opts'
" > /etc/sysconfig/kube-proxy
echo "[Unit]
Description=kube-proxy

[Service]
EnvironmentFile=/etc/sysconfig/kube-proxy
ExecStart=$current_path/kube-proxy \$KUBE_MASTER \\
          \$PROXY_MODE \\
          \$LOG_DIR \\
          \$KUBE_PROXY_OPTS
Restart=on-failure
" > /lib/systemd/system/kube-proxy.service
systemctl daemon-reload
systemctl start kube-proxy
sleep 5
systemctl status -l kube-proxy
