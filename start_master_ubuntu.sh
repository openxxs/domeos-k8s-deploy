#!/bin/bash

# install and start kubernetes master on Ubuntu 12.04, 14.04, 15.10 and 16.04 system
# xiaoshengxu@sohu-inc.com
# http://domeos-script.bjctc.scs.sohucs.com/start_master_ubuntu.sh

AVAILABLE_K8S_VERSION=("1.1.3" "1.1.7" "1.2.0" "1.2.4")
AVAILABLE_FLANNEL_VERSION=("0.5.5")
K8S_VERSION="1.2.0"
FLANNEL_VERSION="0.5.5"
K8S_INSTALL_PATH="/usr/sbin/domeos/k8s"
FLANNEL_INSTALL_PATH="/usr/sbin/domeos/flannel"
K8S_PACKAGE_URL_PREFIX="http://domeos-binpack.bjcnc.scs.sohucs.com/k8s/"
FLANNEL_BIN_URL_PREFIX="http://domeos-binpack.bjcnc.scs.sohucs.com/flannel/"
DOCKER_URL="https://get.docker.com/"
RESOLV_FILE="/etc/resolv.conf"
RESOLV_CONF_HEAD="/etc/resolvconf/resolv.conf.d/head"
FLANNEL_PREFIX="/flannel/network"
DOCKER_REGISTRY_CRT_PATH="/etc/docker/certs.d"
DOCKER_OPTS="--log-level=warn"
FLANNEL_OPTS=
KUBE_APISERVER_OPTS=
KUBE_CONTROLLER_MANAGER_OPTS="--cloud-provider="
KUBE_SCHEDULER_OPTS=
KUBE_PROXY_OPTS="--masquerade-all=true --proxy-mode=iptables"

function command_exists ()
{
  command -v "$@" > /dev/null 2>&1
}

function help ()
{
  echo "
Usage:
  start_master_ubuntu.sh [options]
  start_master_ubuntu.sh [command]

Available Commands:
  help    show the help information about start_master_ubuntu.sh

Options:
  --cluster-dns                 IP address of cluster DNS, should be in range of --service-cluster-ip-range (default 172.16.40.1).
  --cluster-domain              search domain of cluster DNS (default domeos.local).
  --docker-graph-path           root of the Docker runtime (default /var/lib/docker).
  --docker-registry-crt         certification for docker private registry, it is required when --secure-docker-registry is set.
  --etcd-servers                (REQUIRED) a comma-delimited list of etcd servers to watch (http://ip:port).
  --flannel-network-ip-range    flannel network ip range (default 172.24.0.0/13).
  --flannel-subnet-len          flannel subnet length (default 22).
  --flannel-version             flannel version (default $FLANNEL_VERSION).
  --insecure-bind-address       IP address on which to serve kube-apiserver --insecure-port (default 0.0.0.0).
  --insecure-port               port on which to serve kube-apiserver unsecured, unauthenticated access (default 8080).
  --insecure-docker-registry    (REQUIRED) docker insecure registry communication address (ip:port).
  --kube-apiserver-port         port on which to serve kube-apiserver access for kube-proxy, kube-scheduler and kube-controller-manager (default 8080).
  --kubernetes-version          Kubernetes version (default $K8S_VERSION).
  --service-cluster-ip-range    a CIDR notation IP range from which to assign Kubernetes service cluster IPs. This must not overlap with any IP ranges assigned to nodes for pods (default 172.16.0.0/13).
  --secure-docker-registry      docker secure registry communication address (default "").
"
}

echo "
*************************************************************************
            Welcome to install DomeOS Kubernetes Master!
                Contact us: rdc-domeos@sohu-inc.com
*************************************************************************
This is a shell script for install, configure and start Kubernetes Master for DomeOS on Ubuntu 12.04, 14.04, 15.10 and 16.04. It will start flanneld, docker, kube-apiserver, kube-controller-manager, kube-scheduler and kube-proxy after successful execution.

Attention:
1. This shell will try to install the latest docker if docker has not been installed. You can install docker by yourself before execute this shell. Docker version must be 1.8.2 at minimum, version 1.10.3 is recommanded.
2. This shell will reset flannel and docker configure file.

Usage Example:
1. Simple options, use default values:
sudo bash start_master_ubuntu.sh --etcd-servers http://10.11.150.99:4012,http://10.11.150.100:4012,http://10.11.150.101:4012 --insecure-docker-registry 10.11.150.98:5000

2. Full options:
sudo bash start_master_ubuntu.sh --cluster-dns 172.16.40.1 --cluster-domain domeos.local --docker-graph-path /opt/domeos/openxxs/docker --docker-registry-crt /opt/domeos/openxxs/k8s-1.1.7-flannel/registry.crt --etcd-servers http://10.11.150.99:4012,http://10.11.150.100:4012,http://10.11.150.101:4012 --flannel-network-ip-range 172.24.0.0/13 --flannel-subnet-len 22 --flannel-version 0.5.5 --insecure-bind-address 0.0.0.0 --insecure-port 8080 --insecure-docker-registry 10.11.150.78:5000 --kube-apiserver-port 8080 --kubernetes-version 1.2.0 --service-cluster-ip-range 172.16.0.0/13 --secure-docker-registry https://private-registry.sohucs.com
"

if [[ "$1" =~ "help" ]] || [ -z "$1" ]; then
  help
  exit 1
fi

# STEP 01: check linux kernel version
echo -e "\033[36m[INFO] STEP 01: Check system kernel...\033[0m"
kernel_version=`uname -r`
if [ -z "$kernel_version" ]; then
  echo -e "\033[31m[ERROR] get kernel version error, kernel must be 3.10.0 at minimum\033[0m"
  exit 1
fi
kernel_parts_tmp=(${kernel_version//-/ })
kernel_parts=(${kernel_parts_tmp[0]//./ })
ubuntu_release=`lsb_release -a | grep "Release" | awk '{print $2}'`
ubuntu_codename=`lsb_release -a | grep "Codename" | awk '{print $2}'`
if [ "$ubuntu_release" == "12.04" ]; then
  if [ ${kernel_parts[0]} -lt 3 ]; then
    echo -e "\033[31m[ERROR] For Ubuntu Precise, Docker requires 3.13 kernel version at minimum, current version is ${kernel_parts_tmp[0]}\033[0m"
    exit 1
  fi
  if [ ${kernel_parts[0]} -eq 3 ] && [ ${kernel_parts[1]} -lt 13 ]; then
    echo -e "\033[31m[ERROR] For Ubuntu Precise, Docker requires 3.13 kernel version at minimum, current version is ${kernel_parts_tmp[0]}\033[0m"
    exit 1
  fi
elif [ "$ubuntu_release" == "14.04" ]||[ "$ubuntu_release" == "15.10" ]||[ "$ubuntu_release" == "16.04" ]; then
  if [ ${kernel_parts[0]} -lt 3 ]; then
    echo -e "\033[31m[ERROR] For Ubuntu $ubuntu_codename, Docker requires 3.10 kernel version at minimum, current version is ${kernel_parts_tmp[0]}\033[0m"
    exit 1
  fi
  if [ ${kernel_parts[0]} -eq 3 ] && [ ${kernel_parts[1]} -lt 10 ]; then
    echo -e "\033[31m[ERROR] For Ubuntu $ubuntu_codename, Docker requires 3.10 kernel version at minimum, current version is ${kernel_parts_tmp[0]}\033[0m"
    exit 1
  fi
else
  echo -e "\033[31m[ERROR] This installation script only supports Ubuntu 12.04, 14.04, 15.10 and 16.04, current ubuntu version is $ubuntu_release, you need to install docker, flannel and kubernetes by yourself\033[0m"
  exit 1
fi
echo -e "\033[32m[OK] Check kernel OK, current kernel version is ${kernel_parts_tmp[0]}\033[0m"

# STEP 02: check arguments
echo -e "\033[36m[INFO] STEP 02: Check input arguments...\033[0m"
OPTS=$(getopt -o : --long cluster-dns:,cluster-domain:,docker-graph-path:,docker-registry-crt:,etcd-servers:,flannel-network-ip-range:,flannel-subnet-len:,flannel-version:,insecure-bind-address:,insecure-port:,insecure-docker-registry:,kube-apiserver-port:,kubernetes-version:,service-cluster-ip-range:,secure-docker-registry: -- "$@")
if [ $? != 0 ]
then
  echo -e "\033[31m[ERROR] start_master_ubuntu.sh argument is illegal\033[0m"
  exit 1
fi
eval set -- "$OPTS"
cluster_dns=
cluster_domain=
docker_graph_path=
docker_registry_crt=
etcd_servers=
flannel_network_ip_range=
flannel_subnet_len=
flannel_version=
insecure_bind_address=
insecure_port=
insecure_docker_registry=
kube_apiserver_port=
kubernetes_version=
service_cluster_ip_range=
secure_docker_registry=
while true ; do
  case "$1" in
    --cluster-dns) cluster_dns=$2; shift 2;;
    --cluster-domain) cluster_domain=$2; shift 2;;
    --docker-graph-path) docker_graph_path=$2; shift 2;;
    --docker-registry-crt) docker_registry_crt=$2; shift 2;;
    --etcd-servers) etcd_servers=$2; shift 2;;
    --flannel-network-ip-range) flannel_network_ip_range=$2; shift 2;;
    --flannel-subnet-len) flannel_subnet_len=$2; shift 2;;
    --flannel-version) flannel_version=$2; shift 2;;
    --insecure-bind-address) insecure_bind_address=$2; shift 2;;
    --insecure-port) insecure_port=$2; shift 2;;
    --insecure-docker-registry) insecure_docker_registry=$2; shift 2;;
    --kube-apiserver-port) kube_apiserver_port=$2; shift 2;;
    --kubernetes-version) kubernetes_version=$2; shift 2;;
    --service-cluster-ip-range) service_cluster_ip_range=$2; shift 2;;
    --secure-docker-registry) secure_docker_registry=$2; shift 2;;
    --) shift; break;;
  esac
done
if [ -z "$cluster_dns" ]; then
  echo -e "\033[36m[INFO] --cluster-dns is absent, default '172.16.40.1'\033[0m"
  cluster_dns="172.16.40.1"
else
  echo "--cluster-dns: $cluster_dns"
fi
if [ -z "$cluster_domain" ]; then
  echo -e "\033[36m[INFO] --cluster-domain is absent, default 'domeos.local'\033[0m"
  cluster_domain="domeos.local"
else
  echo "--cluster-domain: $cluster_domain"
fi
if [ -z "$docker_graph_path" ]; then
  echo -e "\033[36m[INFO] --docker-graph-path is absent, default '/var/lib/docker'\033[0m"
  docker_graph_path="/var/lib/docker"
else
  echo "--docker-graph-path: $docker_graph_path"
fi
if [ -z "$etcd_servers" ]; then
  echo -e "\033[31m[ERROR] --etcd-servers is absent\033[0m"
  exit 1
else
  echo "--etcd-servers: $etcd_servers"
fi
if [ -z "$flannel_network_ip_range" ]; then
  echo -e "\033[36m[INFO] --flannel-network-ip-range is absent, default '172.24.0.0/13'\033[0m"
  flannel_network_ip_range='172.24.0.0/13'
else
  echo "--flannel-network-ip-range: $flannel_network_ip_range"
fi
if [ -z "$flannel_subnet_len" ]; then
  echo -e "\033[36m[INFO] --flannel-subnet-len is absent, default '22'\033[0m"
  flannel_subnet_len=22
else
  echo "--flannel-subnet-len: $flannel_subnet_len"
fi
if [ -z "$flannel_version" ]; then
  echo -e "\033[36m[INFO] --flannel-version is absent, default '$FLANNEL_VERSION'\033[0m"
  flannel_version=$FLANNEL_VERSION
else
  available="false"
  for i in ${AVAILABLE_FLANNEL_VERSION[@]} ; do
    if [ "$i" == "$flannel_version" ]; then
      available="true"
      break
    fi
  done
  if [ "$available" == "true" ]; then
    echo "--flannel-version: $flannel_version"
  else
    echo -e "\033[31m[ERROR] this shell script does not provide Flannel $flannel_version package\033[0m"
    exit 1
  fi
fi
if [ -z "$insecure_bind_address" ]; then
  echo -e "\033[36m[INFO] --insecure-bind-address is absent, default '0.0.0.0'\033[0m"
  insecure_bind_address='0.0.0.0'
else
  echo "--insecure-bind-address: $insecure_bind_address"
fi
if [ -z "$insecure_port" ]; then
  echo -e "\033[36m[INFO] --insecure-port is absent, default '8080'\033[0m"
  insecure_port=8080
else
  echo "--insecure-port: $insecure_port"
fi
if [ -z "$insecure_docker_registry" ]; then
  echo -e "\033[31m[ERROR] --insecure-docker-registry is absent\033[0m"
  exit 1
else
  echo "--insecure-docker-registry: $insecure_docker_registry"
fi
if [ -z "$kube_apiserver_port" ]; then
  echo -e "\033[36m[INFO] --kube-apiserver-port is absent, default '8080'\033[0m"
  kube_apiserver_port=8080
else
  echo "--kube-apiserver-port: $kube_apiserver_port"
fi
if [ -z "$kubernetes_version" ]; then
  echo -e "\033[36m[INFO] --kubernetes-version is absent, default '$K8S_VERSION'\033[0m"
  kubernetes_version=$K8S_VERSION
else
  available="false"
  for i in ${AVAILABLE_K8S_VERSION[@]} ; do
    if [ "$i" == "$kubernetes_version" ]; then
      available="true"
      break
    fi
  done
  if [ "$available" == "true" ]; then
    echo "--kubernetes-version: $kubernetes_version"
  else
    echo -e "\033[31m[ERROR] this shell script does not provide Kubernetes $kubernetes_version package\033[0m"
    exit 1
  fi
fi
if [ -z "$service_cluster_ip_range" ]; then
  echo -e "\033[36m[INFO] --service-cluster-ip-range is absent, default '172.16.0.0/13'\033[0m"
  service_cluster_ip_range='172.16.0.0/13'
else
  echo "--service-cluster-ip-range: $service_cluster_ip_range"
fi
if [ -n "$secure_docker_registry" ]; then
  echo "--secure-docker-registry: $secure_docker_registry"
  if [ -n "$docker_registry_crt" ] && [ -f $docker_registry_crt ]; then
    echo "--docker-registry-crt: $docker_registry_crt"
  else
    echo -e "\033[31m[ERROR] docker registry certificate $docker_registry_crt is not exist or permission denied\033[0m"
    exit 1
  fi
fi
echo -e "\033[32m[OK] start_master_ubuntu.sh arguments are legal\033[0m"

# STEP 03: check host IP
echo -e "\033[36m[INFO] STEP 03: Check host IP...\033[0m"
host_hostname=`hostname`
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
echo -e "\033[32m[OK] use host IP address: $host_ip\033[0m"

# STEP 04: download and decompress installation package
echo -e "\033[36m[INFO] STEP 04: Download and decompress installation package...\033[0m"
set -e
curl -o master.tgz "$K8S_PACKAGE_URL_PREFIX$kubernetes_version/master.tgz"
tar -zxvf master.tgz
curl -o flanneld "$FLANNEL_BIN_URL_PREFIX$flannel_version/flanneld"
curl -o mk-docker-opts.sh "$FLANNEL_BIN_URL_PREFIX$flannel_version/mk-docker-opts.sh"
chmod +x $current_path/master/kube-apiserver
chmod +x $current_path/master/kube-controller-manager
chmod +x $current_path/master/kube-scheduler
chmod +x $current_path/master/kube-proxy
chmod +x $current_path/master/kubectl
chmod +x $current_path/flanneld
chmod +x $current_path/mk-docker-opts.sh
mkdir -p $K8S_INSTALL_PATH/$kubernetes_version
mkdir -p $FLANNEL_INSTALL_PATH/$flannel_version
mkdir -p /usr/libexec/flannel
mkdir -p /run/flannel
mkdir -p /usr/lib/systemd/system/docker.service.d
mv $current_path/master/kube-apiserver $K8S_INSTALL_PATH/$kubernetes_version/
mv $current_path/master/kube-controller-manager $K8S_INSTALL_PATH/$kubernetes_version/
mv $current_path/master/kube-scheduler $K8S_INSTALL_PATH/$kubernetes_version/
mv $current_path/master/kube-proxy $K8S_INSTALL_PATH/$kubernetes_version/
mv $current_path/master/kubectl $K8S_INSTALL_PATH/$kubernetes_version/
ln -fsn $K8S_INSTALL_PATH/$kubernetes_version $K8S_INSTALL_PATH/current
mv $current_path/flanneld $FLANNEL_INSTALL_PATH/$flannel_version/
ln -fsn $FLANNEL_INSTALL_PATH/$flannel_version $FLANNEL_INSTALL_PATH/current
mv $current_path/mk-docker-opts.sh /usr/libexec/flannel/mk-docker-opts.sh
set +e
echo -e "\033[32m[OK] Download and place required files\033[0m"

# STEP 05: check iface for flannel
echo -e "\033[36m[INFO] STEP 05: Check iface for flannel...\033[0m"
flannel_iface=(`ip addr show | grep $host_ip | awk '{print $7}'`)
if [ -z "$flannel_iface" ]; then
  echo -e "\033[31m[ERROR] get ip iface error\033[0m"
  exit 1
else
  flannel_iface=${flannel_iface[0]}
  echo -e "\033[32m[OK] use flannel iface: $flannel_iface\033[0m"
fi

# STEP 06: add DNS server into resolv.conf and resolv.conf.d/head
echo -e "\033[36m[INFO] STEP 06: Cluster DNS nameserver and search will be added into top of $RESOLV_FILE and $RESOLV_CONF_HEAD\033[0m"
echo -e "\033[36mYou may press Ctrl+C now to abort this script.\033[0m"
echo -e "\033[36mwaitting for 10 seconds...\033[0m"
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
      let host_self_dns_p++
    fi
  elif [ "$name_tmp" == "search" ]; then
    if [ "$cluster_dns_search" != "$value_tmp" ]; then
      host_self_dns[$host_self_dns_p]="$line"
      let host_self_dns_p++
    fi
  else
    host_self_dns[$host_self_dns_p]="$line"
    let host_self_dns_p++
  fi
done < $RESOLV_FILE
set -e
echo "search $cluster_dns_search" > $RESOLV_FILE
echo "nameserver $cluster_dns" >> $RESOLV_FILE
for i in "${host_self_dns[@]}"
do
  echo $i >> $RESOLV_FILE
done
set +e
host_self_dns=
host_self_dns_p=0
while IFS='' read -r line || [[ -n "$line" ]]; do
  name_tmp=$(echo $line | cut -f1 -d ' ')
  value_tmp=$(echo $line | cut -f2- -d ' ')
  if [ "$name_tmp" == "nameserver" ]; then
    if [ "$cluster_dns" != "$value_tmp" ]; then
      host_self_dns[$host_self_dns_p]="$line"
      let host_self_dns_p++
    fi
  elif [ "$name_tmp" == "search" ]; then
    if [ "$cluster_dns_search" != "$value_tmp" ]; then
      host_self_dns[$host_self_dns_p]="$line"
      let host_self_dns_p++
    fi
  else
    host_self_dns[$host_self_dns_p]="$line"
    let host_self_dns_p++
  fi
done < $RESOLV_CONF_HEAD
set -e
echo "search $cluster_dns_search" > $RESOLV_CONF_HEAD
echo "nameserver $cluster_dns" >> $RESOLV_CONF_HEAD
for i in "${host_self_dns[@]}"
do
  echo $i >> $RESOLV_CONF_HEAD
done
set +e
echo -e "\033[32m[OK] Add DNS nameserver and search into $RESOLV_FILE and $RESOLV_CONF_HEAD\033[0m"

# STEP 07: add hostname and IP address to /etc/hosts
echo -e "\033[36m[INFO] STEP 07: Add hostname and IP address to /etc/hosts...\033[0m"
exist_hosts="false"
while IFS='' read -r line || [[ -n "$line" ]]; do
  ip_tmp=$(echo $line | cut -f1 -d ' ')
  hostname_tmp=$(echo $line | cut -f2 -d ' ')
  if [ "$host_ip" == "$ip_tmp" ]; then
    if [ "$host_hostname" == "$hostname_tmp" ]; then
      exist_hosts="true"
      break
    fi
  fi
done < /etc/hosts
set -e
if [ $exist_hosts == "false" ]; then
  echo "$host_ip $host_hostname" >> /etc/hosts
fi
set +e
echo -e "\033[32m[OK] Add hostname and IP address to /etc/hosts\033[0m"

# STEP 08: Configure flannel
echo -e "\033[36m[INFO] STEP 08: Configure Flannel...\033[0m"
flannel_k8s_config="{\"Network\": \"${flannel_network_ip_range}\", \"SubnetLen\": ${flannel_subnet_len}, \"Backend\": {\"Type\": \"vxlan\", \"VNI\": 1}}"
single_etcd_server=$(echo $etcd_servers | cut -f1 -d ',')
curl -L $single_etcd_server/v2/keys$FLANNEL_PREFIX/config -XPUT -d value="${flannel_k8s_config}"
if command_exists flanneld && [ -e /usr/libexec/flannel/mk-docker-opts.sh ]; then
  echo -e "\033[36m[INFO] flanneld command already exists on this system.\033[0m"
  if command_exists systemctl ; then
    echo -e "\033[36m/etc/sysconfig/flanneld, /usr/lib/systemd/system/docker.service.d/flannel.conf and /lib/systemd/system/flanneld.service files will be reset\033[0m"
  elif command_exists initctl ; then
    echo -e "\033[36m/etc/default/flanneld and /etc/init/flanneld.conf files will be reset\033[0m"
  else
    echo -e "\033[31m[ERROR] System should support systemctl(Systemd) or initctl(Upstart) if you want to add kubernetes node by start_master_ubuntu.sh.\033[0m"
    exit 1
  fi
  echo -e "\033[36m[INFO]You may press Ctrl+C now to abort this script.\033[0m"
  echo -e "\033[36m[INFO]waitting for 10 seconds...\033[0m"
  sleep 10
fi
  # check http:// prefix of etcd address
flannel_etcd_servers=
flannel_etcds=(${etcd_servers//,/ })
for i in ${flannel_etcds[@]}
do
  if [[ $i =~ "http://" ]] || [[ $i =~ "https://" ]]; then
    if [ -z "$flannel_etcd_servers" ]; then
      flannel_etcd_servers="$i"
    else
      flannel_etcd_servers="$flannel_etcd_servers,$i"
    fi
  else
    if [ -z "$flannel_etcd_servers" ]; then
      flannel_etcd_servers="http://$i"
    else
      flannel_etcd_servers="$flannel_etcd_servers,http://$i"
    fi
  fi
done
if command_exists systemctl ; then
  echo "FLANNEL_ETCD=\"$flannel_etcd_servers\"
FLANNEL_ETCD_KEY=\"$FLANNEL_PREFIX\"
FLANNEL_IFACE=\"$flannel_iface\"
FLANNEL_OPTIONS=\"$FLANNEL_OPTS\"
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
ExecStart=$FLANNEL_INSTALL_PATH/current/flanneld -etcd-endpoints=\${FLANNEL_ETCD} -etcd-prefix=\${FLANNEL_ETCD_KEY} -iface=\${FLANNEL_IFACE} \$FLANNEL_OPTIONS
ExecStartPost=/usr/libexec/flannel/mk-docker-opts.sh -k DOCKER_NETWORK_OPTIONS -d /run/flannel/docker
Restart=always

[Install]
WantedBy=multi-user.target
RequiredBy=docker.service
" > /lib/systemd/system/flanneld.service
elif command_exists initctl ; then
  echo "FLANNEL_ETCD=\"$flannel_etcd_servers\"
FLANNEL_ETCD_KEY=\"$FLANNEL_PREFIX\"
FLANNEL_IFACE=\"$flannel_iface\"
FLANNEL_OPTIONS=\"$FLANNEL_OPTS\"
" > /etc/default/flanneld
  echo "description \"Flannel service\"
author \"@domeos\"

start on (net-device-up
  and local-filesystems
  and runlevel [2345])
stop on runlevel [016]

respawn
respawn limit 3 10
pre-start script
    FLANNEL=$FLANNEL_INSTALL_PATH/current/\$UPSTART_JOB
    if [ -f /etc/default/\$UPSTART_JOB ]; then
        . /etc/default/\$UPSTART_JOB
    fi
    if [ -f \$FLANNEL ]; then
        exit 0
    fi
exit 22
end script

script
    # modify these in /etc/default/\$UPSTART_JOB (/etc/default/flanneld)
    FLANNEL=$FLANNEL_INSTALL_PATH/current/\$UPSTART_JOB
    FLANNEL_ETCD=\"\"
    FLANNEL_ETCD_KEY=\"\"
    FLANNEL_IFACE=\"\"
    FLANNEL_OPTIONS=\"\"
    if [ -f /etc/default/\$UPSTART_JOB ]; then
        . /etc/default/\$UPSTART_JOB
    fi
    exec \"\$FLANNEL\" -etcd-endpoints=\$FLANNEL_ETCD -etcd-prefix=\$FLANNEL_ETCD_KEY -iface=\$FLANNEL_IFACE \$FLANNEL_OPTIONS
end script
" > /etc/init/flanneld.conf
fi
if [ -e $FLANNEL_INSTALL_PATH/current/flanneld ] && [ -e /usr/libexec/flannel/mk-docker-opts.sh ]; then
  echo -e "\033[32m[OK] flannel environment is ready\033[0m"
else
  echo -e "\033[31m[ERROR] flannel environment is not ready\033[0m"
  exit 1
fi

# STEP 09: install docker
if command_exists docker; then
  echo -e "\033[36m[INFO] STEP 09: docker command alrealy exists on this system.\033[0m"
  if command_exists systemctl ; then
    echo -e "\033[36m/etc/sysconfig/docker and /lib/systemd/system/docker.service files will be reset.\033[0m"
  elif command_exists initctl ; then
    echo -e "\033[36m/etc/default/docker will be reset\033[0m"
  fi
  echo -e "\033[36mYou may press Ctrl+C now to abort this script.\033[0m"
  echo -e "\033[36mwaitting for 10 seconds...\033[0m"
  sleep 10
  docker_version=(`docker version | grep Version | awk '{print $2}'`)
    if [ -z "$docker_version" ]; then
    echo -e "\033[31m[ERROR] Get docker version error, your docker must be 1.8.2 at minimum\033[0m"
    exit 1
  fi
  docker_version_invalid="false"
  for i in ${docker_version[@]}; do
    version_parts=(${i//./ })
    if [ ${version_parts[0]} -lt 1 ]; then
      docker_version_invalid="true"
      break
    fi
    if [ ${version_parts[0]} -eq 1 ] && [ ${version_parts[1]} -lt 8 ]; then
      docker_version_invalid="true"
      break
    fi
    if [ ${version_parts[0]} -eq 1 ] && [ ${version_parts[1]} -eq 8 ] && [ ${version_parts[2]} -lt 2 ]; then
      docker_version_invalid="true"
      break
    fi
  done
  if [ $docker_version_invalid == "true" ]; then
    echo -e "\033[31m[ERROR] Docker server and client version must be 1.8.2 at minimum, current version is $i\033[0m"
    exit 1
  fi
else
  echo -e "\033[36m[INFO] STEP 09: Install and configure docker...\033[0m"
  docker_list_file="/etc/apt/sources.list.d/docker.list"
  docker_repo_url="https://apt.dockerproject.org/repo"
  apt-get update
  apt-get install -y apt-transport-https ca-certificates
  if [ "$ubuntu_release" == "14.04" ]||[ "$ubuntu_release" == "15.10" ]||[ "$ubuntu_release" == "16.04" ]; then
    apt-get install -y linux-image-extra-$kernel_version
  fi
  if [ "$ubuntu_release" == "12.04" ]||[ "$ubuntu_release" == "14.04" ]; then
    apt-get install -y apparmor
  fi
  apt-key adv --keyserver hkp://p80.pool.sks-keyservers.net:80 --recv-keys 58118E89F3A912897C070ADBF76221572C52609D
  if [ -f "$docker_list_file" ]; then
    rm -f $docker_list_file
  fi
  touch $docker_list_file
  echo "deb $docker_repo_url ubuntu-$ubuntu_codename main" > $docker_list_file
  apt-get update
  apt-get purge lxc-docker
  apt-cache policy docker-engine
  apt-get update
  apt-get install -y docker-engine
  set -e
  docker_version=(`docker version | grep Version | awk '{print $2}'`)
  set +e
  echo -e "\033[32m[OK] Docker has been installed, version ${docker_version[0]}\033[0m"
fi

# STEP 10: configure Docker
echo -e "\033[36m[INFO] STEP 10: Configure docker...\033[0m"
if [ -n "$insecure_docker_registry" ]; then
  insecure_docker_registry=$(echo $insecure_docker_registry | sed -e 's/https:\/\///g')
  insecure_docker_registry=$(echo $insecure_docker_registry | sed -e 's/http:\/\///g')
  insecure_docker_registry="--insecure-registry $insecure_docker_registry"
fi
if [ -n "$secure_docker_registry" ]; then
  secure_docker_registry=$(echo $secure_docker_registry | sed -e 's/https:\/\///g')
  secure_docker_registry=$(echo $secure_docker_registry | sed -e 's/http:\/\///g')
  mkdir -p $DOCKER_REGISTRY_CRT_PATH/$secure_docker_registry
  cp $docker_registry_crt $DOCKER_REGISTRY_CRT_PATH/$secure_docker_registry/registry.crt
  if [ -f $DOCKER_REGISTRY_CRT_PATH/$secure_docker_registry/registry.crt ]; then
    echo -e "\033[32m[OK] install docker secure registry certification\033[0m"
  else
    echo -e "\033[31m[ERROR] install docker secure registry certification failed\033[0m"
    exit 1
  fi
fi
docker_opts="$DOCKER_OPTS $insecure_docker_registry --graph $docker_graph_path"
if command_exists systemctl ; then
  docker_opts="DOCKER_OPTS=\"$docker_opts\""
  echo "
$docker_opts
" > /etc/sysconfig/docker
  echo "[Unit]
Description=Docker Application Container Engine
Documentation=https://docs.docker.com
After=network.target docker.socket
Requires=docker.socket

[Service]
Type=notify
EnvironmentFile=/etc/sysconfig/docker
ExecStart=/usr/bin/docker daemon \$DOCKER_OPTS \$DOCKER_NETWORK_OPTIONS -H fd://

MountFlags=slave
LimitNOFILE=1048576
LimitNPROC=1048576
LimitCORE=infinity
TimeoutStartSec=0
Delegate=yes

[Install]
WantedBy=multi-user.target
" > /lib/systemd/system/docker.service
elif command_exists initctl ; then
  docker_opts="DOCKER_OPTS=\"--bip=\${FLANNEL_SUBNET} --mtu=\${FLANNEL_MTU} --ip-masq=\${FLANNEL_IPMASQ} $docker_opts\""
  echo ". /run/flannel/subnet.env
$docker_opts
" > /etc/default/docker
fi
echo -e "\033[32m[OK] Docker environment is ready\033[0m"

# STEP 11: start flannel
echo -e "\033[36m[INFO] STEP 11: Start Flannel...\033[0m"
if command_exists systemctl ; then
  systemctl daemon-reload
  systemctl stop docker
  systemctl stop flanneld
  systemctl disable iptables-services firewalld
  systemctl stop iptables-services firewalld
  ip link delete docker0
  ip link delete flannel.1
  systemctl start flanneld
elif command_exists initctl ; then
  initctl stop docker
  initctl stop flanneld
  initctl stop iptables-services firewalld
  ip link delete docker0
  ip link delete flannel.1
  initctl start flanneld
fi
sleep 5

# STEP 12: start docker
echo -e "\033[36m[INFO] STEP 12: Start Docker...\033[0m"
if command_exists systemctl ; then
  systemctl start docker
elif command_exists initctl ; then
  initctl start docker
fi
sleep 8

# STEP 13: start kube-apiserver
echo -e "\033[36m[INFO] STEP 13: Start kube-apiserver...\033[0m"
if command_exists systemctl ; then
  systemctl stop kube-apiserver
  echo "# configure file for kube-apiserver

# --etcd-servers
ETCD_SERVERS='--etcd-servers=$etcd_servers'
# --service-cluster-ip-range
SERVICE_CLUSTER_IP_RANGE='--service-cluster-ip-range=$service_cluster_ip_range'
# --insecure-bind-address
INSECURE_BIND_ADDRESS='--insecure-bind-address=$insecure_bind_address'
# --insecure-port
INSECURE_PORT='--insecure-port=$insecure_port'
# other parameters
KUBE_APISERVER_OPTS='$KUBE_APISERVER_OPTS'
" > /etc/sysconfig/kube-apiserver
  echo "[Unit]
Description=kube-apiserver

[Service]
EnvironmentFile=/etc/sysconfig/kube-apiserver
ExecStart=$K8S_INSTALL_PATH/current/kube-apiserver \$ETCD_SERVERS \\
          \$SERVICE_CLUSTER_IP_RANGE \\
          \$INSECURE_BIND_ADDRESS \\
          \$INSECURE_PORT \\
          \$KUBE_APISERVER_OPTS
Restart=always
" > /lib/systemd/system/kube-apiserver.service
  systemctl daemon-reload
  systemctl start kube-apiserver
elif command_exists initctl ; then
  initctl stop kube-apiserver
  echo "ETCD_SERVERS='--etcd-servers=$etcd_servers'
SERVICE_CLUSTER_IP_RANGE='--service-cluster-ip-range=$service_cluster_ip_range'
INSECURE_BIND_ADDRESS='--insecure-bind-address=$insecure_bind_address'
INSECURE_PORT='--insecure-port=$insecure_port'
KUBE_APISERVER_OPTS='$KUBE_APISERVER_OPTS'
" > /etc/default/kube-apiserver
  echo "description \"kube-apiserver service\"
author \"@domeos\"

start on runlevel [2345]
stop on runlevel [!2345]

respawn

limit nofile 65536 65536

pre-start script
    KUBE_APISERVER=$K8S_INSTALL_PATH/current/\$UPSTART_JOB
    if [ -f /etc/default/\$UPSTART_JOB ]; then
        . /etc/default/\$UPSTART_JOB
    fi
    if [ -f \$KUBE_APISERVER ]; then
        exit 0
    fi
    exit 22
end script

script
    KUBE_APISERVER=$K8S_INSTALL_PATH/current/\$UPSTART_JOB\
    ETCD_SERVERS=\"\"
    SERVICE_CLUSTER_IP_RANGE=\"\"
    INSECURE_BIND_ADDRESS=\"\"
    INSECURE_PORT=\"\"
    KUBE_APISERVER_OPTS=\"\"
    if [ -f /etc/default/\$UPSTART_JOB ]; then
        . /etc/default/\$UPSTART_JOB
    fi
    exec \"\$KUBE_APISERVER\" \$ETCD_SERVERS \$SERVICE_CLUSTER_IP_RANGE \$INSECURE_BIND_ADDRESS \$INSECURE_PORT \$KUBE_APISERVER_OPTS
end script
" > /etc/init/kube-apiserver.conf
  initctl start kube-apiserver
fi
sleep 10

# STEP 14: start kube-controller-manager
echo -e "\033[36m[INFO] STEP 14: Start kube-controller-manager...\033[0m"
if command_exists systemctl ; then
  systemctl stop kube-controller
  echo "# configure file for kube-controller-manager

# --master
KUBE_MASTER='--master=http://$host_ip:$kube_apiserver_port'
# other parameters
KUBE_CONTROLLER_OPTS='$KUBE_CONTROLLER_MANAGER_OPTS'
" > /etc/sysconfig/kube-controller
  echo "[Unit]
Description=kube-controller-manager
After=kube-apiserver.service
Wants=kube-apiserver.service

[Service]
EnvironmentFile=/etc/sysconfig/kube-controller
ExecStart=$K8S_INSTALL_PATH/current/kube-controller-manager \$KUBE_MASTER \\
          \$KUBE_CONTROLLER_OPTS
Restart=always
" > /lib/systemd/system/kube-controller.service
  systemctl daemon-reload
  systemctl start kube-controller
elif command_exists initctl ; then
  initctl stop kube-controller
  echo "KUBE_MASTER='--master=http://$host_ip:$kube_apiserver_port'
KUBE_CONTROLLER_OPTS='$KUBE_CONTROLLER_MANAGER_OPTS'
" > /etc/default/kube-controller
  echo "description \"kube-controller service\"
author \"@domeos\"

start on started kube-apiserver
stop on runlevel [!2345]

respawn

limit nofile 65536 65536

pre-start script
    KUBE_CONTROLLER=$K8S_INSTALL_PATH/current/\$UPSTART_JOB-manager
    if [ -f /etc/default/\$UPSTART_JOB ]; then
        . /etc/default/\$UPSTART_JOB
    fi
    if [ -f \$KUBE_CONTROLLER ]; then
        exit 0
    fi
    exit 22
end script

script
    KUBE_CONTROLLER=$K8S_INSTALL_PATH/current/\$UPSTART_JOB-manager
    KUBE_MASTER=\"\"
    KUBE_CONTROLLER_OPTS=\"\"
    if [ -f /etc/default/\$UPSTART_JOB ]; then
        . /etc/default/\$UPSTART_JOB
    fi
    exec \"\$KUBE_CONTROLLER\" \$KUBE_MASTER \$KUBE_CONTROLLER_OPTS
end script
" > /etc/init/kube-controller.conf
fi
  initctl start kube-controller
sleep 5

# STEP 15: start kube-scheduler
echo -e "\033[36m[INFO] STEP 15: Start kube-scheduler...\033[0m"
if command_exists systemctl ; then
  systemctl stop kube-scheduler
  echo "# configure file for kube-scheduler

# --master
KUBE_MASTER='--master=http://$host_ip:$kube_apiserver_port'
# other parameters
KUBE_SCHEDULER_OPTS='$KUBE_SCHEDULER_OPTS'
" > /etc/sysconfig/kube-scheduler
  echo "[Unit]
Description=kube-scheduler
After=kube-apiserver.service
Wants=kube-apiserver.service

[Service]
EnvironmentFile=/etc/sysconfig/kube-scheduler
ExecStart=$K8S_INSTALL_PATH/current/kube-scheduler \$KUBE_MASTER \\
          \$KUBE_SCHEDULER_OPTS
Restart=always
" > /lib/systemd/system/kube-scheduler.service
  systemctl daemon-reload
  systemctl start kube-scheduler
elif command_exists initctl ; then
  initctl stop kube-scheduler
  echo "KUBE_MASTER='--master=http://$host_ip:$kube_apiserver_port'
KUBE_SCHEDULER_OPTS='$KUBE_SCHEDULER_OPTS'
" > /etc/default/kube-scheduler
  echo "description \"kube-scheduler service\"
author \"@domeos\"

start on started kube-apiserver
stop on runlevel [!2345]

respawn

limit nofile 65536 65536

pre-start script
    KUBE_SCHEDULER=$K8S_INSTALL_PATH/current/\$UPSTART_JOB
    if [ -f /etc/default/\$UPSTART_JOB ]; then
        . /etc/default/\$UPSTART_JOB
    fi
    if [ -f \$KUBE_SCHEDULER ]; then
        exit 0
    fi
    exit 22
end script

script
    KUBE_SCHEDULER=$K8S_INSTALL_PATH/current/\$UPSTART_JOB\
    KUBE_MASTER=\"\"
    KUBE_SCHEDULER_OPTS=\"\"
    if [ -f /etc/default/\$UPSTART_JOB ]; then
        . /etc/default/\$UPSTART_JOB
    fi
    exec \"\$KUBE_SCHEDULER\" \$KUBE_MASTER \$KUBE_SCHEDULER_OPTS
end script
" > /etc/init/kube-scheduler.conf
  initctl start kube-scheduler
fi
sleep 5

# STEP 16: start kube-proxy
echo -e "\033[36m[INFO] STEP 16: Start kube-proxy...\033[0m"
if command_exists systemctl ; then
  systemctl stop kube-proxy
  echo "# configure file for kube-proxy
# --master
KUBE_MASTER='--master=http://$host_ip:$kube_apiserver_port'
# other parameters
KUBE_PROXY_OPTS='$KUBE_PROXY_OPTS'
" > /etc/sysconfig/kube-proxy
  echo "[Unit]
Description=kube-proxy

[Service]
EnvironmentFile=/etc/sysconfig/kube-proxy
ExecStart=$K8S_INSTALL_PATH/current/kube-proxy \$KUBE_MASTER \\
          \$KUBE_PROXY_OPTS
Restart=on-failure
" > /lib/systemd/system/kube-proxy.service
  systemctl daemon-reload
  systemctl start kube-proxy
elif command_exists initctl ; then
  initctl stop kube-proxy
  echo "KUBE_MASTER='--master=http://$host_ip:$kube_apiserver_port'
KUBE_PROXY_OPTS='$KUBE_PROXY_OPTS'
" > /etc/default/kube-proxy
  echo "description \"kube-proxy service\"
author \"@domeos\"

start on started kube-apiserver
stop on runlevel [!2345]

respawn

limit nofile 65536 65536

pre-start script
    KUBE_PROXY=$K8S_INSTALL_PATH/current/\$UPSTART_JOB
    if [ -f /etc/default/\$UPSTART_JOB ]; then
        . /etc/default/\$UPSTART_JOB
    fi
    if [ -f \$KUBE_PROXY ]; then
        exit 0
    fi
    exit 22
end script

script
    KUBE_PROXY=$K8S_INSTALL_PATH/current/\$UPSTART_JOB\
    KUBE_MASTER=\"\"
    KUBE_PROXY_OPTS=\"\"
    if [ -f /etc/default/\$UPSTART_JOB ]; then
        . /etc/default/\$UPSTART_JOB
    fi
    exec \"\$KUBE_PROXY\" \$KUBE_MASTER \$KUBE_PROXY_OPTS
end script
" > /etc/init/kube-proxy.conf
  initctl start kube-proxy
fi
sleep 5