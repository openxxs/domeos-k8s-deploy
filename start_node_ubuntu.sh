#!/bin/bash

# start kubernetes node for DomeOS in Ubuntu server system
# openxxs@gmail.com
# 2016-05-26
# update 2016-06-01: add heartbeat parameter
# update 2016-06-06: add kubernetes and flannel version
# update 2016-06-08: add help info; remove --start-agent

AVAILABLE_K8S_VERSION=("1.1.3" "1.1.7" "1.2.0" "1.2.4")
AVAILABLE_K8S_FLANNEL_VERSION=("0.5.5")
K8S_VERSION="1.2.0"
FLANNEL_VERSION="0.5.5"
K8S_INSTALL_PATH="/usr/sbin/domeos/k8s"
FLANNEL_INSTALL_PATH="/usr/sbin/domeos/flannel"
K8S_PACKAGE_URL_PREFIX="http://domeos-binpack.bjcnc.scs.sohucs.com/k8s/"
FLANNEL_BIN_URL_PREFIX="http://domeos-binpack.bjcnc.scs.sohucs.com/flannel/"
RESOLV_FILE="/etc/resolv.conf"
RESOLV_CONF_HEAD="/etc/resolvconf/resolv.conf.d/head"
FLANNEL_PREFIX="/flannel/network"
DOCKER_REGISTRY_CRT_PATH="/etc/docker/certs.d"
DOCKER_REGISTRY_CRT_URL="/api/global/registry/private/certification"
DOCKER_LIST_FILE="/etc/apt/sources.list.d/docker.list"
DOCKER_REPO_URL="https://apt.dockerproject.org/repo"
DOMEOS_AGENT_IMAGE="pub.domeos.org/domeos/agent:2.5"
DOCKER_OPTS=
FLANNEL_OPTS=
KUBE_PROXY_OPTS="--masquerade-all=true --proxy-mode=iptables"
KUBELET_OPTS="--max-pods=70 --pod-infra-container-image=pub.domeos.org/kubernetes/pause:latest"

function command_exists ()
{
  command -v "$@" > /dev/null 2>&1
}

function help ()
{
  echo "
Usage:
  start_node_ubuntu.sh [options]
  start_node_ubuntu.sh [command]

Available Commands:
  help    show the help information about start_node_ubuntu.sh

Options:
  --api-server            (REQUIRED) kube-apiserver address ('ip:port').
  --cluster-dns           IP address of cluster DNS, should be in range of --service-cluster-ip-range (default 172.16.40.1).
  --cluster-domain        search domain of cluster DNS (default domeos.local).
  --docker-graph-path     root of the Docker runtime (default /var/lib/docker).
  --docker-log-level      Docker logger level (default 'warn', available value {'debug', 'info', 'warn', 'error', 'fatal'}).
  --domeos-server         DomeOS server address, it is required when --registry-type=https.
  --etcd-server           (REQUIRED) a comma-delimited list of etcd endpoints ('http://IP:Port').
  --flannel-version       Flannel version (default $FLANNEL_VERSION).
  --heartbeat-addr        heartbeat server address for starting agent.
  --hostname-override     if non-empty, will use this string as identification instead of the actual hostname.
  --k8s-data-dir          directory path for managing kubelet files (default '/var/lib/kubelet').
  --kubernetes-version    Kubernetes version (default $K8S_VERSION).
  --monitor-transfer      monitor transfer address for starting agent, it is required when --heartbeat-addr is set.
  --node-labels           labels for node.
  --registry-type         (REQUIRED) Docker registry type (available value {'http', 'https'}).
  --registry-arg          (REQUIRED) Docker secure registry communication address for --registry-type=https; Docker insecure registry communication address for --registry-type=http.
"
}

echo "
***************************************************************************
               Welcome to install DomeOS Kubernetes Node!
                  Contact us: rdc-domeos@sohu-inc.com
***************************************************************************
This is a shell script for install, configure and start Kubernetes Node for DomeOS on Ubuntu 12.04, 14.04, 15.10 and 16.04. It will start flanneld, docker, kube-proxy and kubelet after successful execution.

Attention:
1. This shell will try to install the latest docker if docker has not been installed. You can install docker by yourself before execute this shell. Docker version must be 1.8.2 at minimum, version 1.10.3 is recommanded.
2. This shell will reset flannel and docker configure file, and modify DNS configure of host.
3. Use 'bash start_node_ubuntu.sh help' to get more information.

Usage Example:
sudo bash start_node_ubuntu.sh --api-server http://0.0.0.0:8080 --cluster-dns 172.16.40.1 --cluster-domain domeos.local --docker-graph-path /opt/domeos/openxxs/docker-graph --docker-log-level warn --domeos-server 0.0.0.0:8080 --etcd-server http://0.0.0.0:4012,http://0.0.0.1:4012,http://0.0.0.2:4012 --flannel-version 0.5.5 --heartbeat-addr 0.0.0.0:6030 --hostname-override my-host --k8s-data-dir /opt/domeos/openxxs/k8s-data --kubernetes-version 1.2.0 --monitor-transfer 0.0.0.0:8433,0.0.0.1:8433 --node-labels TESTENV=HOSTENVTYPE,PRODENV=HOSTENVTYPE --registry-type http --registry-arg 0.0.0.0:5000
"

if [[ "$1" =~ "help" ]]; then
  help
  exit 1
fi

# STEP 01: check linux kernel version
echo -e "\033[36m[INFO] STEP 01: Check linux kernel version...\033[0m"
kernel_version=`uname -r`
if [ -z "$kernel_version" ]; then
  echo -e "\033[31m[ERROR] Get kernel version error, kernel must be 3.10.0 at minimum\033[0m"
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
OPTS=$(getopt -o : --long api-server:,cluster-dns:,cluster-domain:,docker-graph-path:,docker-log-level:,domeos-server:,etcd-server:,flannel-version:,heartbeat-addr:,hostname-override:,k8s-data-dir:,kubernetes-version:,monitor-transfer:,node-labels:,registry-type:,registry-arg: -- "$@")
if [ $? != 0 ]
then
  echo -e "\033[31m[ERROR] start_node_ubuntu.sh argument is illegal\033[0m"
  exit 1
fi
eval set -- "$OPTS"
api_server=
cluster_dns=
cluster_domain=
docker_graph_path=
docker_log_level=
domeos_server=
etcd_server=
flannel_version=
heartbeat_addr=
hostname_override=
k8s_data_dir=
kubernetes_version=
monitor_transfer=
node_labels=
registry_type=
registry_arg=
while true ; do
  case "$1" in
    --api-server) api_server=$2; shift 2;;
    --cluster-dns) cluster_dns=$2; shift 2;;
    --cluster-domain) cluster_domain=$2; shift 2;;
    --docker-graph-path) docker_graph_path=$2; shift 2;;
    --docker-log-level) docker_log_level=$2; shift 2;;
    --domeos-server) domeos_server=$2; shift 2;;
    --etcd-server) etcd_server=$2; shift 2;;
    --flannel-version) flannel_version=$2; shift 2;;
    --heartbeat-addr) heartbeat_addr=$2; shift 2;;
    --hostname-override) hostname_override=$2; shift 2;;
    --k8s-data-dir) k8s_data_dir=$2; shift 2;;
    --kubernetes-version) kubernetes_version=$2; shift 2;;
    --monitor-transfer) monitor_transfer=$2; shift 2;;
    --node-labels) node_labels=$2; shift 2;;
    --registry-type) registry_type=$2; shift 2;;
    --registry-arg) registry_arg=$2; shift 2;;
    --) shift; break;;
  esac
done
if [ -z "$api_server" ]; then
  echo -e "\033[31m[ERROR] --api-server is absent\033[0m"
  exit 1
else
  echo "--api-server: $api_server"
fi
if [ -z "$cluster_dns" ]; then
  echo -e "\033[36m[INFO] --cluster-dns is absent, default '172.16.40.1'\033[0m"
  cluster_dns="172.16.40.1"
else
  cluster_dns_check=`echo $cluster_dns | grep ':' | wc | awk '{print $3}'`
  if [ $cluster_dns_check -gt 0 ]; then
    echo -e "\033[33m[WARN] --cluster-dns $cluster_dns includes port, it is illegal\033[0m"
    cluster_dns=`echo $cluster_dns | cut -f1 -d ':'`
    echo -e "\033[36m[INFO] use '--cluster-dns $cluster_dns' instead, DNS port always be 53\033[0m"
  else
    echo "--cluster-dns: $cluster_dns"
  fi
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
if [ -z "$docker_log_level" ]; then
  echo -e "\033[36m[INFO] --docker-log-level is absent, default 'warn'\033[0m"
  docker_log_level="warn"
else
  echo "--docker-log-level: $docker_log_level"
fi
if [ -z "$domeos_server" ]; then
  if [ "$registry_type" == "https" ]; then
    echo -e "\033[31m[ERROR] --domeos-server is absent. This shell needs to curl docker registry certification from DomeOS server if you set '--registry-type https'\033[0m"
    exit 1
  fi
else
  echo "--domeos-server: $domeos_server"
fi
if [ -z "$etcd_server" ]; then
  echo -e "\033[31m[ERROR] --etcd-server is absent\033[0m"
  exit 1
else
  echo "--etcd-server: $etcd_server"
fi
if [ -z "$flannel_version" ]; then
  echo -e "\033[36m[INFO] --flannel-version is absent, default '$FLANNEL_VERSION'\033[0m"
  flannel_version=$FLANNEL_VERSION
else
  available="false"
  for i in ${AVAILABLE_K8S_FLANNEL_VERSION[@]} ; do
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
if [ -z "$monitor_transfer" ]; then
  echo -e "\033[31m[ERROR] --monitor-transfer is absent, --monitor-transfer is required when --heartbeat-addr is set.\033[0m"
  exit 1
else
  echo "--heartbeat-addr: $heartbeat_addr"
fi
if [ -z "$hostname_override" ]; then
  echo -e "\033[36m[INFO] --hostname-override is absent, default $(hostname)\033[0m"
  hostname_override=$(hostname)
else
  echo "--hostname-override: $hostname_override"
fi
if [ -z "$k8s_data_dir" ]; then
  echo -e "\033[36m[INFO] --k8s-data-dir is absent, default '/var/lib/kubelet'\033[0m"
  k8s_data_dir="/var/lib/kubelet"
else
  echo "--k8s-data-dir: $k8s_data_dir"
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
echo "--monitor-transfer: $monitor_transfer"
echo "--node-labels: $node_labels"
if [ -z "$registry_type" ]; then
  echo -e "\033[31m[ERROR] --registry-type is absent\033[0m"
  exit 1
else
  echo "--registry-type: $registry_type"
fi
if [ -z "$registry_arg" ]; then
  echo -e "\033[31m[ERROR] --registry-arg is absent\033[0m"
  exit 1
else
  echo "--registry-arg: $registry_arg"
fi
echo -e "\033[32m[OK] start_node_ubuntu.sh arguments are legal\033[0m"

# STEP 03: check ip
echo -e "\033[36m[INFO] STEP 03: Check node IP...\033[0m"
node_ips=(`ip addr show | grep inet | grep -v inet6 | grep brd | awk '{print $2}' | cut -f1 -d '/'`)
if [ -z "$node_ips" ]; then
  echo -e "\033[31m[ERROR] get node ip address error\033[0m"
  exit 1
fi
node_ip=
for i in ${node_ips[@]}
do
  ip_parts=(${i//./ })
  if [ ${ip_parts[0]} -eq 10 ]; then
    node_ip=$i
    break
  fi
  if [ ${ip_parts[0]} -eq 172 ] && [ ${ip_parts[1]} -ge 16 ]; then
    node_ip=$i
    break
  fi
  if [ ${ip_parts[0]} -eq 192 ] && [ ${ip_parts[1]} -eq 168 ]; then
    node_ip=$i
    break
  fi
done
if [ -z "$node_ip" ]; then
  node_ip=${node_ips[0]}
fi
echo -e "\033[32m[OK] use node IP address: $node_ip\033[0m"

# STEP 04: check hostname (DNS roles)
echo -e "\033[36m[INFO] STEP 04: Check node hostname...\033[0m"
node_hostname=$hostname_override
hostname_cnt=`echo $node_hostname | grep '^[0-9a-zA-Z-]*$' | wc | awk '{print $3}'`
if [ $hostname_cnt -le 0 ]; then
  echo -e "\033[31m[ERROR] node hostname used for DomeOS is illegal (^[0-9a-zA-Z-]*$), you can use change_hostname.sh(http://domeos-script.bjctc.scs.sohucs.com/change_hostname.sh) to assign a new hostname for node, or set --hostname-override parameter for start_node_ubuntu.sh\033[0m"
  exit 1
elif [ $hostname_cnt -ge 64 ]; then
    echo -e "\033[31m[ERROR] node hostname is longer than 63 chars\033[0m"
    exit 1
fi
echo -e "\033[32m[OK] Node hostname is legal\033[0m"

# STEP 05: get iface for flannel
echo -e "\033[36m[INFO] STEP 05: Get iface for Flannel...\033[0m"
flannel_iface=(`ip addr show | grep $node_ip | awk '{print $7}'`)
if [ -z "$flannel_iface" ]; then
  echo -e "\033[31m[ERROR] fail to get iface for Flannel\033[0m"
  exit 1
else
  flannel_iface=${flannel_iface[0]}
  echo -e "\033[32m[OK] use flannel iface: $flannel_iface\033[0m"
fi

# STEP 06: download and decompress installation package
echo -e "\033[36m[INFO] STEP 06: Download and decompress installation package...\033[0m"
set -e
current_path=$(pwd)
curl -o node.tgz "$K8S_PACKAGE_URL_PREFIX$kubernetes_version/node.tgz"
tar -zxvf node.tgz
curl -o flanneld "$FLANNEL_BIN_URL_PREFIX$flannel_version/flanneld"
curl -o mk-docker-opts.sh "$FLANNEL_BIN_URL_PREFIX$flannel_version/mk-docker-opts.sh"
chmod +x $current_path/node/kube-proxy
chmod +x $current_path/node/kubelet
chmod +x $current_path/node/kubectl
chmod +x $current_path/flanneld
chmod +x $current_path/mk-docker-opts.sh
mkdir -p $K8S_INSTALL_PATH/$kubernetes_version
mkdir -p $FLANNEL_INSTALL_PATH/$flannel_version
mv $current_path/node/kube-proxy $K8S_INSTALL_PATH/$kubernetes_version/
mv $current_path/node/kubelet $K8S_INSTALL_PATH/$kubernetes_version/
mv $current_path/node/kubectl $K8S_INSTALL_PATH/$kubernetes_version/
ln -fsn $K8S_INSTALL_PATH/$kubernetes_version $K8S_INSTALL_PATH/current
mv $current_path/flanneld $FLANNEL_INSTALL_PATH/$flannel_version/
ln -fsn $FLANNEL_INSTALL_PATH/$flannel_version $FLANNEL_INSTALL_PATH/current
set +e
echo -e "\033[32m[OK] Download and place required files\033[0m"

# STEP 07: add hostname and IP address into hosts
echo -e "\033[36m[INFO] STEP 07: Add /etc/hosts record...\033[0m"
exist_hosts=0
while IFS='' read -r line || [[ -n "$line" ]]; do
  ip_tmp=$(echo $line | cut -f1 -d ' ')
  hostname_tmp=$(echo $line | cut -f2 -d ' ')
  if [ "$node_ip" == "$ip_tmp" ]; then
    if [ "$node_hostname" == "$hostname_tmp" ]; then
      exist_hosts=1
      break
    fi
  fi
done < /etc/hosts
if [ $exist_hosts -eq 0 ]; then
  echo "$node_ip $node_hostname" >> /etc/hosts
fi
echo -e "\033[32m[OK] /etc/hosts has been updated\033[0m"

# STEP 08: add DNS server into resolv.conf and resolv.conf.d/head
echo -e "\033[36m[INFO] STEP 08: Cluster DNS nameserver and search will be added into top of $RESOLV_FILE and $RESOLV_CONF_HEAD\033[0m"
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

# STEP 09: Configure flannel
echo -e "\033[36m[INFO] STEP 09: Configure Flannel...\033[0m"
if command_exists flanneld ; then
  echo -e "\033[36m[INFO] flanneld command already exists on this system.\033[0m"
  if command_exists systemctl ; then
    echo -e "\033[36m/etc/sysconfig/flanneld and /lib/systemd/system/flanneld.service files will be reset\033[0m"
  elif command_exists initctl ; then
    echo -e "\033[36m/etc/default/flanneld and /etc/init/flanneld.conf files will be reset\033[0m"
  else
    echo -e "\033[31m[ERROR] System should support systemctl(Systemd) or initctl(Upstart) if you want to add kubernetes node by start_node_ubuntu.sh.\033[0m"
    exit 1
  fi
  echo -e "\033[36mYou may press Ctrl+C now to abort this script.\033[0m"
  echo -e "\033[36mWaitting for 10 seconds...\033[0m"
  sleep 10
fi
  # check http:// prefix of etcd address
flannel_etcd_servers=
flannel_etcds=(${etcd_server//,/ })
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
  mkdir -p /etc/sysconfig
  mkdir -p /usr/libexec/flannel
  mkdir -p /usr/lib/systemd/system/docker.service.d
  mv $current_path/mk-docker-opts.sh /usr/libexec/flannel/mk-docker-opts.sh
  echo "FLANNEL_ETCD=\"$flannel_etcd_servers\"
FLANNEL_ETCD_KEY=\"$FLANNEL_PREFIX\"
FLANNEL_IFACE=\"$flannel_iface\"
FLANNEL_OPTIONS=\"$FLANNEL_OPTS\"
" > /etc/sysconfig/flanneld
  echo "[Service]
EnvironmentFile=/run/flannel/docker
" > /usr/lib/systemd/system/docker.service.d/flannel.conf
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
if [ -e $FLANNEL_INSTALL_PATH/current/flanneld ] ; then
  echo -e "\033[32m[OK] flannel environment is ready\033[0m"
else
  echo -e "\033[31m[ERROR] flannel environment is not ready\033[0m"
  exit 1
fi

# STEP 10: install docker
if command_exists docker ; then
  echo -e "\033[36m[INFO] docker command already exists on this system.\033[0m"
  if command_exists systemctl ; then
    echo -e "\033[36m[/etc/sysconfig/docker and /lib/systemd/system/docker.service files will be reset.\033[0m"
  elif command_exists initctl ; then
    echo -e "\033[36m/etc/default/docker will be reset\033[0m"
  fi
  echo -e "\033[36m[You may press Ctrl+C now to abort this script.\033[0m"
  echo -e "\033[36m[waitting for 10 seconds...\033[0m"
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
  echo -e "\033[36m[INFO] STEP 10: Install Docker...\033[0m"
  apt-get update
  apt-get install -y apt-transport-https ca-certificates
  if [ "$ubuntu_release" == "14.04" ]||[ "$ubuntu_release" == "15.10" ]||[ "$ubuntu_release" == "16.04" ]; then
    apt-get install -y linux-image-extra-$kernel_version
  fi
  if [ "$ubuntu_release" == "12.04" ]||[ "$ubuntu_release" == "14.04" ]; then
    apt-get install -y apparmor
  fi
  apt-key adv --keyserver hkp://p80.pool.sks-keyservers.net:80 --recv-keys 58118E89F3A912897C070ADBF76221572C52609D
  if [ -f "$DOCKER_LIST_FILE" ]; then
    rm -f $DOCKER_LIST_FILE
  fi
  touch $DOCKER_LIST_FILE
  echo "deb $DOCKER_REPO_URL ubuntu-$ubuntu_codename main" > $DOCKER_LIST_FILE
  apt-get update
  apt-get purge lxc-docker
  apt-cache policy docker-engine
  apt-get update
  apt-get install -y docker-engine
  set -e
  docker_version=(`docker version | grep Version | awk '{print $2}'`)
  set +e
  echo -e "\033[32m[OK] Docker ${docker_version[0]} has been installed\033[0m"
fi

# STEP 11: Configure Docker
echo -e "\033[36m[INFO] STEP 11: Configure Docker...\033[0m"
docker_opts="$DOCKER_OPTS"
if [ "$registry_type" == "http" ]; then
  registry_arg=$(echo $registry_arg | sed -e 's/https:\/\///g')
  registry_arg=$(echo $registry_arg | sed -e 's/http:\/\///g')
  if [ -n "$registry_arg" ]; then
    docker_insecure_registry="--insecure-registry $registry_arg"
    docker_opts="$docker_opts $docker_insecure_registry"
  fi
elif [ "$registry_type" == "https" ]; then
  registry_arg=$(echo $registry_arg | sed -e 's/https:\/\///g')
  mkdir -p $DOCKER_REGISTRY_CRT_PATH/$registry_arg
  registry_crt="$DOCKER_REGISTRY_CRT_PATH/$registry_arg/registry.crt"
  registry_crt_url="$domeos_server$DOCKER_REGISTRY_CRT_URL"
  #cp $current_path/registry.crt $registry_crt
  curl -o $registry_crt $registry_crt_url
  if [ -f $registry_crt ]; then
    echo -e "\033[32m[OK] install docker registry certification\033[0m"
  else
    echo -e "\033[31m[ERROR] install docker secure registry certification failed\033[0m"
    exit 1
  fi
  echo -e "\033[32m[OK] install docker registry certification\033[0m"
fi
if [ -n "$docker_graph_path" ]; then
  docker_storage_options="--graph $docker_graph_path"
  docker_opts="$docker_opts $docker_storage_options"
fi
if [ -n "$docker_log_level" ]; then
  docker_log_level="--log-level $docker_log_level"
  docker_opts="$docker_opts $docker_log_level"
fi
if command_exists systemctl ; then
  docker_opts="DOCKER_OPTS=\"$docker_opts\""
  echo "$docker_opts
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
echo -e "\033[32m[OK] Docker configure\033[0m"

# STEP 12: start flannel
echo -e "\033[36m[INFO] STEP 12: Start Flannel...\033[0m"
if command_exists systemctl ; then
  systemctl daemon-reload
  systemctl stop docker
  systemctl stop flanneld
  ip link delete docker0
  ip link delete flannel.1
  systemctl disable iptables-services firewalld
  systemctl stop iptables-services firewalld
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

# STEP 13: start docker 
echo -e "\033[36m[INFO] STEP 13: Start Docker...\033[0m"
if command_exists systemctl ; then
  systemctl start docker
elif command_exists initctl ; then
  initctl start docker
fi
sleep 8

# STEP 14: configure and start kube-proxy
echo -e "\033[36m[INFO] STEP 14: Start kube-proxy...\033[0m"
if command_exists systemctl ; then
  systemctl stop kube-proxy
  echo "# configure file for kube-proxy
# --master
KUBE_MASTER='--master=$api_server'
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
  echo "KUBE_MASTER='--master=$api_server'
KUBE_PROXY_OPTS='$kube_proxy_opts'
" > /etc/default/kube-proxy
  echo "description \"Kube-Proxy service\"
author \"@domeos\"

# start in conjunction with flanneld
start on started flanneld
stop on runlevel [!2345]

respawn

limit nofile 65536 65536

pre-start script
	KUBE_PROXY=K8S_INSTALL_PATH/current/\$UPSTART_JOB
	if [ -f /etc/default/\$UPSTART_JOB ]; then
		. /etc/default/\$UPSTART_JOB
	fi
	if [ -f \$KUBE_PROXY ]; then
		exit 0
	fi
    exit 22
end script

script
	# modify these in /etc/default/\$UPSTART_JOB (/etc/default/kube-proxy)
	KUBE_PROXY=K8S_INSTALL_PATH/current/\$UPSTART_JOB
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

# STEP 15: start kubelet
echo -e "\033[36m[INFO] STEP 15: Start kubelet...\033[0m"
mkdir -p $k8s_data_dir
if command_exists systemctl ; then
  systemctl stop kubelet
  echo "# configure file for kubelet
# --api-servers
API_SERVERS='--api-servers=$api_server'
# --cluster-dns
CLUSTER_DNS='--cluster-dns=$cluster_dns'
# --cluster-domain
CLUSTER_DOMAIN='--cluster-domain=$cluster_domain'
# --root-dir
ROOT_DIR='--root-dir=$k8s_data_dir'
# --hostname-override
HOSTNAME_OVERRIDE='--hostname-override=$node_hostname'
# other parameters
KUBELET_OPTS='$KUBELET_OPTS'
" > /etc/sysconfig/kubelet
  echo "[Unit]
Description=kubelet

[Service]
EnvironmentFile=/etc/sysconfig/kubelet
ExecStart=$K8S_INSTALL_PATH/current/kubelet \$API_SERVERS \\
          \$CLUSTER_DNS \\
          \$CLUSTER_DOMAIN \\
          \$ROOT_DIR \\
          \$HOSTNAME_OVERRIDE \\
          \$KUBELET_OPTS
Restart=on-failure
" > /lib/systemd/system/kubelet.service
  systemctl daemon-reload
  systemctl start kubelet
elif command_exists initctl ; then
  initctl stop kubelet
  echo "API_SERVERS=\"--api-servers=$api_server\"
CLUSTER_DNS=\"--cluster-dns=$cluster_dns\"
CLUSTER_DOMAIN=\"--cluster-domain=$cluster_domain\"
ROOT_DIR=\"--root-dir=$k8s_data_dir\"
HOSTNAME_OVERRIDE=\"--hostname-override=$node_hostname\"
KUBELET_OPTS=\"$KUBELET_OPTS\"
" > /etc/default/kubelet
  echo "
description \"Kubelet service\"
author \"@domeos\"

# start in conjunction with flanneld
start on started flanneld
stop on runlevel [!2345]

respawn

pre-start script
	# see also https://github.com/jainvipin/kubernetes-ubuntu-start
	KUBELET=$K8S_INSTALL_PATH/current/\$UPSTART_JOB
	if [ -f /etc/default/\$UPSTART_JOB ]; then
		. /etc/default/\$UPSTART_JOB
	fi
	if [ -f \$KUBELET ]; then
		exit 0
	fi
    exit 22
end script

script
	# modify these in /etc/default/\$UPSTART_JOB (/etc/default/kubelet)
	KUBELET=$K8S_INSTALL_PATH/current/\$UPSTART_JOB
	API_SERVERS=\"\"
	CLUSTER_DNS=\"\"
	CLUSTER_DOMAIN=\"\"
	ROOT_DIR=\"\"
	HOSTNAME_OVERRIDE=\"\"
	KUBELET_OPTS=\"\"
	if [ -f /etc/default/\$UPSTART_JOB ]; then
		. /etc/default/\$UPSTART_JOB
	fi
	exec \"\$KUBELET\" \$API_SERVERS \$CLUSTER_DNS \$CLUSTER_DOMAIN \$ROOT_DIR \$HOSTNAME_OVERRIDE \$KUBELET_OPTS
end script
" > /etc/init/kubelet.conf
  initctl start kubelet
fi
sleep 5

# STEP 16: configure and start monitor agent
if [ -n "$monitor_transfer" ]; then
  echo -e "\033[36m[INFO] STEP 15: Start DomeOS agent\033[0m"
  docker rm -f agent
  monitor_transfer=$(echo $monitor_transfer | sed -e 's/https:\/\///g')
  monitor_transfer=$(echo $monitor_transfer | sed -e 's/http:\/\///g')
  heartbeat_addr=$(echo $heartbeat_addr | sed -e 's/https:\/\///g')
  heartbeat_addr=$(echo $heartbeat_addr | sed -e 's/http:\/\///g')
  monitor_transfers=(${monitor_transfer//,/ })
  format_transfer=
  for i in ${monitor_transfers[@]}
  do
    format_transfer="$format_transfer,\"$i\""
  done
  format_transfer=$(echo $format_transfer | sed -e 's/,//')
  if [ -n "$heartbeat_addr" ]; then
    docker run -d --restart=always -p 2222:2222 -e HOSTNAME="\"$node_hostname\"" -e TRANSFER_ADDR="[$format_transfer]" -e TRANSFER_INTERVAL="10" -e HEARTBEAT_ENABLED="true" -e HEARTBEAT_ADDR="\"$heartbeat_addr\"" -v /:/rootfs:ro -v /var/run:/var/run:rw -v /sys:/sys:ro -v $docker_graph_path:$docker_graph_path:ro -v /var/run/docker.sock:/var/run/docker.sock -v /usr/bin/docker:/bin/docker -v /lib64:/lib64:ro --name agent $DOMEOS_AGENT_IMAGE
  else
    docker run -d --restart=always -p 2222:2222 -e HOSTNAME="\"$node_hostname\"" -e TRANSFER_ADDR="[$format_transfer]" -e TRANSFER_INTERVAL="10" -v /:/rootfs:ro -v /var/run:/var/run:rw -v /sys:/sys:ro -v $docker_graph_path:$docker_graph_path:ro -v /var/run/docker.sock:/var/run/docker.sock -v /usr/bin/docker:/bin/docker -v /lib64:/lib64:ro --name agent $DOMEOS_AGENT_IMAGE
  fi
fi

# STEP 17: patch labels for node
echo -e "\033[36m[INFO] STEP 17: Patch labels for node $node_hostname...\033[0m"
  # sleep for kubernetes node register
sleep 3
labels=($(echo $node_labels | sed 's/,/ /g'))
for label in "${labels[@]}"
do
  $K8S_INSTALL_PATH/current/kubectl --server=$api_server label node $node_hostname $label
done
