#!/bin/sh

# start kubernetes node for DomeOS in centos server system
# xiaoshengxu@sohu-inc.com
# 2016-01-11
# 2016-03-30 update
# update 2016-04-21: 1) add cluster DNS nameserver and search into top of resolv.conf;
#                    2) format output;
#                    3) check more parameters;
#                    4) adjust installation sequence;
#                    5) add kubelet --log-dir and --root-dir setting. root-dir is used for log collection in DomeOS
# update 2016-05-03: change install path from ${pwd} to "/usr/sbin/domeos/k8s/"; remove invalid log-dir parameter for Kubernetes
# update 2016-05-04: add kubelet data path parameter for start_node_centos.sh; rename "TRANSFER_ADDR" to "TRANSFER_ADDR" for agent; fix agent -v bug
# update 2016-05-04: change agent install params: add heartbeat server
# update 2016-05-06: add --hostname-override parameter
# update 2016-05-16: make agent optional
# update 2016-05-23: chattr +i for resolv.conf
# update 2016-05-24: replace install package url; add kernel version and docker version check
# update 2016-05-29: fix hostname-override bug
# update 2016-06-06: add kubernetes and flannel version
# update 2016-06-07: add help info; remove --start-agent

AVAILABLE_K8S_VERSION=("1.1.3" "1.1.7" "1.2.0" "1.2.4")
AVAILABLE_K8S_FLANNEL_VERSION=("0.5.5")
K8S_VERSION="1.2.0"
FLANNEL_VERSION="0.5.5"
K8S_INSTALL_PATH="/usr/sbin/domeos/k8s"
FLANNEL_INSTALL_PATH="/usr/sbin/domeos/flannel"
K8S_PACKAGE_URL_PREFIX="http://domeos-binpack.bjcnc.scs.sohucs.com/k8s/"
FLANNEL_BIN_URL_PREFIX="http://domeos-binpack.bjcnc.scs.sohucs.com/flannel/"
DOCKER_URL="https://get.docker.com/"
RESOLV_FILE="/etc/resolv.conf"
FLANNEL_PREFIX="/flannel/network"
DOCKER_REGISTRY_CRT_PATH="/etc/docker/certs.d"
DOCKER_REGISTRY_CRT_URL="/api/global/registry/private/certification"
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
  start_node_centos.sh [options]
  start_node_centos.sh [command]

Available Commands:
  help    show the help information about start_node_centos.sh

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
This is a shell script for install, configure and start Kubernetes Node for DomeOS on CentOS 7. It will start flanneld, docker, kube-proxy and kubelet after successful execution.

Attention:
1. This shell will try to install the latest docker if docker has not been installed. You can install docker by yourself before execute this shell. Docker version must be 1.8.2 at minimum, version 1.10.3 is recommanded.
2. This shell will reset flannel and docker configure file, and modify DNS configure of host.
3. Use 'bash start_node_centos.sh help' to get more information.

Usage Example:
sudo bash start_node_centos.sh --api-server http://10.16.52.200:8080 --cluster-dns 172.16.40.1 --cluster-domain domeos.local --docker-graph-path /opt/domeos/openxxs/docker-graph --docker-log-level warn --domeos-server 10.11.158.76:8080 --etcd-server http://10.16.52.199:4012,http://10.16.52.200:4012,http://10.16.52.201:4012 --flannel-version 0.5.5 --heartbeat-addr 10.16.52.199:6030 --hostname-override tc-158-94 --k8s-data-dir /opt/domeos/openxxs/k8s-data --kubernetes-version 1.2.0 --monitor-transfer 10.16.52.198:8433,10.16.52.199:8433 --node-labels TESTENV=HOSTENVTYPE,PRODENV=HOSTENVTYPE --registry-type http --registry-arg 10.11.150.76:5000
"

if [[ "$1" =~ "help" ]]; then
  help
  exit 1
fi

# STEP 01: check linux kernel version
echo -e "\033[36m[INFO] STEP 01: Check Linux kernel version...\033[0m"
kernel_version=`uname -r`
if [ -z $kernel_version ]; then
  echo -e "\033[31m[ERROR] get kernel version error, kernel must be 3.10.0 at minimum\033[0m"
  exit 1
fi
kernel_parts_tmp=(${kernel_version//-/ })
kernel_parts=(${kernel_parts_tmp[0]//./ })
if [ ${kernel_parts[0]} -lt 3 ]; then
  echo -e "\033[31m[ERROR] Kernel version must be 3.10.0 at minimum, current version is ${kernel_parts_tmp[0]}\033[0m"
  exit 1
fi
if [ ${kernel_parts[0]} -eq 3 ] && [ ${kernel_parts[1]} -lt 10 ]; then
  echo -e "\033[31m[ERROR] Kernel version must be 3.10.0 at minimum, current version is ${kernel_parts_tmp[0]}\033[0m"
  exit 1
fi
echo -e "\033[32m[OK] Check kernel OK, current kernel version is ${kernel_parts_tmp[0]}\033[0m"

# STEP 02: check arguments
echo -e "\033[36m[INFO] STEP 02: Check input arguments...\033[0m"
OPTS=$(getopt -o : --long api-server:,cluster-dns:,cluster-domain:,docker-graph-path:,docker-log-level:,domeos-server:,etcd-server:,flannel-version:,heartbeat-addr:,hostname-override:,k8s-data-dir:,kubernetes-version:,monitor-transfer:,node-labels:,registry-type:,registry-arg: -- "$@")
if [ $? != 0 ]
then
  echo -e "\033[31m[ERROR] start_node_centos.sh argument is illegal\033[0m"
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
echo -e "\033[32m[OK] check start_node_centos.sh arguments are legal\033[0m"

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
  echo -e "\033[31m[ERROR] node hostname used for DomeOS is illegal (^[0-9a-zA-Z-]*$), you can use change_hostname.sh(http://domeos-script.bjctc.scs.sohucs.com/change_hostname.sh) to assign a new hostname for node, or set --hostname-override parameter for start_node_centos.sh\033[0m"
  exit 1
elif [ $hostname_cnt -ge 64 ]; then
  echo -e "\033[31m[ERROR] node hostname is longer than 63 chars\033[0m"
  exit 1
fi
echo -e "\033[32m[OK] check node hostname\033[0m"

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
mkdir -p /usr/libexec/flannel
mkdir -p /run/flannel
mkdir -p /usr/lib/systemd/system/docker.service.d
mv $current_path/node/kube-proxy $K8S_INSTALL_PATH/$kubernetes_version/
mv $current_path/node/kubelet $K8S_INSTALL_PATH/$kubernetes_version/
mv $current_path/node/kubectl $K8S_INSTALL_PATH/$kubernetes_version/
ln -fsn $K8S_INSTALL_PATH/$kubernetes_version $K8S_INSTALL_PATH/current
mv $current_path/flanneld $FLANNEL_INSTALL_PATH/$flannel_version/
ln -fsn $FLANNEL_INSTALL_PATH/$flannel_version $FLANNEL_INSTALL_PATH/current
mv $current_path/mk-docker-opts.sh /usr/libexec/flannel/mk-docker-opts.sh
set +e
echo -e "\033[32m[OK] Download and place required files\033[0m"

# STEP 07: add hostname and IP address into hosts
echo -e "\033[36m[INFO] STEP 07: Add /etc/hosts record\033[0m"
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

# STEP 08: add DNS server into resolv.conf
echo -e "\033[36m[INFO] STEP 08: Cluster DNS nameserver and search will be added into top of $RESOLV_FILE\033[0m"
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
chattr -i $RESOLV_FILE
echo "search $cluster_dns_search" > $RESOLV_FILE
echo "nameserver $cluster_dns" >> $RESOLV_FILE
for i in "${host_self_dns[@]}"
do
  echo $i >> $RESOLV_FILE
done
chattr +i $RESOLV_FILE
set +e
echo -e "\033[32m[OK] Add DNS nameserver and search into $RESOLV_FILE\033[0m"

# STEP 09: Configure flannel
echo -e "\033[36m[INFO] STEP 09: Configure Flannel...\033[0m"
if command_exists flanneld && [ -e /usr/libexec/flannel/mk-docker-opts.sh ]; then
  echo -e "\033[36m[INFO] flanneld command already exists on this system.\033[0m"
  echo -e "\033[36m/etc/sysconfig/flanneld /usr/lib/systemd/system/docker.service.d/flannel.conf and /lib/systemd/system/flanneld.service files will be reset\033[0m"
  echo -e "\033[36mYou may press Ctrl+C now to abort this script.\033[0m"
  echo -e "\033[36mwaitting for 10 seconds...\033[0m"
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
if [ -e $FLANNEL_INSTALL_PATH/current/flanneld ] && [ -e /usr/libexec/flannel/mk-docker-opts.sh ]; then
  echo -e "\033[32m[OK] flannel environment is ready\033[0m"
else
  echo -e "\033[31m[ERROR] flannel environment is not ready\033[0m"
  exit 1
fi

# STEP 10: install and configure docker
if command_exists docker ; then
  echo -e "\033[36m[INFO] docker command already exists on this system.\033[0m"
  echo -e "\033[36m/etc/sysconfig/docker and /lib/systemd/system/docker.service files will be reset.\033[0m"
  echo -e "\033[36mYou may press Ctrl+C now to abort this script.\033[0m"
  echo -e "\033[36mwaitting for 10 seconds...\033[0m"
  sleep 10
else
  #yum install -y docker-engine-selinux-1.10.2-1.el7.centos.noarch.rpm
  #yum install -y docker-engine-1.10.2-1.el7.centos.x86_64.rpm
  echo -e "\033[36m[INFO] STEP 10: Install and configure docker...\033[0m"
  curl -sSL $DOCKER_URL | sh
fi
docker_opts="DOCKER_OPTS=\"$DOCKER_OPTS\""
echo $docker_opts > /etc/sysconfig/docker
if [ "$registry_type" == "http" ]; then
  registry_arg=$(echo $registry_arg | sed -e 's/https:\/\///g')
  registry_arg=$(echo $registry_arg | sed -e 's/http:\/\///g')
  if [ -n "$registry_arg" ]; then
    docker_insecure_registry="INSECURE_REGISTRY=\"--insecure-registry $registry_arg\""
    echo $docker_insecure_registry >> /etc/sysconfig/docker
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
  docker_storage_options="DOCKER_STORAGE_OPTIONS=\"--graph $docker_graph_path\""
  echo $docker_storage_options >> /etc/sysconfig/docker
fi
if [ -n "$docker_log_level" ]; then
  docker_log_level="DOCKER_LOG_LEVEL=\"--log-level $docker_log_level\""
  echo $docker_log_level >> /etc/sysconfig/docker
fi
echo "[Unit]
Description=Docker Application Container Engine
Documentation=https://docs.docker.com
After=network.target docker.socket
Requires=docker.socket

[Service]
Type=notify
EnvironmentFile=/etc/sysconfig/docker
ExecStart=/usr/bin/docker daemon \$DOCKER_OPTS \\
\$DOCKER_STORAGE_OPTIONS \\
\$DOCKER_NETWORK_OPTIONS \\
\$DOCKER_LOG_LEVEL \\
\$ADD_REGISTRY \\
\$BLOCK_REGISTRY \\
\$INSECURE_REGISTRY

MountFlags=slave
LimitNOFILE=1048576
LimitNPROC=1048576
LimitCORE=infinity
TimeoutStartSec=0
Delegate=yes

[Install]
WantedBy=multi-user.target
" > /lib/systemd/system/docker.service
if command_exists docker ; then
  echo -e "\033[32m[OK] docker environment is ready\033[0m"
else
  echo -e "\033[31m[ERROR] docker environment is not ready\033[0m"
  exit 1
fi

# STEP 11: start flannel
echo -e "\033[36m[INFO] STEP 11: Start Flannel...\033[0m"
systemctl daemon-reload
systemctl stop docker
systemctl stop flanneld
ip link delete docker0
ip link delete flannel.1
systemctl disable iptables-services firewalld
systemctl stop iptables-services firewalld
systemctl start flanneld
sleep 5
systemctl status -l flanneld

# STEP 12: start docker 
echo -e "\033[36m[INFO] STEP 12: Start Docker...\033[0m"
systemctl start docker
sleep 8
systemctl status -l docker

# STEP 13: start kube-proxy
echo -e "\033[36m[INFO] STEP 13: Start kube-proxy...\033[0m"
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
sleep 5
systemctl status -l kube-proxy

# STEP 14: start kubelet
echo -e "\033[36m[INFO] STEP 13: Start kubelet...\033[0m"
systemctl stop kubelet
mkdir -p $k8s_data_dir
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
KUBELET_OPTS='$kubelet_opts'
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
sleep 5
systemctl status -l kubelet

# STEP 15: configure and start monitor agent
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

# STEP 16: patch labels for node
echo -e "\033[36m[INFO] STEP 16: Patch labels for node $node_hostname\033[0m"
labels=($(echo $node_labels | sed 's/,/ /g'))
for label in "${labels[@]}"
do
  $K8S_INSTALL_PATH/current/kubectl --server=$api_server label node $node_hostname $label
done
