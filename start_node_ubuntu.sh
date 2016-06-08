#!/bin/bash

# start kubernetes node for DomeOS in Ubuntu server system
# xiaoshengxu@sohu-inc.com
# 2016-05-26
# update 2016-06-01: add heartbeat parameter
# update 2016-06-06: add kubernetes and flannel version

# sudo bash start_node_ubuntu.sh --api-server <api_servers> --cluster-dns <cluster_dns> --cluster-domain <cluster_domain> --docker-graph-path <docker_graph_path> --k8s-data-dir <k8s_data_dir> --docker-log-level <docker_log_level> --registry-type <registry_type> --registry-arg <registry_arg> --domeos-server <domeos_server> --etcd-server <etcd_server> --node-labels <node_labels> --hostname-override <legal-hostname> --start-agent <true/false> --monitor-transfer <monitor_transfer> --heartbeat-addr <heartbeat_addr>
# example: sudo bash start_node_ubuntu.sh --api-server http://10.16.42.200:8080 --cluster-dns 172.16.40.1 --cluster-domain domeos.local --docker-graph-path /opt/domeos/openxxs/docker-graph --k8s-data-dir /opt/domeos/openxxs/k8s-data --docker-log-level warn --registry-type http --registry-arg 10.11.150.76:5000 --domeos-server 10.11.150.76:8080 --etcd-server http://10.16.42.199:4012,http://10.16.42.200:4012,http://10.16.42.201:4012 --node-labels TESTENV=HOSTENVTYPE,PRODENV=HOSTENVTYPE --hostname-override tc-150-94 --start-agent true --monitor-transfer 10.16.42.198:8433,10.16.42.199:8433 --heartbeat-addr 10.16.42.199:6030 --kubernetes-version 1.2.0 --flannel-version 0.5.5

command_exists() {
  command -v "$@" > /dev/null 2>&1
}

# STEP 01: check system kernel version
echo -e "\033[36m[INFO] STEP 01: Check system kernel...\033[0m"
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
OPTS=$(getopt -o : --long api-server:,cluster-dns:,cluster-domain:,docker-graph-path:,k8s-data-dir:,docker-log-level:,registry-type:,registry-arg:,domeos-server:,etcd-server:,node-labels:,hostname-override:,start-agent:,monitor-transfer:,heartbeat-addr:,kubernetes-version:,flannel-version: -- "$@")
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
k8s_data_dir=
docker_log_level=
registry_type=
registry_arg=
domeos_server=
etcd_server=
node_labels=
hostname_override=
start_agent=
monitor_transfer=
heartbeat_addr=
kubernetes_version=
flannel_version=
while true ; do
  case "$1" in
    --api-server) api_server=$2; shift 2;;
    --cluster-dns) cluster_dns=$2; shift 2;;
    --cluster-domain) cluster_domain=$2; shift 2;;
    --docker-graph-path) docker_graph_path=$2; shift 2;;
    --k8s-data-dir) k8s_data_dir=$2; shift 2;;
    --docker-log-level) docker_log_level=$2; shift 2;;
    --registry-type) registry_type=$2; shift 2;;
    --registry-arg) registry_arg=$2; shift 2;;
    --domeos-server) domeos_server=$2; shift 2;;
    --etcd-server) etcd_server=$2; shift 2;;
    --node-labels) node_labels=$2; shift 2;;
    --hostname-override) hostname_override=$2; shift 2;; 
    --start-agent) start_agent=$2; shift 2;;
    --monitor-transfer) monitor_transfer=$2; shift 2;;
    --heartbeat-addr) heartbeat_addr=$2; shift 2;;
    --kubernetes-version) kubernetes_version=$2; shift 2;;
    --flannel-version) flannel_version=$2; shift 2;;
    --) shift; break;;
  esac
done
if [ "$api_server" == "" ]; then
  echo -e "\033[31m[ERROR] --api-server is absent\033[0m"
  exit 1
else
  echo "--api-server: $api_server"
fi
cluster_dns_check=`echo $cluster_dns | grep ':' | wc | awk '{print $3}'`
if [ $cluster_dns_check -gt 0 ]; then
  echo -e "\033[33m[WARN] --cluster-dns $cluster_dns includes port, it is illegal, \033[0m"
  cluster_dns=`echo $cluster_dns | cut -f1 -d ':'`
  echo "use '--cluster-dns $cluster_dns' instead, DNS port always be 53"
fi
if [ "$cluster_domain" == "" ]; then
  echo -e "\033[31m[ERROR] --cluster-domain is absent\033[0m"
  exit 1
else
  echo "--cluster-domain: $cluster_domain"
fi
if [ "$docker_graph_path" == "" ]; then
  echo -e "\033[36m[INFO] --docker-graph-path is absent, default '$(pwd)/docker-graph'\033[0m"
  docker_graph_path="$(pwd)/docker-graph"
else
  echo "--docker-graph-path: " $docker_graph_path
fi
if [ "$k8s_data_dir" == "" ]; then
  echo -e "\033[36m[INFO] --k8s-data-dir is absent, default '/var/lib/domeos/k8s-data'\033[0m"
  k8s_data_dir="/var/lib/domeos/k8s-data"
else
  echo "--k8s-data-dir: $k8s_data_dir"
fi
if [ "$docker_log_level" == "" ]; then
  echo -e "\033[36m[INFO] --docker-log-level is absent, default 'warn'\033[0m"
  docker_log_level="warn"
else
  echo "--docker-log-level: $docker_log_level"
fi
if [ "$registry_type" == "" ]; then
  echo -e "\033[31m[ERROR] --registry-type is absent\033[0m"
  exit 1
else
  echo "--registry-type: $registry_type"
fi
if [ "$registry_arg" == "" ]; then
  echo -e "\033[31m[ERROR] --registry-arg is absent\033[0m"
  exit 1
else
  echo "--registry-arg: $registry_arg"
fi
if [ "$domeos_server" == "" ]; then
  if [ "$registry_type" == "https" ]; then
    echo -e "\033[31m[ERROR] --domeos-server is absent. This shell needs to curl docker registry certification from DomeOS server if you set '--registry-type https'\033[0m"
    exit 1
  fi
else
  echo "--domeos-server: $domeos_server"
fi
if [ "$etcd_server" == "" ]; then
  echo -e "\033[31m[ERROR] --etcd-server is absent\033[0m"
  exit 1
else
  echo "--etcd-server: $etcd_server"
fi
echo "--node-labels: $node_labels"
if [ "$hostname_override" == "" ]; then
  echo -e "\033[36m[INFO] --hostname-override is absent, default $(hostname)\033[0m"
  hostname_override=$(hostname)
else
  echo "--hostname-override: $hostname_override"
fi
if [ "$start_agent" == "" ]; then
  echo -e "\033[36m[INFO] --start-agent is absent, default 'true'\033[0m"
  start_agent="true"
elif [ "$start_agent" != "true" ] && [ "$start_agent" != "false" ]; then
  echo -e "\033[31m[ERROR] --start-agent is illegal, should be 'true' or 'false'\033[0m"
  exit 1
else
  echo "--start-agent: $start_agent"
fi
if [ "$start_agent" == "true" ]; then
  if [ "$monitor_transfer" == "" ]; then
    echo -e "\033[31m[ERROR] --start-agent is true but --monitor-transfer is absent\033[0m"
    exit 1
  else
    echo "--monitor-transfer: $monitor_transfer"
  fi
  if [ "$heartbeat_addr" == "" ]; then
    echo -e "\033[31m[ERROR] --start-agent is true but --heartbeat-addr is absent\033[0m"
    exit 1
  else
    echo "--heartbeat-addr: $heartbeat_addr"
  fi
fi
if [ -z "$kubernetes_version" ]; then
  echo -e "\033[36m[INFO] --kubernetes-version is absent, default 1.2.0\033[0m"
  kubernetes_version="1.2.0"
else
  echo "--kubernetes-version: $kubernetes_version"
fi
if [ -z "$flannel_version" ]; then
  echo -e "\033[36m[INFO] --flannel-version is absent, default 0.5.5\033[0m"
  flannel_version="0.5.5"
else
  echo "--flannel-version: $flannel_version"
fi
echo -e "\033[32m[OK] start_node_ubuntu.sh arguments are legal\033[0m"

# STEP 03: assign append arguments
echo -e "\033[36m[INFO] STEP 03: assign append arguments...\033[0m"
KUBERNETES_VERSION=$kubernetes_version
k8s_install_path="/usr/sbin/domeos/k8s"
proxy_mode="iptables"
kube_proxy_opts="--v=0 --masquerade-all=true"
max_pods=70
pod_infra="pub.domeos.org/kubernetes/pause:latest"
kubelet_allow_privileged="false"
kubelet_root_dir="$k8s_data_dir/root-dir"
kubelet_opts="--v=0"
registry_crt_path="/etc/docker/certs.d"
registry_crt_url="/api/global/registry/private/certification"
docker_url="https://get.docker.com/"
docker_opts=
docker_insecure_registry=
node_package_url="http://domeos-binpack.bjcnc.scs.sohucs.com/k8s/$KUBERNETES_VERSION/node.tgz"
flannel_prefix="/flannel/network"
flannel_opts=
resolv_file="/etc/resolv.conf"
domeos_agent_image="pub.domeos.org/domeos/agent:2.5"
docker_list_file="/etc/apt/sources.list.d/docker.list"
docker_repo_url="https://apt.dockerproject.org/repo"
echo -e "\033[32m[OK] Append arguments have been assigned\033[0m"

# STEP 04: download and decompress installation package
echo -e "\033[36m[INFO] STEP 04: Download and decompress installation package...\033[0m"
curl -o node.tgz $node_package_url
curl -o flanneld "http://domeos-binpack.bjcnc.scs.sohucs.com/flannel/$flannel_version/flanneld"
curl -o mk-docker-opts.sh "http://domeos-binpack.bjcnc.scs.sohucs.com/flannel/$flannel_version/mk-docker-opts.sh"
tar -zxvf node.tgz
current_path=$(pwd)
chmod +x $current_path/flanneld
chmod +x $current_path/mk-docker-opts.sh
chmod +x $current_path/node/kube-proxy
chmod +x $current_path/node/kubelet
chmod +x $current_path/node/kubectl
mkdir -p $k8s_install_path/$KUBERNETES_VERSION
mkdir -p $kubelet_root_dir
mv $current_path/node/kube-proxy $k8s_install_path/$KUBERNETES_VERSION/
mv $current_path/node/kubelet $k8s_install_path/$KUBERNETES_VERSION/
mv $current_path/node/kubectl $k8s_install_path/$KUBERNETES_VERSION/
ln -fsn $k8s_install_path/$KUBERNETES_VERSION $k8s_install_path/current
echo -e "\033[32m[OK] installation package has been downloaded and decompressed.\033[0m"

# STEP 05: check hostname (DNS roles)
echo -e "\033[36m[INFO] STEP 05: Check node name...\033[0m"
node_hostname=$hostname_override
hostname_cnt=`echo $node_hostname | grep '^[0-9a-zA-Z-]*$' | wc | awk '{print $3}'`
if [ $hostname_cnt -le 0 ]; then
  echo -e "\033[31m[ERROR] node name used for DomeOS is illegal (^[0-9a-zA-Z-]*$), you can use change_hostname.sh(http://domeos-script.bjctc.scs.sohucs.com/change_hostname.sh) to assign a new hostname for node, or set --hostname-override parameter for start_node_ubuntu.sh\033[0m"
  exit 1
else
  if [ $hostname_cnt -ge 64 ]; then
    echo -e "\033[31m[ERROR] node name is longer than 63 chars\033[0m"
    exit 1
  fi
fi
echo -e "\033[32m[OK] Node name is legal\033[0m"

# STEP 06: check ip
echo -e "\033[36m[INFO] STEP 06: Check node ip...\033[0m"
node_ips=(`ip addr show | grep inet | grep -v inet6 | grep brd | awk '{print $2}' | cut -f1 -d '/'`)
if [ "$node_ips" == "" ]; then
  echo -e "\033[31m[ERROR] get ip address error\033[0m"
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
if [ "$node_ip" == "" ]; then
  node_ip=${node_ips[0]}
fi
echo -e "\033[32m[OK] use host ip address: $node_ip\033[0m"

# STEP 07: get iface for flannel
echo -e "\033[36m[INFO] STEP 07: Get iface for flannel...\033[0m"
flannel_iface=(`ip addr show | grep $node_ip | awk '{print $7}'`)
if [ "$flannel_iface" == "" ]; then
  echo -e "\033[31m[ERROR] get ip iface error\033[0m"
  exit 1
else
  flannel_iface=${flannel_iface[0]}
fi
echo -e "\033[32m[OK] use flannel iface: $flannel_iface\033[0m"

# STEP 08: add node name and IP address into hosts
echo -e "\033[36m[INFO] STEP 08: Add hostname and IP address into hosts...\033[0m"
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

# STEP 09: add DNS server into resolv.conf
echo -e "\033[36m[INFO] STEP 09: Cluster DNS nameserver and search will be added into top of $resolv_file\033[0m"
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
chattr +i $resolv_file
echo -e "\033[32m[OK] $resolv_file has been updated\033[0m"

# STEP 10: install and configure flannel
echo -e "\033[36m[INFO] STEP 10: Install and configure flannel...\033[0m"
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
else
  mv $current_path/flanneld /usr/bin/flanneld
fi
# check http:// prefix of etcd address
flannel_etcd_servers=
flannel_etcds=(${etcd_server//,/ })
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
if command_exists systemctl ; then
  mkdir -p /etc/sysconfig
  mkdir -p /usr/libexec/flannel
  mkdir -p /usr/lib/systemd/system/docker.service.d
  mv $current_path/mk-docker-opts.sh /usr/libexec/flannel/mk-docker-opts.sh
  echo "FLANNEL_ETCD=\"$flannel_etcd_servers\"
FLANNEL_ETCD_KEY=\"$flannel_prefix\"
FLANNEL_IFACE=\"$flannel_iface\"
FLANNEL_OPTIONS=\"$flannel_opts\"
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
ExecStart=/usr/bin/flanneld -etcd-endpoints=\${FLANNEL_ETCD} -etcd-prefix=\${FLANNEL_ETCD_KEY} -iface=\${FLANNEL_IFACE} \$FLANNEL_OPTIONS
Restart=always
ExecStartPost=/usr/libexec/flannel/mk-docker-opts.sh -k DOCKER_NETWORK_OPTIONS -d /run/flannel/docker
Restart=on-failure
[Install]
WantedBy=multi-user.target
RequiredBy=docker.service
" > /lib/systemd/system/flanneld.service
elif command_exists initctl ; then
  echo "FLANNEL_ETCD=\"$flannel_etcd_servers\"
FLANNEL_ETCD_KEY=\"$flannel_prefix\"
FLANNEL_IFACE=\"$flannel_iface\"
FLANNEL_OPTIONS=\"$flannel_opts\"
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
    FLANNEL=/usr/bin/\$UPSTART_JOB
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
    FLANNEL=/usr/bin/\$UPSTART_JOB
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
if command_exists flanneld ; then
  echo -e "\033[32m[OK] flannel environment is ready\033[0m"
else
  echo -e "\033[31m[ERROR] flannel environment is not ready\033[0m"
  exit 1
fi

# STEP 11: install docker
echo -e "\033[36m[INFO] STEP 11: Install Docker...\033[0m"
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

# STEP 12: Configure Docker
echo -e "\033[36m[INFO] STEP 12: Configure Docker...\033[0m"
if [ "$registry_type" == "http" ]; then
  registry_arg=$(echo $registry_arg | sed -e 's/https:\/\///g')
  registry_arg=$(echo $registry_arg | sed -e 's/http:\/\///g')
  if [ "$registry_arg" != "" ]; then
    docker_insecure_registry="--insecure-registry $registry_arg"
  fi
else
  registry_arg=$(echo $registry_arg | sed -e 's/https:\/\///g')
  mkdir -p $registry_crt_path/$registry_arg
  registry_crt="$registry_crt_path/$registry_arg/registry.crt"
  registry_crt_url="$domeos_server$registry_crt_url"
  #cp $current_path/registry.crt $registry_crt
  curl -o $registry_crt $registry_crt_url
  if [ -f $registry_crt ]; then
    echo -e "\033[32m[OK] install docker registry certification\033[0m"
  else
    echo -e "\033[31m[ERROR] install docker secure registry certification failed\033[0m"
    exit 1
  fi
fi
docker_opts="$docker_opts --log-level=$docker_log_level $docker_insecure_registry --graph $docker_graph_path"
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

# STEP 13: start flannel
echo -e "\033[36m[INFO] STEP 13: Start Flannel...\033[0m"
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

# STEP 14: start docker 
echo -e "\033[36m[INFO] STEP 14: Start Docker...\033[0m"
if command_exists systemctl ; then
  systemctl start docker
elif command_exists initctl ; then
  initctl start docker
fi
sleep 10

# STEP 15: configure and start kube-proxy
echo -e "\033[36m[INFO] STEP 15: Start kube-proxy...\033[0m"
if command_exists systemctl ; then
  systemctl stop kube-proxy
  echo "# configure file for kube-proxy
# --master
KUBE_MASTER='--master=$api_server'
# --proxy-mode
PROXY_MODE='--proxy-mode=$proxy_mode'
# other parameters
KUBE_PROXY_OPTS='$kube_proxy_opts'
" > /etc/sysconfig/kube-proxy
  echo "[Unit]
Description=kube-proxy

[Service]
EnvironmentFile=/etc/sysconfig/kube-proxy
ExecStart=$k8s_install_path/current/kube-proxy \$KUBE_MASTER \\
          \$PROXY_MODE \\
          \$KUBE_PROXY_OPTS
Restart=on-failure
" > /lib/systemd/system/kube-proxy.service
  systemctl daemon-reload
  systemctl start kube-proxy
elif command_exists initctl ; then
  initctl stop kube-proxy
  echo "KUBE_MASTER='--master=$api_server'
PROXY_MODE='--proxy-mode=$proxy_mode'
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
	KUBE_PROXY=/usr/sbin/domeos/k8s/current/\$UPSTART_JOB
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
	KUBE_PROXY=/usr/sbin/domeos/k8s/current/\$UPSTART_JOB
	KUBE_MASTER=\"\"
	PROXY_MODE=\"\"
	KUBE_PROXY_OPTS=\"\"
	if [ -f /etc/default/\$UPSTART_JOB ]; then
		. /etc/default/\$UPSTART_JOB
	fi
	exec \"\$KUBE_PROXY\" \$KUBE_MASTER \$PROXY_MODE \$KUBE_PROXY_OPTS
end script
" > /etc/init/kube-proxy.conf
  initctl start kube-proxy
fi
sleep 5

# STEP 16: start kubelet
echo -e "\033[36m[INFO] STEP 16: Start kubelet...\033[0m"
if command_exists systemctl ; then
  systemctl stop kubelet
  echo "# configure file for kubelet

# --api-servers
API_SERVERS='--api-servers=$api_server'
# --address
ADDRESS='--address=0.0.0.0'
# --allow-privileged
ALLOW_PRIVILEGED='--allow-privileged=$kubelet_allow_privileged'
# --pod-infra-container-image
POD_INFRA='--pod-infra-container-image=$pod_infra'
# --cluster-dns
CLUSTER_DNS='--cluster-dns=$cluster_dns'
# --cluster-domain
CLUSTER_DOMAIN='--cluster-domain=$cluster_domain'
# --max-pods
MAX_PODS='--max-pods=$max_pods'
# --root-dir
ROOT_DIR='--root-dir=$kubelet_root_dir'
# other parameters
KUBELET_OPTS='$kubelet_opts --hostname-override=$node_hostname'
" > /etc/sysconfig/kubelet
  echo "[Unit]
Description=kubelet

[Service]
EnvironmentFile=/etc/sysconfig/kubelet
ExecStart=$k8s_install_path/current/kubelet \$API_SERVERS \\
          \$ADDRESS \\
          \$ALLOW_PRIVILEGED \\
          \$POD_INFRA \\
          \$CLUSTER_DNS \\
          \$CLUSTER_DOMAIN \\
          \$MAX_PODS \\
          \$ROOT_DIR \\
          \$KUBELET_OPTS
Restart=on-failure
" > /lib/systemd/system/kubelet.service
  systemctl daemon-reload
  systemctl start kubelet
elif command_exists initctl ; then
  initctl stop kubelet
  echo "API_SERVERS=\"--api-servers=$api_server\"
ADDRESS=\"--address=0.0.0.0\"
ALLOW_PRIVILEGED=\"--allow-privileged=$kubelet_allow_privileged\"
POD_INFRA=\"--pod-infra-container-image=$pod_infra\"
CLUSTER_DNS=\"--cluster-dns=$cluster_dns\"
CLUSTER_DOMAIN=\"--cluster-domain=$cluster_domain\"
MAX_PODS=\"--max-pods=$max_pods\"
ROOT_DIR=\"--root-dir=$kubelet_root_dir\"
KUBELET_OPTS=\"$kubelet_opts --hostname-override=$node_hostname\"
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
	KUBELET=/usr/sbin/domeos/k8s/current/\$UPSTART_JOB
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
	KUBELET=/usr/sbin/domeos/k8s/current/\$UPSTART_JOB
	API_SERVERS=\"\"
	ADDRESS=\"\"
	ALLOW_PRIVILEGED=\"\"
	POD_INFRA=\"\"
	CLUSTER_DNS=\"\"
	CLUSTER_DOMAIN=\"\"
	MAX_PODS=\"\"
	ROOT_DIR=\"\"
	KUBELET_OPTS=\"\"
	if [ -f /etc/default/\$UPSTART_JOB ]; then
		. /etc/default/\$UPSTART_JOB
	fi
	exec \"\$KUBELET\" \$API_SERVERS \$ADDRESS \$ALLOW_PRIVILEGED \$POD_INFRA \$CLUSTER_DNS \$CLUSTER_DOMAIN \$MAX_PODS \$ROOT_DIR \$KUBELET_OPTS
end script
" > /etc/init/kubelet.conf
  initctl start kubelet
fi
sleep 5

# STEP 17: configure and start monitor agent
echo -e "\033[36m[INFO] STEP 17: Start monitor agent...\033[0m"
if [ "$start_agent" == "true" ]; then
  monitor_transfer=$(echo $monitor_transfer | sed -e 's/https:\/\///g')
  monitor_transfer=$(echo $monitor_transfer | sed -e 's/http:\/\///g')
  heartbeat_addr=$(echo $heartbeat_addr | sed -e 's/https:\/\///g')
  heartbeat_addr=$(echo $heartbeat_addr | sed -e 's/http:\/\///g')
  monitor_transfers=(${monitor_transfer//,/ })
  format_transfer=
  for i in ${monitor_transfers[@]}
  do
    format_transfer=$format_transfer,\"$i\"
  done
  format_transfer=$(echo $format_transfer | sed -e 's/,//')
  docker rm -f agent
  docker run -d --restart=always -p 2222:2222 -e HOSTNAME="\"$node_hostname\"" -e TRANSFER_ADDR="[$format_transfer]" -e TRANSFER_INTERVAL="10" -e HEARTBEAT_ENABLED="true" -e HEARTBEAT_ADDR="\"$heartbeat_addr\"" -v /:/rootfs:ro -v /var/run:/var/run:rw -v /sys:/sys:ro -v $docker_graph_path:$docker_graph_path:ro -v /var/run/docker.sock:/var/run/docker.sock -v /usr/bin/docker:/bin/docker -v /lib64:/lib64:ro --name agent $domeos_agent_image
fi
echo -e "\033[32m[OK] Monitor agent has started\033[0m"

# STEP 18: patch labels for node
echo -e "\033[36m[INFO] STEP 18: Patch labels...\033[0m"
labels=($(echo $node_labels | sed 's/,/ /g'))
for label in "${labels[@]}"
do
  $k8s_install_path/current/kubectl --server=$api_server label node $node_hostname $label
done
