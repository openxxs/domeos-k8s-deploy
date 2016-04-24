#!/bin/sh

# start kubernetes node for DomeOS in centos system
# xiaoshengxu@sohu-inc.com
# 2016-01-11
# 2016-03-30 update
# update 2016-04-21: 1) add cluster DNS nameserver and search into top of resolv.conf;
#                    2) format output;
#                    3) check more parameters;
#                    4) adjust installation sequence;
#                    5) add kubelet --log-dir and --root-dir setting in STEP 02. root-dir is used for log collection in DomeOS

# sudo sh start_node_centos.sh --api-server <api_servers> --cluster-dns <cluster_dns> --cluster-domain <cluster_domain> --monitor-transfer <monitor_transfer> --docker-graph-path <docker_graph_path> --docker-log-level <docker_log_level> --registry-type <registry_type> --registry-arg <registry_arg> --domeos-server <domeos_server> --etcd-server <etcd_server> --node-labels <node_labels>
# example: sudo sh start_node_centos.sh --api-server http://10.16.42.200:8080 --cluster-dns 172.16.40.1 --cluster-domain domeos.local --monitor-transfer 10.16.42.198:8433,10.16.42.199:8433 --docker-graph-path /opt/domeos/openxxs/docker-graph --docker-log-level warn --registry-type http --registry-arg 10.11.150.76:5000 --domeos-server 10.11.150.76:8080 --etcd-server http://10.16.42.199:4012,http://10.16.42.200:4012,http://10.16.42.201:4012 --node-labels TESTENV=HOSTENVTYPE,PRODENV=HOSTENVTYPE

# STEP 01: check arguments
OPTS=$(getopt -o : --long api-server:,cluster-dns:,cluster-domain:,monitor-transfer:,docker-graph-path:,docker-log-level:,registry-type:,registry-arg:,domeos-server:,etcd-server:,node-labels: -- "$@")
if [ $? != 0 ]
then
  echo -e "\033[31m[ERROR] start_node_centos.sh argument is illegal\033[0m"
  exit 1
fi
eval set -- "$OPTS"
api_server=
cluster_dns=
cluster_domain=
monitor_transfer=
docker_graph_path=
docker_log_level=
registry_type=
registry_arg=
domeos_server=
etcd_server=
node_labels=
while true ; do
  case "$1" in
    --api-server) api_server=$2; shift 2;;
    --cluster-dns) cluster_dns=$2; shift 2;;
    --cluster-domain) cluster_domain=$2; shift 2;;
    --monitor-transfer) monitor_transfer=$2; shift 2;;
    --docker-graph-path) docker_graph_path=$2; shift 2;;
    --docker-log-level) docker_log_level=$2; shift 2;;
    --registry-type) registry_type=$2; shift 2;;
    --registry-arg) registry_arg=$2; shift 2;;
    --domeos-server) domeos_server=$2; shift 2;;
    --etcd-server) etcd_server=$2; shift 2;;
    --node-labels) node_labels=$2; shift 2;;
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
if [ "$monitor_transfer" == "" ]; then
  echo -e "\033[31m[ERROR] --monitor-transfer is absent\033[0m"
  exit 1
else
  echo "--monitor-transfer: $monitor_transfer"
fi
if [ "$docker_graph_path" == "" ]; then
  echo -e "\033[36m[INFO] --docker-graph-path is absent, default '$(pwd)/docker-graph'\033[0m"
  docker_graph_path=$(pwd)/docker-graph
else
  echo "--docker-graph-path: " $docker_graph_path
fi
if [ "$docker_log_level" == "" ]; then
  echo -e "\033[36m[INFO] --docker-log-level is absent, default 'warn'\033[0m"
  docker_log_level="warn"
else
  echo "--docker-log-level: " $docker_log_level
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
echo -e "\033[32m[OK] check start_node_centos.sh arguments\033[0m"

# STEP 02: assign append arguments
proxy_mode="iptables"
kube_proxy_opts="--v=0 --masquerade-all=true"
max_pods=70
pod_infra="pub.domeos.org/kubernetes/pause:latest"
kubelet_allow_privileged="false"
kubelet_log_dir="$(pwd)/log-dir"
kubelet_root_dir="$(pwd)/root-dir"
kubelet_opts="--v=0"
registry_crt_path="/etc/docker/certs.d"
registry_crt_url="/api/global/registry/private/certification"
docker_url="https://get.docker.com/"
docker_opts=
docker_insecure_registry=
node_package_url="http://deploy-domeos.bjcnc.scs.sohucs.com/domeos-k8s-node.tar.gz"
flannel_prefix="/flannel/network"
flannel_opts=
resolv_file="/etc/resolv.conf"
domeos_agent_image="pub.domeos.org/domeos/agent:2.4"

command_exists() {
  command -v "$@" > /dev/null 2>&1
}

# STEP 03: download and decompress install package
curl -o domeos-k8s-node.tar.gz $node_package_url
tar -zxvf domeos-k8s-node.tar.gz
current_path=$(pwd)
chmod +x $current_path/flanneld
chmod +x $current_path/mk-docker-opts.sh
chmod +x $current_path/kube-proxy
chmod +x $current_path/kubelet
chmod +x $current_path/kubectl
mkdir -p $current_path/logs

# STEP 04: check hostname (DNS roles)
node_hostname=`hostname`
hostname_cnt=`echo $node_hostname | grep '^[0-9a-zA-Z-]*$' | wc | awk '{print $3}'`
if [ $hostname_cnt -le 0 ]; then
  echo -e "\033[31m[ERROR] node hostname is illegal (^[0-9a-zA-Z-]*$), you can use change_hostname.sh to assign a new hostname for node\033[0m"
  exit 1
else
  if [ $hostname_cnt -ge 64 ]; then
    echo -e "\033[31m[ERROR] node hostname is longer than 63 chars\033[0m"
    exit 1
  fi
fi
echo -e "\033[32m[OK] check node hostname\033[0m"

# STEP 05: check ip
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
echo -e "\033[36m[INFO] use host ip address: $node_ip\033[0m"

# STEP 06: get iface for flannel
flannel_iface=(`ip addr show | grep $node_ip | awk '{print $7}'`)
if [ "$flannel_iface" == "" ]; then
  echo -e "\033[31m[ERROR] get ip iface error\033[0m"
  exit 1
else
  flannel_iface=${flannel_iface[0]}
  echo -e "\033[36m[INFO] use flannel iface: $flannel_iface\033[0m"
fi

# STEP 07: add hostname and IP address into hosts
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

# STEP 09: install and configure flannel
if command_exists flanneld && [ -e /usr/libexec/flannel/mk-docker-opts.sh ]; then
  echo -e "\033[36[INFO] flanneld command already exists on this system.\033[0m"
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

# STEP 10: install and configure docker
if command_exists docker ; then
  echo -e "\033[36m[INFO] docker command already exists on this system.\033[0m"
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
if [ "$registry_type" == "http" ]; then
  registry_arg=$(echo $registry_arg | sed -e 's/https:\/\///g')
  registry_arg=$(echo $registry_arg | sed -e 's/http:\/\///g')
  if [ "$registry_arg" != "" ]; then
    docker_insecure_registry="INSECURE_REGISTRY=\"--insecure-registry $registry_arg\""
  fi
else
  registry_arg=$(echo $registry_arg | sed -e 's/https:\/\///g')
  mkdir -p $registry_crt_path/$registry_arg
  registry_crt="$registry_crt_path/$registry_arg/registry.crt"
  registry_crt_url="$domeos_server$registry_crt_url"
  # TODO domeos offline
  #cp $current_path/registry.crt $registry_crt
  curl -o $registry_crt $registry_crt_url
  if [ -f $registry_crt ]; then
    echo -e "\033[32m[OK] install docker registry certification\033[0m"
  else
    echo -e "\033[31m[ERROR] install docker secure registry certification failed\033[0m"
    exit 1
  fi
fi
docker_opts="$docker_opts --log-level=$docker_log_level"
docker_opts="DOCKER_OPTS=\"$docker_opts\""
echo $docker_opts > /etc/sysconfig/docker
echo $docker_insecure_registry >> /etc/sysconfig/docker
docker_storage_options="DOCKER_STORAGE_OPTIONS=\"--graph $docker_graph_path\""
echo $docker_storage_options >> /etc/sysconfig/docker
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

# STEP 11: start flannel
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

# STEP 12: start docker 
systemctl start docker
sleep 10
systemctl status -l docker

# STEP 13: start kube-proxy
systemctl stop kube-proxy
echo "# configure file for kube-proxy
# --master
KUBE_MASTER='--master=$api_server'
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

# STEP 14: start kubelet
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
# --log-dir
LOG_DIR='--log-dir=$kubelet_log_dir'
# --root-dir
ROOT_DIR='--root-dir=$kubelet_root_dir'
# other parameters
KUBELET_OPTS='$kubelet_opts'
" > /etc/sysconfig/kubelet
echo "[Unit]
Description=kubelet

[Service]
EnvironmentFile=/etc/sysconfig/kubelet
ExecStart=$current_path/kubelet \$API_SERVERS \\
          \$ADDRESS \\
          \$ALLOW_PRIVILEGED \\
          \$POD_INFRA \\
          \$CLUSTER_DNS \\
          \$CLUSTER_DOMAIN \\
          \$MAX_PODS \\
          \$LOG_DIR \\
          \$ROOT_DIR \\
          \$KUBELET_OPTS
Restart=on-failure
" > /lib/systemd/system/kubelet.service
systemctl daemon-reload
systemctl start kubelet
sleep 5
systemctl status -l kubelet

# STEP 15: configure and start monitor agent
monitor_transfer=$(echo $monitor_transfer | sed -e 's/https:\/\///g')
monitor_transfer=$(echo $monitor_transfer | sed -e 's/http:\/\///g')
monitor_transfers=(${monitor_transfer//,/ })
format_transfer=
for i in ${monitor_transfers[@]}
do
  format_transfer=$format_transfer,\"$i\"
done
format_transfer=$(echo $format_transfer | sed -e 's/,//')
docker rm -f agent
docker run -d --restart=always -p 2222:2222 -e HOSTNAME="\"$node_hostname\"" -e TRANSTER_ADDR="[$format_transfer]" -e TRANSFER_INTERVAL="10" -v /:/rootfs:ro -v /var/run:/var/run:rw -v /sys:/sys:ro -v /var/lib/docker/:/var/lib/docker:ro -v /var/run/docker.sock:/var/run/docker.sock -v /usr/bin/docker:/bin/docker -v /lib64:/lib64:ro --name agent $domeos_agent_image

# STEP 16: patch labels for node
labels=($(echo $node_labels | sed 's/,/ /g'))
for label in "${labels[@]}"
do
  $current_path/kubectl --server=$api_server label node $node_hostname $label
done
