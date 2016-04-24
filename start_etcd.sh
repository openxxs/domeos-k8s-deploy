#!/bin/sh

# start etcd cluster
# xiaoshengxu@sohu-inc.com
# 2016-03-01
# update 2016-04-21: format output

# Usage:   sudo sh start_etcd.sh <number>
# Require: etcd_node_list.conf
# Example: sudo sh start_etcd.sh 1
# Tips:    1) number begin with 1
#          2) calibrate system time for all nodes: ntpdate ntp.sohu.com

# STEP 01: check arguments
node_id=$1
if [ "$1" == "" ]; then
  echo "Usage: sudo sh start_etcd.sh <number>"
  exit 1
fi
tmp=`echo $node_id | sed 's/[0-9]//g'`
if [ -n "${tmp}" ]; then
  echo -e "\033[31m[ERROR] Argument must be integer\033[0m"
  exit 1
fi
if [ $node_id -lt 1 ]; then
  echo -e "\033[31m[ERROR] number $node_id is less than 1\033[0m"
  exit 1
fi

# STEP 02: assign append arguments
current_path=$(pwd)
data_dir=$current_path/etcd-data
conf_file=$current_path/etcd_node_list.conf
cluster_token='k8s-etcd-cluster'
name_prefix='k8sEtcd'
peer_port=4010
client_port=4012
etcd_opts="--data-dir $data_dir"
mkdir -p $data_dir
chmod +x $current_path/etcd

# STEP 03: get all node ips and set current node ip
node_ips=
node_len=0
current_node_ip=
clusters=
while IFS='' read -r line || [[ -n "$line" ]]; do
  node_ips[$node_len]="$line"
  ((node_len++))
  if [ $node_len -eq 1 ]; then
    clusters=$name_prefix$node_len="http://$line:$peer_port"
  else
    clusters=$clusters,$name_prefix$node_len="http://$line:$peer_port"
  fi
done < $conf_file
if [ $node_id -gt $node_len ]; then
  echo -e "\033[31m[ERROR] number $node_id is out of range\033[0m"
  exit 1
fi
current_node_ip="${node_ips[$((node_id-1))]}"

# STEP 04: compare selected node ip with local ips
local_ips=(`ip addr show | grep inet | grep -v inet6 | grep brd | awk '{print $2}' | cut -f1 -d '/'`)
exist_ip=0
for i in ${local_ips[@]}
do
  if [ "$i" == "$current_node_ip" ]; then
    exist_ip=1
    break
  fi
done
if [ $exist_ip -eq 0 ]; then
  echo -e "\033[31m[ERROR] IP $current_node_ip is not node IP\033[0m"
  exit 1
fi

# STEP 05: install and configure etcd
echo "# configure file for etcd.service
# -name
ETCD_NAME='-name $name_prefix$node_id'
# -initial-advertise-peer-urls
INITIAL_ADVERTISE_PEER_URLS='-initial-advertise-peer-urls http://$current_node_ip:$peer_port'
# -listen-peer-urls
LISTEN_PEER_URLS='-listen-peer-urls http://0.0.0.0:$peer_port'
# -advertise-client-urls
ADVERTISE_CLIENT_URLS='-advertise-client-urls http://$current_node_ip:$client_port'
# -listen-client-urls
LISTEN_CLIENT_URLS='-listen-client-urls http://0.0.0.0:$client_port'
# -initial-cluster-token
INITIAL_CLUSTER='-initial-cluster-token $cluster_token'
# -initial-cluster
INITIAL_CLUSTER='-initial-cluster $clusters'
# -initial-cluster-state
INITIAL_CLUSTER_STATE='-initial-cluster-state new'
# other parameters
ETCD_OPTS='$etcd_opts'
" > /etc/sysconfig/etcd
echo "[Unit]
Description=ETCD
[Service]
Type=notify
EnvironmentFile=/etc/sysconfig/etcd
ExecStart=$current_path/etcd \$ETCD_NAME \\
          \$INITIAL_ADVERTISE_PEER_URLS \\
          \$LISTEN_PEER_URLS \\
          \$ADVERTISE_CLIENT_URLS \\
          \$LISTEN_CLIENT_URLS \\
          \$INITIAL_CLUSTER_TOKEN \\
          \$INITIAL_CLUSTER \\
          \$INITIAL_CLUSTER_STATE \\
          \$ETCD_OPTS
Restart=always
" > /lib/systemd/system/etcd.service

# STEP 06: start etcd
systemctl stop etcd
systemctl daemon-reload
systemctl start etcd
sleep 5
systemctl status -l etcd
