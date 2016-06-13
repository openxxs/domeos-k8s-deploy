#!/bin/sh

# stop kubernetes node
# openxxs@gmail.com
# 2016-04-21

# Usage: sudo sh stop-k8s-node.sh

# STEP 01: stop kube-proxy
echo "[INFO] stopping kube-proxy..."
systemctl stop kube-proxy
sleep 3

# STEP 02: stop kubelet
echo "[INFO] stopping kubelet.."
systemctl stop kubelet
sleep 3

# STEP 03: stop all docker containers
echo "[INFO] stopping docker containers..."
ids=(`docker ps | grep -v "CONTAINER" | awk '{print $1}'`)
for i in "${ids[@]}" ; do
  docker stop $i
done
sleep 10

# STEP 04: stop docker
echo "[INFO] stopping docker..."
systemctl stop docker
sleep 10

# STEP 05: stop flannel
echo "[INFO] stopping flannel..."
systemctl stop flanneld
sleep 3

# STEP 06: clean related bridges and iptables
ip link delete docker0
ip link delete flannel.1
iptables -F
iptables -t nat -F
