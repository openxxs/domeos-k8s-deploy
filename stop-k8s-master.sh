#!/bin/sh

# stop kubernetes master
# openxxs@gmail.com
# 2016-04-22

# Usage: sudo sh stop-k8s-master.sh

# STEP 01: stop kube-proxy
echo "[INFO] stopping kube-proxy..."
systemctl stop kube-proxy
sleep 1

# STEP 02: stop kube-controller-manager
echo "[INFO] stopping kube-controller-manager..."
systemctl stop kube-controller
sleep 1

# STEP 03: stop kube-scheduler
echo "[INFO] stopping kube-scheduler..."
systemctl stop kube-scheduler
sleep 1

# STEP 04: stop kube-apiserver
echo "[INFO] stopping kube-apiserver..."
systemctl stop kube-apiserver
sleep 3

# STEP 05: stop docker
echo "[INFO] stopping docker..."
systemctl stop docker
sleep 5

# STEP 06: stop flanneld
echo "[INFO] stopping flannel..."
systemctl stop flanneld
sleep 1

# STEP 07: clean releated bridges and iptables
ip link delete docker0
ip link delete flannel.1
iptables -F
iptables -t nat -F
