#!/bin/sh

# clean all kubernetes resources in all namespace
# openxxs@gmail.com
# 2016-04-22

# Usage:   sudo sh clean-k8s-resource.sh <kube_apiserver_address>
# Example: sudo sh clean-k8s-resource.sh 0.0.0.1:8080

# STEP 01: set kubectl command
if [ "$1" == "" ]; then
  echo "Usage: sudo sh clean-k8s-resource.sh <kube_apiserver_address>"
  exit 1
fi
kubectl="kubectl --server $1"

# STEP 02: get all namespaces
namespaces=(`$kubectl get namespace | grep -v 'NAME' | awk '{print $1}'`)

# STEP 03: delete job, svc, rc and pod in all namespaces
for namespace in "${namespaces[@]}" ; do
  ids=(`$kubectl --namespace=$namespace get job | grep -v 'NAME' | awk '{print $1}'`)
  for i in "${ids[@]}" ; do
    echo "deleting job $i ..."
    $kubectl --namespace=$namespace delete job $i
    sleep 1
  done
  ids=(`$kubectl --namespace=$namespace get svc | grep -v 'NAME' | awk '{print $1}'`)
  for i in "${ids[@]}" ; do
    echo "deleting service $i ..."
    $kubectl --namespace=$namespace delete svc $i
  done
  ids=(`$kubectl --namespace=$namespace get rc | grep -v 'NAME' | awk '{print $1}'`)
  for i in "${ids[@]}" ; do
    echo "deleting rc $i ..."
    $kubectl --namespace=$namespace delete rc $i
    sleep 1
  done
  sleep 10
  ids=(`$kubectl --namespace=$namespace get pod | grep -v 'NAME' | awk '{print $1}'`)
  for i in "${ids[@]}" ; do
    echo "deleting pod $i ..."
    $kubectl --namespace=$namespace delete pod $i
    sleep 1
  done
done
