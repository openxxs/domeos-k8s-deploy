#!/bin/sh

# change hostname for centos
# sh change_hostname.sh <new hostname>
# openxxs@gmail.com
# 2016-01-11
# update 2016-04-21: info selected ip address when update /etc/hosts

network_file=/etc/sysconfig/network
hostname_file=/etc/hostname
hosts_file=/etc/hosts
new_hostname=$1

# STEP 01: check parameters
if [ "$1" == "" ]; then
  echo "Usage: sudo sh change_hostname.sh <new-hostname>"
  exit 1
else
  echo -e "\033[36m[INFO] new hostname will be: $1\033[0m"
fi

# STEP 02: modify network configure file
true > network_tmp
while read -a network_info
do
  value=${network_info[@]}
  var=`echo $value | awk '{split($0,a,"="); print a[1]}'`
  if [[ "$var" = HOSTNAME ]]; then
    value=$var=$new_hostname
  fi
  echo $value >> network_tmp
done < $network_file
mv network_tmp $network_file

# STEP 03: modify hostname configure file
echo $new_hostname > $hostname_file

# STEP 04: modify hosts
ips=(`ip addr show | grep inet | grep -v inet6 | grep brd | awk '{print $2}' | cut -f1 -d '/'`)
if [ "${ips[0]}" == "" ]; then
  echo -e "\033[33m[WARN] get ip address error, you need add '<ip_address> $new_hostname' record into $hosts_file by yourself\033[0m"
else
  ip=${ips[0]}
  exist_hosts=0
  while IFS='' read -r line || [[ -n "$line" ]]; do
    ip_tmp=$(echo $line | cut -f1 -d ' ')
    hostname_tmp=$(echo $line | cut -f2 -d ' ')
    if [ "$ip" == "$ip_tmp" ]; then
      if [ "$new_hostname" == "$hostname_tmp" ]; then
        exist_hosts=1
        break
      fi
    fi
  done < $hosts_file
  if [ $exist_hosts -eq 0 ]; then
    echo -e "\033[32m[INFO] add '$ip $new_hostname' record into $hosts_file . You can modify $hosts_file by yourself if you want to use other ip for $new_hostname\033[0m"
    echo "$ip $new_hostname" >> $hosts_file
  fi
fi

# STEP 05: set hostname and restart network
hostname $new_hostname
/etc/init.d/network restart
