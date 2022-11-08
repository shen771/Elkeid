#!/bin/bash
mkdir -p /ko_output
BUILD_VERSION=$(cat LKM/src/init.c | grep MODULE_VERSION | awk -F '"' '{print $2}')
KO_NAME=$(grep "MODULE_NAME" ./LKM/Makefile | grep -m 1 ":=" | awk '{print $3}')

for each_lt_version in `curl http://mirrors.coreix.net/elrepo-archive-archive/kernel/el7/x86_64/RPMS/ | grep el7.elrepo.x86_64.rpm | grep kernel-lt-devel | sed -r 's/.*href="([^"]+).*/\1/g' | sed -r 's/kernel-lt-devel-([^"]+).el7.elrepo.x86_64.rpm/\1/g'`
do 
    wget "http://mirrors.coreix.net/elrepo-archive-archive/kernel/el7/x86_64/RPMS/kernel-lt-devel"-$each_lt_version.el7.elrepo.x86_64.rpm
    wget "http://mirrors.coreix.net/elrepo-archive-archive/kernel/el7/x86_64/RPMS/kernel-lt-tools"-$each_lt_version.el7.elrepo.x86_64.rpm
    wget "http://mirrors.coreix.net/elrepo-archive-archive/kernel/el7/x86_64/RPMS/kernel-lt-tools-libs"-$each_lt_version.el7.elrepo.x86_64.rpm
    
    yum remove -y kernel-devel kernel-lt-devel kernel-ml-devel 
    yum remove -y kernel-tools kernel-lt-tools kernel-ml-tools 
    yum remove -y kernel-tools-libs kernel-lt-tools-libs kernel-ml-tools-libs
    
    rpm -ivh --force ./kernel*.rpm 
    rm -f ./kernel*.rpm 
    KV=$each_lt_version.el7.elrepo.x86_64
    KVERSION=$KV make -C ./LKM clean || true 
    BATCH=true KVERSION=$KV make -C ./LKM -j all || true 
     sha256sum  ./LKM/${KO_NAME}.ko | awk '{print $1}' > /ko_output/${KO_NAME}_${BUILD_VERSION}_${KV}_amd64.sign  || true  
    mv ./LKM/${KO_NAME}.ko /ko_output/${KO_NAME}_${BUILD_VERSION}_${KV}_amd64.ko || true 
    KVERSION=$KV  make -C ./LKM clean || true
done