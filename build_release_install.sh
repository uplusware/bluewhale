#!/bin/bash
SCRIPT_DIR=$(cd "$(dirname "$0")"; pwd)
cd ${SCRIPT_DIR}/src/
make clean
make
cd ${SCRIPT_DIR}
chmod a+x ${SCRIPT_DIR}/release.sh
${SCRIPT_DIR}/release.sh 0.1 beta ubuntu
sudo ${SCRIPT_DIR}/ubuntu-bluewhale-bin-beta-x86_64-linux/install.sh
sudo /etc/init.d/bwgated restart