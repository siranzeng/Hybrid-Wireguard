#!/bin/sh

#
# Artefacts for Usenix submission #29 "A Tale of Two Worlds, a Formal Story of WireGuard Hybridization"
#

## /!\ root password is required /!\ 

sudo apt update -y
sudo apt full-upgrade -y

sudo apt install curl libssl-dev cmake clang 
curl https://sh.rustup.rs -sSf | sh
