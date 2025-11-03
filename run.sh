#!/bin/bash

set -o pipefail
set -e

# build
cargo build --release
# set capability
sudo setcap cap_net_admin=epi ./target/release/tcprs

./target/release/tcprs &
pid=$!

# set ip class
sudo ip address add 192.168.0.1/24 dev tun
sudo ip link set up dev tun

trap "kill $pid" INT TERM
wait $pid

