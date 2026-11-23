#!/bin/bash
# shape.sh off | RATE_KBIT DELAY_MS QUEUE_BYTES [LOSS_PCT]: shapes TCP to and from port 8443 on eth0.
dev=eth0 port=8443
tc qdisc del dev $dev ingress 2>/dev/null
tc qdisc del dev $dev root 2>/dev/null
tc qdisc del dev ifb0 root 2>/dev/null
[ "$1" = off ] && { echo shaping off; exit 0; }
rate=$1 delay=$2 queue=$3 loss=${4:-0}
modprobe ifb numifbs=1 2>/dev/null
ip link show ifb0 >/dev/null 2>&1 || ip link add ifb0 type ifb
ip link set ifb0 up
ethtool -K $dev gro off lro off 2>/dev/null
set -e
tc qdisc add dev $dev handle ffff: ingress
tc filter add dev $dev parent ffff: protocol ip u32 match ip protocol 6 0xff match ip dport $port 0xffff \
  action mirred egress redirect dev ifb0
l=""
[ "$loss" != 0 ] && l="loss random ${loss}%"
tc qdisc add dev ifb0 root handle 1: netem limit 1000000 delay ${delay}ms $l
tc qdisc add dev ifb0 parent 1:1 handle 10: tbf rate ${rate}kbit burst 64kb limit $queue
tc qdisc add dev $dev root handle 1: prio
tc qdisc add dev $dev parent 1:1 handle 11: netem limit 1000000 delay ${delay}ms
tc filter add dev $dev parent 1: protocol ip u32 match ip protocol 6 0xff match ip sport $port 0xffff flowid 1:1
echo "shaping up ${rate}kbit queue ${queue}B loss ${loss}%, ${delay}ms each way"
