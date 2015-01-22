# Introduction

This is a wireless medium simulation tool for Linux, based on the netlink API
implemented in the `mac80211_hwsim` kernel driver.  Unlike the default in-kernel
forwarding mode of `mac80211_hwsim`, wmediumd allows simulating frame loss and
delay.

This version is forked from an earlier version, hosted here:

    https://github.com/cozybit/wmediumd

# Prerequisites

First, you need a recent Linux kernel with the `mac80211_hwsim` module
available.  If you do not have this module, you may be able to build it using
the [backports project](https://backports.wiki.kernel.org/index.php/Main_Page).

Wmediumd requires libnl3.0.

# Building
```
cd wmediumd && make
```

# Using Wmediumd

Starting wmediumd with an appropriate config file is enough to make frames
pass through wmediumd:
```
sudo modprobe mac80211_hwsim radios=2
sudo ./wmediumd/wmediumd -c tests/2node.cfg &
# run some hwsim test
```
However, please see the next section on some potential pitfalls.

A complete example using network namespaces is given at the end of
this document.

## Gotchas

### Allowable MAC addresses

The kernel only allows wmediumd to work on the second available hardware
address, which has bit 6 set in the most significant octet
(i.e. 42:00:00:xx:xx:xx, not 02:00:00:xx:xx:xx).  Set this appropriately
using 'ip link set address'.

### Rates

wmediumd's rate table is currently hardcoded to 802.11a OFDM rates.
Therefore, either operate wmediumd networks in 5 GHz channels, or supply
a rateset for the BSS with no CCK rates.

### Send-to-self

By default, traffic between local devices in Linux will not go over
the wire / wireless medium.  This is true of vanilla hwsim as well.
In order to make this happen, you need to either run the hwsim interfaces
in separate network namespaces, or you need to set up routing rules with
the hwsim devices at a higher priority than local forwarding.

`tests/test-001.sh` contains an example of the latter setup.

# Example session

The following sequence of commands establishes a two-node mesh using network
namespaces.
```
sudo modprobe -r mac80211_hwsim
sudo modprobe mac80211_hwsim
sudo ./wmediumd/wmediumd -c ./tests/2node.cfg

# in window 2
sudo lxc-unshare -s NETWORK bash
ps | grep bash  # note pid

# in window 1
sudo iw phy phy2 set netns $pid

sudo ip link set wlan1 down
sudo iw dev wlan1 set type mp
sudo ip link set addr 42:00:00:00:00:00 dev wlan1
sudo ip link set wlan1 up
sudo ip addr add 10.10.10.1/24 dev wlan1
sudo iw dev wlan1 set channel 149
sudo iw dev wlan1 mesh join meshabc

# in window 2
ip link set lo

sudo ip link set wlan2 down
sudo iw dev wlan2 set type mp
sudo ip link set addr 42:00:00:00:01:00 dev wlan2
sudo ip link set wlan2 up
sudo ip addr add 10.10.10.2/24 dev wlan2
sudo iw dev wlan2 set channel 149
sudo iw dev wlan2 mesh join meshabc

iperf -u -s -i 10 -B 10.10.10.2

# in window 1
iperf -u -c 10.10.10.2 -b 100M -i 10 -t 120
```
