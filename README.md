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
the hwsim devices at a higher priority than with local forwarding.

`tests/test-001.sh` contains an example of the latter setup.

