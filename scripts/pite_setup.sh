#! /usr/bin/env bash

# This script disables NMI watchdogs and enables access to the rdpmc
# instruction, which is required to use PITE for reading uop counters
# REQUIRES ROOT PRIVILEGES
#
# See: https://github.com/obilaniu/libpfc

set -ex


modprobe -ar iTCO_wdt iTCO_vendor_support

echo 0 > /proc/sys/kernel/nmi_watchdog

echo 2 > /sys/bus/event_source/devices/cpu/rdpmc

