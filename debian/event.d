#!/bin/sh
set -e

# only run this script if the system is going into suspend
if [ "$1" != "suspend" ]; then
	exit 0
fi

# unmount any automounted filesystems when suspending

invoke-rc.d autofs stop

