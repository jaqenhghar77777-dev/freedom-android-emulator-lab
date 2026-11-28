#!/data/data/com.termux/files/usr/bin/sh
# A scheduler launch has no arguments. An interactive local launch may select a phone.py command.
if [ "$#" -eq 0 ]; then set -- once; fi
exec /data/data/com.termux/files/usr/bin/env -i HOME=/data/data/com.termux/files/home PREFIX=/data/data/com.termux/files/usr PATH=/data/data/com.termux/files/usr/bin:/system/bin LC_ALL=C /data/data/com.termux/files/usr/bin/python -I -S -B /data/data/com.termux/files/home/.freedom-finish/app/phone.py "$@"
