#
# Regular cron jobs for the rtpflood package
#
0 4	* * *	root	[ -x /usr/bin/rtpflood_maintenance ] && /usr/bin/rtpflood_maintenance
