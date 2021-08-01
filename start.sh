#!/bin/bash
export EDITOR=vi
export PIP_USER=yes
#export PATH=${HOME}/.local/bin:$PATH
alias startmirror="cd ~/github/bots/lotidemirror;/usr/bin/screen -dmS mirror python3 lotidemirror.py"
#export LC_ALL="en_US.UTF-8"


BOTDIR="${HOME}/github/bots/lotidemirror"
cd $BOTDIR

export TZ=EST5EDT
BOTPIDFILE="${BOTDIR}/bot.pid"
BOTPID=$(cat ${BOTPIDFILE})

if [ -f ${BOTDIR}/DONOTSTART ]; then
	exit 0
fi

if ! ps -ef |awk '{print $2}' |grep -q ${BOTPID}; then
    	/usr/bin/screen -L -dmS mirror python3 -u lotidemirror.py
else
	echo "Bot running: pid=${BOTPID}" 
	exit 0
fi

