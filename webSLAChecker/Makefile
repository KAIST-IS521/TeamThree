

all: packages

packages:
	if ! dpkg -l | grep gnupg -c >>/dev/null; then sudo apt-get update; sudo apt-get install gnupg; fi
	if ! dpkg -l | grep python-pip -c >>/dev/null; then sudo apt-get update; sudo apt-get install python-pip; fi
	sudo -H pip -q install python-gnupg
