

all: packages

packages:
	if ! dpkg -l | grep gnupg -c >>/dev/null; then sudo apt-get update; sudo apt-get -y install gnupg; fi
	if ! dpkg -l | grep python-pip -c >>/dev/null; then sudo apt-get update; sudo apt-get -y install python-pip; fi
	sudo -H pip -q install python-gnupg
	sudo -H pip -q install Flask
	sudo -H pip -q install flask-login
	sudo -H pip -q install flask-session
	sudo -H pip -q install pygal
