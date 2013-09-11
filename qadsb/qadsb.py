#!/usr/bin/env python

import sys, os, subprocess, getpass, crypt, json, random

user = None
passwd = None
ipaddr = None
sshport = None
torrentport = None
ftpport = None
settingspath = None
settings = None

def getString(label, ispassword=False, default=None):
	pass1 = ""
	pass2 = ""
	if ispassword == True:
		while pass1 == pass2 and pass1 == "" and pass2 == "":
			pass1 = getpass.getpass(label)
			pass2 = getpass.getpass("Confirm: ")
			if pass1 == pass2:
				return pass1
			else:
				print "Passwords do not match, enter passwords again."
				pass1 = ""
				pass2 = ""
				continue
	else:
		newvar = ""
		while newvar == "":
			newvar = raw_input(label)
			if newvar == "" or newvar == None and default != None:
				newvar = default
			if newvar == "" or newvar == None:
				continue
			else:
				return newvar

def getSettings():
	global user, settingspath, settings
	base = "/home/"+user+"/.config/transmission"
	if settingspath == None:
		settingspath = base + "-daemon/settings.json"
	with open(settingspath, 'rb') as fp:
		settings = json.load(fp)

def setSettings():
	global settingspath, settings
	with open(settingspath, 'wb') as fp:
		json.dump(settings, fp)

def exc(com):
	p = subprocess.Popen(com, stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True)
	(output, err) = p.communicate()
	if err == "":
		return True
	else:
		return err
		print "Error: (" + str(err) + ")"

def createSSLCACert():
	global user, passwd, ipaddr
	exc("cd /etc/qadsb/")
	exc("rm -r /etc/qadsb/ssl/CA")
	exc("mkdir -p /etc/qadsb/ssl/CA/newcerts")
	exc("mkdir -p /etc/qadsb/ssl/CA/private")
	exc("cd /etc/qadsb/ssl/CA")
	
	exc("echo '01' > serial  && touch index.txt")
	exc("cp /etc/qadsb/root.ca.cacert.conf.template /etc/qadsb/ssl/CA/caconfig.cnf")
	exc("perl -pi -e \"s/<username>/"+user+"/g\" /etc/qadsb/ssl/CA/caconfig.cnf")
	exc("perl -pi -e \"s/<servername>/"+ipaddr+"/g\" /etc/qadsb/ssl/CA/caconfig.cnf")
	
	exc("openssl req -new -x509 -extensions v3_ca -keyout private/cakey.pem -passout pass:"+passwd+" -out cacert.pem -days 3650 -config /etc/qadsb/ssl/CA/caconfig.cnf")
	exc("openssl req -new -nodes -out /etc/qadsb/ssl/CA/req.pem -passout pass:"+passwd+" -config /etc/qadsb/ssl/CA/caconfig.cnf")
	exc("openssl ca -batch -out /etc/qadsb/ssl/CA/cert.pem -config /etc/qadsb/ssl/CA/caconfig.cnf -passin pass:"+passwd+" -infiles /etc/qadsb/ssl/CA/req.pem")
	exc("mv /etc/qadsb/ssl/CA/cert.pem /etc/qadsb/ssl/CA/tmp.pem")
	exc("openssl x509 -in /etc/qadsb/ssl/CA/tmp.pem -out /etc/qadsb/ssl/CA/cert.pem")
	exc("cat /etc/qadsb/ssl/CA/key.pem /etc/qadsb/ssl/CA/cert.pem > /etc/qadsb/ssl/CA/key-cert.pem")
	
	exc("cp /etc/qadsb/ssl/CA/cacert.pem /etc/qadsb/ssl")
	exc("cp /etc/qadsb/ssl/CA/cert.pem /etc/qadsb/ssl")
	exc("cp /etc/qadsb/ssl/CA/key-cert.pem /etc/qadsb/ssl")
	exc("cp /etc/qadsb/ssl/CA/key.pem /etc/qadsb/ssl")
	exc("cp /etc/qadsb/ssl/CA/private/cakey.pem /etc/qadsb/ssl")
	exc("cp /etc/qadsb/ssl/CA/req.pem /etc/qadsb/ssl")
	
	exc("chmod 600 /etc/qadsb/ssl/*")
	exc("chmod 644 /etc/qadsb/ssl/cert.pem")
	exc("chmod 644 /etc/qadsb/ssl/key.pem")

def setupDirectory():
	print "Setting up directories and grabbing git repository..."
	exc("rm -f -r /etc/qadsb")
	exc("apt-get --yes install git")
	result = exc("git clone http://www.github.com/Beelzebarb/quick-and-dirty-seedbox.git /etc/qadsb")
	if result != True:
		print "There seems to be a problem with the github repository, without this, the script will not work, exiting now."
		sys.exit(1)
	exc("mv /etc/qadsb/qadsb/* /etc/qadsb")
	exc("rm -r /etc/qadsb/qadsb")

def installFTP():
	print "Installing vsftpd and creating ssl certificates..."
	exc("mkdir -p /etc/ssl/private/")
	exc("openssl req -x509 -nodes -days 365 -newkey rsa:1024 -keyout /etc/ssl/private/vsftpd.pem -out /etc/ssl/private/vsftpd.pem -config /etc/qadsb/ssl/CA/caconfig.cnf")
	result = exc("apt-get --yes install vsftpd")
	if result == True:
		return True
	else:
		return False

def installFail2Ban():
	print "Installing and configuring fail2ban..."
	if exc("apt-get --yes install fail2ban") == True:
		exc("cp /etc/fail2ban/jail.conf /etc/fail2ban/jail.conf.original")
		exc("cp /etc/qadsb/etc.fail2ban.jail.conf.template /etc/fail2ban/jail.conf")
		exc("fail2ban-client reload")

def installTransmission():
	global user, passwd
	print "Installing transmission-daemon..."
	result = exc("apt-get --yes install transmission-cli transmission-daemon transmission-common")
	if result == True:
		res2 = engageTransmission()
		if res2 == True:
			print "Installation successful, service running, grabbing settings file..."
			if setTransmissionConfig() == True:
				print "Settings file retreived, parsing now..."
				getSettings()
			else:
				print "Settings file failed to load, error, exiting script."
				sys.exit(1)
	else:
		print "ERROR: " + str(result) + ", exiting script."
		sys.exit(1)

def engageTransmission():
	result = subprocess.check_output(['ps', '-A'])
	if not 'transmission-da' in result:
		exc("service transmission-daemon start")
	elif 'transmission-da' in result:
		exc("service transmission-daemon restart")
	res2 = subprocess.check_output(['ps', '-A'])
	if 'transmission-da' in res2:
		return True
	else:
		return False

def setTransmissionConfig():
	global settingspath
	path = "/home/"+user+"/.config/transmission-daemon"
	exc("export TRANSMISSION_HOME="+path)
	if not os.path.exists(path):
		exc("mkdir -p "+path)
		exc("cp /etc/qadsb/trans-config/settings.json " + path + "/settings.json")
		if os.path.exists(path + "/settings.json"):
			exc("chown -R "+user+":"+user+" /home/"+user+"/.config/transmission-daemon/*")
			return True
		else:
			return False
	else:
		if os.path.exists(path + "/settings.json") == False:
			exc("cp /etc/qadsb/trans-config/settings.json " + path + "/settings.json")
			if os.path.exists(path + "/settings.json"):
				exc("chown -R "+user+":"+user+" /home/"+user+"/.config/transmission-daemon/*")
				return True
			else:
				return False
		else:
			exc("chown -R "+user+":"+user+" /home/"+user+"/.config/transmission-daemon/*")
			return True

def configTransmission():
	global settings, user, passwd, torrentport
	print "Configuring transmission...",
	settings['download-dir'] = "/home/"+user+"/Downloads"
	settings['watch-dir'] = "/home/"+user+"/torrents"
	settings['watch-dir-enabled'] = True
	settings['rpc-username'] = user
	settings['rpc-password'] = passwd
	settings['rpc-enabled'] = True
	settings['peer-limit-global'] = 1024
	settings['peer-limit-torrent'] = 1024
	settings['peer-port'] = torrentport
	settings['encryption'] = 1
	settings['ratio-limit-enabled'] = False
	setSettings()
	print "done, restarted the service..."
	exc("service transmission-daemon restart")

def configFTP():
	global ftpport
	print "Configuring vsftpd..."
	exc("perl -pi -e \"s/anonymous_enable\=YES/\#anonymous_enable\=YES/g\" /etc/vsftpd.conf")
	exc("perl -pi -e \"s/connect_from_port_20\=YES/#connect_from_port_20\=YES/g\" /etc/vsftpd.conf")
	exc("echo \"listen_port="+str(ftpport)+"\" | tee -a /etc/vsftpd.conf >> /dev/null")
	exc("echo \"ssl_enable=YES\" | tee -a /etc/vsftpd.conf >> /dev/null")
	exc("echo \"allow_anon_ssl=YES\" | tee -a /etc/vsftpd.conf >> /dev/null")
	exc("echo \"force_local_data_ssl=YES\" | tee -a /etc/vsftpd.conf >> /dev/null")
	exc("echo \"force_local_logins_ssl=YES\" | tee -a /etc/vsftpd.conf >> /dev/null")
	exc("echo \"ssl_tlsv1=YES\" | tee -a /etc/vsftpd.conf >> /dev/null")
	exc("echo \"ssl_sslv2=NO\" | tee -a /etc/vsftpd.conf >> /dev/null")
	exc("echo \"ssl_sslv3=NO\" | tee -a /etc/vsftpd.conf >> /dev/null")
	exc("echo \"require_ssl_reuse=NO\" | tee -a /etc/vsftpd.conf >> /dev/null")
	exc("echo \"ssl_ciphers=HIGH\" | tee -a /etc/vsftpd.conf >> /dev/null")
	exc("echo \"rsa_cert_file=/etc/ssl/private/vsftpd.pem\" | tee -a /etc/vsftpd.conf >> /dev/null")
	exc("echo \"local_enable=YES\" | tee -a /etc/vsftpd.conf >> /dev/null")
	exc("echo \"write_enable=YES\" | tee -a /etc/vsftpd.conf >> /dev/null")
	exc("echo \"local_umask=022\" | tee -a /etc/vsftpd.conf >> /dev/null")
	exc("echo \"chroot_local_user=YES\" | tee -a /etc/vsftpd.conf >> /dev/null")
	exc("echo \"chroot_list_file=/etc/vsftpd.chroot_list\" | tee -a /etc/vsftpd.conf >> /dev/null")

def configSSH():
	global sshport
	print "Configuring ssh for optimal security..."
	exc("perl -pi -e \"s/Port 22/Port "+str(sshport)+"1/g\" /etc/ssh/sshd_config")
	exc("perl -pi -e \"s/PermitRootLogin yes/PermitRootLogin no/g\" /etc/ssh/sshd_config")
	exc("perl -pi -e \"s/#Protocol 2/Protocol 2/g\" /etc/ssh/sshd_config")
	exc("perl -pi -e \"s/X11Forwarding yes/X11Forwarding no/g\" /etc/ssh/sshd_config")
	exc("groupadd sshdusers")
	exc("echo \"\" | tee -a /etc/ssh/sshd_config > /dev/null")
	exc("echo \"UseDNS no\" | tee -a /etc/ssh/sshd_config > /dev/null")
	exc("echo \"AllowGroups sshdusers\" >> /etc/ssh/sshd_config")
	exc("mkdir -p /usr/share/terminfo/l/")
	exc("cp /lib/terminfo/l/linux /usr/share/terminfo/l/")
	exc("service ssh restart")

def createUser():
	global user, passwd
	print "Creating user " + user + "..."
	shapasswd = crypt.crypt(passwd, "22")
	exc("useradd -m -p "+shapasswd+" "+user)
	exc("mkdir /home/"+user+"/torrents")
	exc("mkdir /home/"+user+"/Downloads")
	exc("chown -R " + user + ":" + user + " /home/" + user + "/*")
	exc("usermod -a -G sshdusers " + user)

def getVars():
	global user, passwd, ipaddr, sshport, ftpport, torrentport
	user = getString("You must create a new user for the seedbox, enter a username: ")
	passwd = getString("Please enter a password for " + user + ": ", True)
	ipaddr = getString("IP Address of your seedbox: ", False, "127.0.0.1")
	sshport = int(getString("Enter the port number you wish to use for SSH (Usually 22): ", False, 22))
	ftpport = int(getString("FTP Port number to use (Usually 21): ", False, 21))
	torrentport = int(getString("Port for torrents (Must be above 49152, leave blank for random): ", False, random.randint(49152, 65535)))

def outputBeginning():
	print "#"
	print "#"
	print "# The quick and dirty seedbox script"
	print "#   By Beelzebarb"
	print "#"
	print "#"
	print "#"
	print ""

def main():
	outputBeginning()
	if not os.geteuid() == 0: # User didn't run script with root privilegdes
		sys.exit("This script must be run as root")
	setupDirectory()
	getVars()
	createUser()
	#installFail2Ban()
	createSSLCACert()
	installFTP()
	configFTP()
	#installTransmission()
	#configTransmission()
	#configSSH()
if __name__ == "__main__":
	main()
