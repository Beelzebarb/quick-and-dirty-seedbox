#!/usr/bin/env python

import sys, os, subprocess, getpass

user = None
passwd = None
ipaddr = None
sshport = None
ftpport = None

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

def runCommand(com):
	p = subprocess.Popen(com, stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True)
	(output, err) = p.communicate()
	if err == "":
		return True
	else:
		return err
		print "Error: (" + str(err) + ")"

def createSSLCACert(service):
	global user, passwd, ipaddr
	runCommand("cd /etc/qadsb/")
	runCommand("rm -r /etc/qadsb/ssl/CA")
	runCommand("mkdir -p /etc/qadsb/ssl/CA/newcerts")
	runCommand("mkdir -p /etc/qadsb/ssl/CA/private")
	runCommand("cd /etc/qadsb/ssl/CA")
	
	runCommand("echo '01' > serial  && touch index.txt")
	runCommand("cp /etc/qadsb/root.ca.cacert.conf.template /etc/qadsb/ssl/CA/caconfig.cnf")
	runCommand("perl -pi -e \"s/<username>/"+user+"/g\" /etc/qadsb/ssl/CA/caconfig.cnf")
	runCommand("perl -pi -e \"s/<servername>/"+ipaddr+"/g\" /etc/qadsb/ssl/CA/caconfig.cnf")
	
	runCommand("openssl req -new -x509 -extensions v3_ca -keyout private/cakey.pem -passout pass:"+passwd+" -out cacert.pem -days 3650 -config /etc/qadsb/ssl/CA/caconfig.cnf")
	runCommand("openssl req -new -nodes -out /etc/qadsb/ssl/CA/req.pem -passout pass:"+passwd+" -config /etc/qadsb/ssl/CA/caconfig.cnf")
	runCommand("openssl ca -batch -out /etc/qadsb/ssl/CA/cert.pem -config /etc/qadsb/ssl/CA/caconfig.cnf -passin pass:"+passwd+" -infiles /etc/qadsb/ssl/CA/req.pem")
	runCommand("mv /etc/qadsb/ssl/CA/cert.pem /etc/qadsb/ssl/CA/tmp.pem")
	runCommand("openssl x509 -in /etc/qadsb/ssl/CA/tmp.pem -out /etc/qadsb/ssl/CA/cert.pem")
	runCommand("cat /etc/qadsb/ssl/CA/key.pem /etc/qadsb/ssl/CA/cert.pem > /etc/qadsb/ssl/CA/key-cert.pem")
	
	runCommand("cp /etc/qadsb/ssl/CA/cacert.pem /etc/qadsb/ssl")
	runCommand("cp /etc/qadsb/ssl/CA/cert.pem /etc/qadsb/ssl")
	runCommand("cp /etc/qadsb/ssl/CA/key-cert.pem /etc/qadsb/ssl")
	runCommand("cp /etc/qadsb/ssl/CA/key.pem /etc/qadsb/ssl")
	runCommand("cp /etc/qadsb/ssl/CA/private/cakey.pem /etc/qadsb/ssl")
	runCommand("cp /etc/qadsb/ssl/CA/req.pem /etc/qadsb/ssl")
	
	runCommand("chmod 600 /etc/qadsb/ssl/*")
	runCommand("chmod 644 /etc/qadsb/ssl/cert.pem")
	runCommand("chmod 644 /etc/qadsb/ssl/key.pem")
	

def setupDirectory():
	runCommand("rm -f -r /etc/qadsb")
	runCommand("mkdir -p /etc/qadsb")
	runCommand("mkdir -p cd /etc/qadsb/source")
	runCommand("mkdir -p cd /etc/qadsb/users")

def installFTP():
	runCommand("mkdir -p /etc/ssl/private/")
	runCommand("openssl req -x509 -nodes -days 365 -newkey rsa:1024 -keyout /etc/ssl/private/vsftpd.pem -out /etc/ssl/private/vsftpd.pem -config /etc/qadsb/ssl/CA/caconfig.cnf")
	result = runCommand("apt-get --yes install vsftpd")
	if result == True:
		return True
	else:
		return False

def configFTP():
	global ftpport
	runCommand("perl -pi -e \"s/anonymous_enable\=YES/\#anonymous_enable\=YES/g\" /etc/vsftpd.conf")
	runCommand("perl -pi -e \"s/connect_from_port_20\=YES/#connect_from_port_20\=YES/g\" /etc/vsftpd.conf")
	runCommand("echo \"listen_port="+ftpport+"\" | tee -a /etc/vsftpd.conf >> /dev/null")
	runCommand("echo \"ssl_enable=YES\" | tee -a /etc/vsftpd.conf >> /dev/null")
	runCommand("echo \"allow_anon_ssl=YES\" | tee -a /etc/vsftpd.conf >> /dev/null")
	runCommand("echo \"force_local_data_ssl=YES\" | tee -a /etc/vsftpd.conf >> /dev/null")
	runCommand("echo \"force_local_logins_ssl=YES\" | tee -a /etc/vsftpd.conf >> /dev/null")
	runCommand("echo \"ssl_tlsv1=YES\" | tee -a /etc/vsftpd.conf >> /dev/null")
	runCommand("echo \"ssl_sslv2=NO\" | tee -a /etc/vsftpd.conf >> /dev/null")
	runCommand("echo \"ssl_sslv3=NO\" | tee -a /etc/vsftpd.conf >> /dev/null")
	runCommand("echo \"require_ssl_reuse=NO\" | tee -a /etc/vsftpd.conf >> /dev/null")
	runCommand("echo \"ssl_ciphers=HIGH\" | tee -a /etc/vsftpd.conf >> /dev/null")
	runCommand("echo \"rsa_cert_file=/etc/ssl/private/vsftpd.pem\" | tee -a /etc/vsftpd.conf >> /dev/null")
	runCommand("echo \"local_enable=YES\" | tee -a /etc/vsftpd.conf >> /dev/null")
	runCommand("echo \"write_enable=YES\" | tee -a /etc/vsftpd.conf >> /dev/null")
	runCommand("echo \"local_umask=022\" | tee -a /etc/vsftpd.conf >> /dev/null")
	runCommand("echo \"chroot_local_user=YES\" | tee -a /etc/vsftpd.conf >> /dev/null")
	runCommand("echo \"chroot_list_file=/etc/vsftpd.chroot_list\" | tee -a /etc/vsftpd.conf >> /dev/null")

def configSSH():
	global sshport
	runCommand("perl -pi -e \"s/Port 22/Port "+sshport+"1/g\" /etc/ssh/sshd_config")
	runCommand("perl -pi -e \"s/PermitRootLogin yes/PermitRootLogin no/g\" /etc/ssh/sshd_config")
	runCommand("perl -pi -e \"s/#Protocol 2/Protocol 2/g\" /etc/ssh/sshd_config")
	runCommand("perl -pi -e \"s/X11Forwarding yes/X11Forwarding no/g\" /etc/ssh/sshd_config")
	runCommand("groupadd sshdusers")
	runCommand("echo \"\" | tee -a /etc/ssh/sshd_config > /dev/null")
	runCommand("echo \"UseDNS no\" | tee -a /etc/ssh/sshd_config > /dev/null")
	runCommand("echo \"AllowGroups sshdusers\" >> /etc/ssh/sshd_config")
	runCommand("mkdir -p /usr/share/terminfo/l/")
	runCommand("cp /lib/terminfo/l/linux /usr/share/terminfo/l/")
	runCommand("service ssh restart")

def getVars():
	global user, passwd, ipaddr, sshport, ftpport
	user = getString("You must create a new user for the seedbox, enter a username: ")
	passwd = getString("Please enter a password for " + user + ": ", True)
	ipaddr = getString("IP Address of your seedbox: ", False, "127.0.0.1")
	sshport = getString("Enter the port number you wish to use for SSH (Usually 22): ", False, 22)
	ftpport = getString("FTP Port number to use (Usually 21): ", False, 21)

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
	global user, passwd, ipaddr, sshport, ftpport
	outputBeginning()
	if not os.geteuid() == 0: # User didn't run script with root privilegdes
		sys.exit("This script must be run as root")
	setupDirectory()
	getVars()

if __name__ == "__main__":
	main()