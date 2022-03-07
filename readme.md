# Symantec Security log catcher.

Get the security log from Symantec IDS/IPS and find the IP-address that attacked. 

Then add those IPs to mikrotik firewall through SSH.

Install Python Dependencies:

    -pip3 install mysql-connector-python
    -pip3 install paramiko


Before run:
- add smc.exe in system variable path
- create database name called attackers
- import database
