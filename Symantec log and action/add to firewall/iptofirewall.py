"""
Send Ip address to Mikrotik address list with Api

"""

import os, mysql.connector, time ,paramiko
import api

# get the dir path of this file
dir_path = os.path.dirname(os.path.realpath(__file__))

# Read database config file in config dir
with open(dir_path + "\\config\\config.conf") as conf:
    for line in range(sum(1 for line in open(dir_path + "\\config\\config.conf", "r"))):
        configline = conf.readline().strip("\n").split("=")
        if configline[0] == 'host':
            host = configline[1]
        elif configline[0] == 'user':
            user = configline[1]
        elif configline[0] == 'passwd':
            passwd = configline[1]
        elif configline[0] == 'database':
            database = configline[1]
        elif configline[0] == 'refresh time':
            refreshtime = int(configline[1])
        elif configline[0] == 'sshhost':
            sshhost = configline[1]
        elif configline[0] == 'sshuser':
            sshuser = configline[1]
        elif configline[0] == 'sshpass':
            sshpass = configline[1]
        elif configline[0] == 'sshport':
            sshport = configline[1]
        elif configline[0] == 'iplistname':
            iplistname = configline[1]
        elif configline[0] == 'mikrotikhost':
            mikrotikhost = configline[1]
        elif configline[0] == 'mikrotikapiuser':
            mikrotikapiuser = configline[1]
        elif configline[0] == 'mikrotikapipass':
            mikrotikapipass = configline[1]
        elif configline[0] == 'mikrotikapiport':
            mikrotikapiport = configline[1]
        elif configline[0] == 'ipblocktimeout':
            ipblocktimeout = configline[1]

# countdown function
def countdown(t):
    while t:
        mins, secs = divmod(t, 60)
        # print(mins,secs)
        timeformat = '{:02d}:{:02d}'.format(mins, secs)
        print(timeformat, end='\r')
        time.sleep(1)
        t -= 1
    print('continue...')


# push to database fucntion
def pushdb(query, value):
    try:
        conndb = mysql.connector.connect(
            host=host,
            user=user,
            passwd=passwd,
            database=database,
            # auth_plugin='mysql_native_password',
        )

        mycursor = conndb.cursor()
        mycursor.execute(query ,value)
        conndb.commit()

    except mysql.connector.Error as err:
        print("Something went wrong: {}".format(err))
        #reverting changes because of exception
        conndb.rollback()

# pull from database function
def pulldb(query):
    try:
        conndb = mysql.connector.connect(
        host=host,
        user=user,
        passwd=passwd,
        database=database,
        # auth_plugin='mysql_native_password',
        )

        mycursor = conndb.cursor()
        mycursor.execute(query)
        result = mycursor.fetchall()
        return result
    except mysql.connector.Error as err:
        print("Something went wrong: {}".format(err))

# Send IPs Over Mikrotik API
def Send_to_Mikroitk_API(mikrotikhost, ip, ipblocktimeout, iplistname):
    router = api.Api(mikrotikhost)
    try:
        r = router.talk(f'/ip/firewall/address-list/add =list={iplistname} =address={ip} =timeout={ipblocktimeout}')
        if r == []:
            return ""
        else:
            return r

    except Exception as e:
        return e.args[0]

# Send Ips over SSH
def send_to_firewall(ip):
    sshclient = paramiko.SSHClient()
    sshclient.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    sshclient.connect(sshhost, username=sshuser, password=sshpass, port=sshport)
    stdin, stdout, stderr = sshclient.exec_command("ip firewall address-list add address=%s list=blockedbysymantec" %ip)
    opt = stdout.readlines()
    opt = "".join(opt)
    sshclient.close()
    return opt



def main():
    while True:
        new_ips = pulldb("SELECT attackerip FROM attackers.ip_details where addedtofirewall = 0")
        if new_ips == []:
            print("No new Record")

        try:
            for ip in new_ips:
                # convert to list because Mysql can not accept tuple
                ip = ip[0]
                # firewall_message = send_to_firewall(ip)
                firewall_message = Send_to_Mikroitk_API(mikrotikhost, ip, ipblocktimeout, iplistname)
                # write ips to FireWall and then change the ip state
                if firewall_message == "":
                    pushdb("UPDATE attackers.ip_details SET addedtofirewall = %s WHERE attackerip = %s", ('1', ip))
                    print("added to firewall black list %s" %ip)
                elif firewall_message == 'failure: already have such entry\n':
                    pushdb("UPDATE attackers.ip_details SET addedtofirewall = %s WHERE attackerip = %s", ('1', ip))
                    print('Duplicated Ip Detected: %s' %ip)
                elif "already have such entry" in firewall_message.split("\n")[2]:
                    pushdb("UPDATE attackers.ip_details SET addedtofirewall = %s WHERE attackerip = %s", ('1', ip))
                    print('Duplicated Ip Detected: %s' %ip)
                else:
                    print(firewall_message)
        except Exception as e:
            print(e)
        
        # wait in seconds that defined in config
        countdown(refreshtime)
        
if __name__ == "__main__":
    main()
