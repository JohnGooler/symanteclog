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


def DB_Connect(query, value, method):
    try:
        if method == 'push':
            conndb = mysql.connector.connect(
            host=host,
            user=user,
            passwd=passwd,
            database=database,
            #auth_plugin='mysql_native_password',
            )

            mycursor = conndb.cursor()
            mycursor.executemany(query, value)
            conndb.commit()
            
            #print inserted record
            if mycursor.rowcount > 0:
                print(mycursor.rowcount, "record inserted.")
            
            else:
                print('No New Record')
                

        elif method == 'update':
            conndb = mysql.connector.connect(
            host=host,
            user=user,
            passwd=passwd,
            database=database,
            #auth_plugin='mysql_native_password',
            )

            mycursor = conndb.cursor()
            mycursor.execute(query, value)
            conndb.commit()
            
            #print inserted record
            if mycursor.rowcount > 0:
                print(mycursor.rowcount, "record Updated.")
            
            else:
                print('No New Record')

        elif method == 'pull':
            conndb = mysql.connector.connect(
            host=host,
            user=user,
            passwd=passwd,
            database=database,
            #auth_plugin='mysql_native_password',
            )

            mycursor = conndb.cursor()
            mycursor.execute(query)
            result = mycursor.fetchall()
            return result

        else:
            raise('Method is not Correct')
    
    except Exception as err:
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
        new_ips = DB_Connect("SELECT attackerip FROM attackers.ip_details where addedtofirewall = 0", None, 'pull')
        if new_ips == []:
            print("No new Record")

        try:
            for ip in new_ips:
                # convert to list because For Mysql
                ip = ip[0]
                # firewall_message = send_to_firewall(ip)
                firewall_message = Send_to_Mikroitk_API(mikrotikhost, ip, ipblocktimeout, iplistname)
                # write ips to FireWall and then change the ip state
                if firewall_message == "":
                    DB_Connect("UPDATE attackers.ip_details SET addedtofirewall = %s WHERE attackerip = %s", ('1', ip), 'update')
                    print("added to firewall black list %s" %ip)
                elif firewall_message == 'failure: already have such entry\n':
                    DB_Connect("UPDATE attackers.ip_details SET addedtofirewall = %s WHERE attackerip = %s", ('1', ip), 'update')
                    print('Duplicated Ip Detected: %s' %ip)
                elif "already have such entry" in firewall_message.split("\n")[2]:
                    DB_Connect("UPDATE attackers.ip_details SET addedtofirewall = %s WHERE attackerip = %s", ('1', ip), 'update')
                    print('Duplicated Ip Detected: %s' %ip)
                else:
                    print(firewall_message)
        except Exception as e:
            print(e)
        
        # wait in seconds that defined in config
        countdown(refreshtime)
        
if __name__ == "__main__":
    main()
