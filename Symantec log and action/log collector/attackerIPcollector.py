import os, subprocess, mysql.connector, time

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

# create directory if not exist
dirName = 'symanteclog'
if not os.path.exists(dirName):
    os.mkdir(dirName)
    print("Directory " , dirName ,  " Created ")
else:    
    print("Directory " , dirName ,  " already exists")


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
def pushdb(val):
    try:
        conndb = mysql.connector.connect(
            host=host,
            user=user,
            passwd=passwd,
            database=database,
            # auth_plugin='mysql_native_password',
        )

        mycursor = conndb.cursor()

        sql = "INSERT INTO ip_details (attackerip, addedtofirewall) VALUES (%s, 'no')"
        val = val

        mycursor.executemany(sql, val)
        conndb.commit()

        if mycursor.rowcount > 0:
            print(mycursor.rowcount, "record inserted.")
        else:
            print('No New Record')
        mycursor.close()
        conndb.close()

    except mysql.connector.Error as err:
        print("Something went wrong: {}".format(err))
    finally:
    #closing database connection.
        if(conndb.is_connected()):
            mycursor.close()
            conndb.close()     

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
    finally:
    #closing database connection.
        if(conndb.is_connected()):
            mycursor.close()
            conndb.close()


# remove duplicate ips from local
def remove_dub(newdata, olddata):
    seen = []
    for i in newdata:
        if i not in seen:
            if i not in olddata:
                seen.append(i)
    seen = list(seen)
    return seen


def main():
    while True:
        # run symantec app for generated security logs and placed it in directory that has been created
        try:
            subprocess.call(['smc', '-exportlog' ,'1', '0', '-1', dir_path + '\\symanteclog\\symantecsec.log'])
        except Exception as e:
            print(e)
            print("\r Make sure The Symantec Antiviruse is installed")
        ############## end of symantec log collector################################################

        old_ip = pulldb("SELECT attackerip FROM attackers.ip_details")
        old_ip = [list(x) for x in old_ip]

        usable_log = []
        # Check Symanteclog is exist?
        line_number = sum(1 for line in open(dir_path + "\\symanteclog\\symantecsec.log", "r"))
        
        try:
            f = open(dir_path + "\\symanteclog\\symantecsec.log", "r")
        except Exception as e:
            print(e)
        
        for line in range(line_number):
            logs = f.readline().split('\t')
            # Get only IP address from Log
            index_number = [6]
            filterd = [logs[val] for val in index_number]
            usable_log.append(filterd)

        usable_log = remove_dub(usable_log, old_ip)

        # write ips to database
        pushdb(usable_log)
        # wait 60 seconds
        countdown(refreshtime)


if __name__ == "__main__":
    main()
