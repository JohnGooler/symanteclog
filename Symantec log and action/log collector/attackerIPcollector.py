import sys, os, subprocess, mysql.connector, time
from mysql.connector.plugins import mysql_native_password
from mysql.connector.locales.eng import client_error
from persiantools.jdatetime import JalaliDate
from datetime import datetime

# get the dir path of this file
def get_script_folder():
    # path of main .py or .exe when converted with pyinstaller
    if getattr(sys, 'frozen', False):
        script_path = os.path.dirname(sys.executable)
    else:
        script_path = os.path.dirname(
            os.path.abspath(sys.modules['__main__'].__file__)
        )
    return script_path


# dir_path = os.path.dirname(os.path.realpath(__file__))
dir_path = get_script_folder()

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
        elif configline[0] == 'Delete_Old_Ips_Interval':
            Delete_Old_Ips_Interval = int(configline[1])

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

def DB_Connect(query, value, method):
    try:
        if method == 'push':
            conndb = mysql.connector.connect(
            host=host,
            user=user,
            passwd=passwd,
            database=database,
            auth_plugin='mysql_native_password',
            )

            mycursor = conndb.cursor()
            mycursor.executemany(query, value)
            conndb.commit()
            
            #print inserted record
            if mycursor.rowcount > 0:
                print(mycursor.rowcount, "record inserted.")
            
            else:
                print('No New Record')

        elif method == 'pull':
            conndb = mysql.connector.connect(
            host=host,
            user=user,
            passwd=passwd,
            database=database,
            auth_plugin='mysql_native_password',
            )

            mycursor = conndb.cursor()
            mycursor.execute(query)
            result = mycursor.fetchall()
            return result
        
        elif method == 'del':
            conndb = mysql.connector.connect(
            host=host,
            user=user,
            passwd=passwd,
            database=database,
            auth_plugin='mysql_native_password',
            )

            mycursor = conndb.cursor()
            mycursor.execute(query)
            conndb.commit()
            print(mycursor.rowcount, "IP(s) deleted")

        else:
            raise('Method is not Correct')
    
    except Exception as err:
        print("Something went wrong: {}".format(err))

# remove duplicate ips and trusted ips
def remove_dub(newdata, olddata, white_list):    
    seen = []
    #convert oldips to sigle array for easy compare
    oldips = [item for olddata in olddata for item in olddata]
    for i in newdata:
        try:
            #Check one by one IPs
            if i[0] not in [x[0] for x in seen]:
                if i[0] not in oldips:
                    if i[0] not in white_list:
                        seen.append(i)
        except Exception as e:
            print(e)

    seen = list(seen)
    return seen

# get the Trusted ips from Database only when the app is running for the fist time
try:
    print("Get Trusted Ips")
    white_list_ip = DB_Connect("SELECT ip FROM white_list_ip", None, 'pull')
    white_list_ip = [list(x) for x in white_list_ip]
    white_list_ip = [item for white_list_ip in white_list_ip for item in white_list_ip]
    print("Done")
except:
    print('Make Sure The database are connected')


def main():
    while True:
# run symantec app for generated security logs and placed it in directory that has been created
        try:
            subprocess.call(['smc', '-exportlog' ,'1', '0', '-1', dir_path + '\\symanteclog\\symantecsec.log'])
        except Exception as e:
            print(e)
            print("\r Make sure The Symantec Antiviruse is installed")
        ############## end of symantec log collector################################################

        try:
            old_ip = DB_Connect("SELECT attackerip FROM ip_details", None, 'pull')
            old_ip = [list(x) for x in old_ip]
        except:
            print('Make Sure The database are connected')

        # create an empty list for all ip address
        Ip_of_attacher = []

        # Check Symanteclog if exist
        line_number = sum(1 for line in open(dir_path + "\\symanteclog\\symantecsec.log", "r"))

        try:
            f = open(dir_path + "\\symanteclog\\symantecsec.log", "r")
        except Exception as e:
            print(e)

        for _ in range(line_number):
            logs = f.readline().split('\t')

            # Get IP-address and date of attack from Log
            Ip_index_number = [6]
            date_index_number = [1]
            try:
                #Get ip address from log file
                filterd_ip = [logs[ip] for ip in Ip_index_number]
                Ip_of_attacher.append(filterd_ip)

                #need a proper date format for database, then convert persian date to gregorian date
                try:
                    # get only date form log file
                    filterd_tarikh = [logs[tarikh].split(" ")[0] for tarikh in date_index_number]
                    filterd_tarikh = filterd_tarikh[0].split('/')
                    filterd_tarikh = [int(x) for x in filterd_tarikh]
                    #If Jalali date detected, we will convert it to gregorian
                    if filterd_tarikh[2] < 2000:
                        filterd_tarikh = [JalaliDate(int(filterd_tarikh[2]), int(filterd_tarikh[1]), int(filterd_tarikh[0])).to_gregorian().strftime("%Y-%m-%d")]
                    
                    else: # Gregorian date type detected
                        #create a list for mysql data import
                        filterd_tarikh = ['-'.join(str(i) for i in filterd_tarikh)]
                        #Convert date to "%m/%d/%Y" format
                        filterd_tarikh = [datetime.strptime(filterd_tarikh[0], "%m-%d-%Y").strftime("%Y-%m-%d")]

                except ValueError:
                    print(f"Correct date format is: mm/dd/yyyy \nYour date format {filterd_tarikh[0]} is not correct.")
                    quit()

                Ip_of_attacher.append(filterd_tarikh)
            except IndexError as e:
                print(e)
                pass

        #Prepare ips and date for mysql. Only get ips that attacks today in log
        FinalIPS = []
        for i in range(0,len(Ip_of_attacher)-1, 2):
            try:
                IPAndDate = Ip_of_attacher[i]+Ip_of_attacher[i+1]
                if IPAndDate[1] == datetime.now().strftime("%Y-%m-%d"):
                    FinalIPS.append(Ip_of_attacher[i]+Ip_of_attacher[i+1])
                else:
                    #OutDated logs
                    pass
            except IndexError:
                #If list is empty, mean it is starting
                print(IndexError)
                pass

        #remove duplicated IPS
        try:
            Ip_of_attacher = remove_dub(FinalIPS, old_ip, white_list_ip)
            
        except:
            print('Make Sure the files are exist')
        
        # write ips to database
        DB_Connect("INSERT INTO ip_details (attackerip, createdat, addedtofirewall) VALUES (%s, %s, 'no')", Ip_of_attacher, 'push')

        # wait in seconds
        countdown(refreshtime)

        #Remove old data from Database. Configurable from config file
        DB_Connect(f"Delete FROM ip_details WHERE createdat < NOW() - INTERVAL {Delete_Old_Ips_Interval} DAY", None,  method="del")

if __name__ == "__main__":
    main()
