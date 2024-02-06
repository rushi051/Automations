#!/bin/python
"""
Python script to generate certificate from keyfactor zip
Output format:- .cer, .jks, .p12, .sth, .rdb, .pem
Date=20221219
Author=Nishikant Deshmukh|nd4286|nd4286v@att.com:Nishikant.Deshmukh@amdocs.com
CURRENT VERSION:1.0.2
VERSION:1.0.1 -- [20221220] --> Updated with nw password promt
VERSION:1.0.2 -- [20221221] --> updated to argument and menu based

"""
import os, subprocess, datetime, getopt, glob, time, sys, string, smtplib,logging, commands
import os.path
from datetime import datetime
cd = commands.getoutput('pwd')
#pylib="/opt/app/iOMIP/scripts/pyLibs"
#sys.path.insert(0,cd)
#from multiLog import loghandlers
#parser="/opt/app/iOMIP/scripts/pyLibs/parseenv.py"
user=os.getlogin()
green="\033[32m"
red="\033[31;1m"
white="\033[37;1m"
yellow="\033[33m"
lightblue="\033[94m"
pink="\033[95m"
cyan="\033[36;1m"
KEYTOOL ='/opt/app/was/was85_bckp/java_1.8_64/jre/bin/keytool'
accountUser=commands.getoutput("whoami")
logs=cd+"/logs/"
logid=time.strftime("%Y%m%d_%H%M%S_")+str(os.getpid())+"_"+user
global logger
try:
        conLevel=sys.argv[1]
except:
        conLevel=""
f_name = datetime.now().strftime(logs+logid+".log")

logging.basicConfig(filename=f_name,

                    format='%(asctime)s %(message)s',

                    filemode='w')
logger=logging.getLogger("logger")
logger.setLevel(logging.DEBUG)


#loghandlers("logger",logs+logid+".log","enable",conLevel)
#logger=logging.getLogger("logger")
seg=[]

def welcomeNote(note):
        logger.info(green+"Welcome "+user+" "+note+white)
        logger.info(yellow+"KeyFactor Tool Menu"+white)

def validInput(arg,val1,val2,CN,passw,cname,passwd):
	try:
		if arg > val1 or arg < val2:
                        logger.error("Invalid input")
                        sys.exit(1)
                elif arg == 1:
                        certProcess(CN,passw,cname,passwd)
		elif arg == val1:
                        sys.exit(0)
	except ValueError:
                logger.error("Invalid input")

def mainMenu():
        logger.info(yellow+"1- Generate and post process"+white)
	logger.info(yellow+"2- Exit"+white)
        value=int(input("Enter your choice: "))
        if value == 2:
                sys.exit(0)
        CN=raw_input(yellow+"Enter certificate name same as in KeyFactor : "+white)
	passw=raw_input(yellow+"Enter password from KeyFactor : "+white)	
	cname=raw_input(yellow+"Enter Common Friendly Name : "+white)
	passwd=raw_input(yellow+"Enter the new password which you want to update : "+white)
        validInput(value,2,1,CN,passw,cname,passwd)

def mainCall(note):
        welcomeNote(note)
        mainMenu()

def pathExists(path):
        """
        To check whether a file path
        exists or not in the server.
        """
        if os.path.isdir(path) == True:
                cmd="mv "+path+"  "+path+"_"+time.strftime("%Y%m%d_%H%M%S_")
		(status,out)=commands.getstatusoutput(cmd)
		print(out)

def certProcess(CN,passw,cname,passwd):
 	CN1 = CN.replace('.','')	
	hdir=cd+"/data/certs"
	zdir=cd+"/zip_files"
	path=hdir+"/"+CN
	pathExists(path)
	cmd="mkdir -m775 "+hdir+"/"+CN
	(status,out)=commands.getstatusoutput(cmd)
	logger.info(cyan+"Extracting "+CN+"com.zip......"+white)
	cmd="unzip -o "+zdir+"/"+CN+"*.zip -d "+hdir+"/"+CN
	(status,out)=commands.getstatusoutput(cmd)	
	ndir=hdir+"/"+CN+"/"
	if status == 0:
		logger.info(green+out+white)	
	else:
		logger.error(red+"Failed to extrzct .zip file"+white)
	logger.info(cyan+"\nCreating .cer file......"+white)
	cmd="cp -p "+hdir+"/"+CN+"/"+CN1+"-server.cer "+hdir+"/"+CN+"/"+CN+".cer"
	(status,out)=commands.getstatusoutput(cmd)	
	if status == 0:
                logger.info(green+".cer file created sucessfully"+white)
        else:
                logger.error(red+"Failed to create .cer file"+white)
	logger.info(cyan+"\nCreating JKS keystore......"+white)
	cmd="cat "+ndir+CN1+"-server.cer "+ndir+CN1+"-chain1.cer "+ndir+CN1+"-chain2.cer > "+ndir+"import.pem"
        (status,out)=commands.getstatusoutput(cmd)
	#print("/usr/bin/openssl pkcs12 -export -in "+ndir+"import.pem -inkey "+ndir+cname+"-key.pem -out "+ndir+cname+".p12 -passin pass:"+passw+" -password pass:IOMIPKF")
	out=subprocess.Popen("/usr/bin/openssl pkcs12 -export -in "+ndir+"import.pem -inkey "+ndir+CN1+"-key.pem -out "+ndir+cname+".p12 -passin pass:"+passw+" -password pass:"+passwd,shell=True,stdout=subprocess.PIPE, stderr=subprocess.PIPE)
	stdout,stderr = out.communicate()
	#logger.info(green+stdout+white)
	#logger.error(red+stderr+white)
	cmd= KEYTOOL+" -importkeystore -deststorepass "+passwd+" -destkeystore "+ndir+CN+".jks -deststoretype JKS -srckeystore "+ndir+cname+".p12 -srcstoretype PKCS12 -srcstorepass "+passwd+" <<< yes"
        (status,out)=commands.getstatusoutput(cmd)
	print(cmd)
	print(out)
	if status == 0:
		logger.info("\n")
		logger.info(green+"JKS file created sucessfully"+white)
		logger.info("\n"+out)
	else:
		logger.info("\n")
		logger.error(red+"Failed to create JKS file"+white)
		logger.error("\n"+out)
	cmd=KEYTOOL+" -changealias -alias 1 -destalias '"+cname+"' -keystore "+ndir+CN+".jks -storepass "+passwd
	(status,out)=commands.getstatusoutput(cmd)
	if status == 0:
		logger.info("\n")
                logger.info(green+"Alias changes done sucessfully"+white)
                logger.info(out)
        else:
		logger.info("\n")
                logger.error(red+"Failed to change Alias"+white)
                logger.error(out)

 	#cmd=gskcmd+" -cert -add -db "+ndir+CN+".jks -pw "+passwd+" -label 'digicert tls rsa sha256 2020 ca1' -file "+ndir+cname+"-chain1.cer"
	cmd="/usr/bin/openssl x509 -in "+ndir+CN1+"-chain1.cer -outform DER -out "+ndir+CN1+"-chain1.crt <<< yes"	
	(status,out)=commands.getstatusoutput(cmd)
	if status == 0:
		logger.info(green+cname+"-chain1.crt file generated sucessfully"+white)
		cmd=KEYTOOL+" -import -trustcacerts -keystore "+ndir+CN+".jks -storepass "+passwd+" -alias 'digicert tls rsa sha256 2020 ca1' -file "+ndir+CN1+"-chain1.crt <<< yes"
		(status,out)=commands.getstatusoutput(cmd)
		if status == 0:
        	        logger.info(green+cname+"-chain1.crt imported sucessfully"+white)
                	logger.info(out)
        	else:
                	logger.error(red+"Failed to import "+cname+"-chain1.crt in JKS file"+white)
               		logger.error(out)
	else:
		logger.error(red+"Failed to generate "+cname+"-chain1.crt file"+white)

	#cmd=gskcmd+" -cert -add -db "+ndir+CN+".jks -pw "+passwd+" -label 'DigiCert Global Root CA' -file "+ndir+cname+"-chain2.cer"
	cmd="openssl x509 -in "+ndir+CN1+"-chain2.cer -outform DER -out "+ndir+CN1+"-chain2.crt <<< yes"
        (status,out)=commands.getstatusoutput(cmd)
	if status == 0:
		logger.info(green+cname+"-chain2.crt file generated sucessfully"+white)
		cmd=KEYTOOL+" -import -trustcacerts -keystore "+ndir+CN+".jks -storepass "+passwd+" -alias 'DigiCert Global Root CA' -file "+ndir+CN1+"-chain2.crt <<< yes"
        	(status,out)=commands.getstatusoutput(cmd)
	        if status == 0:
        	        logger.info(green+cname+"-chain2.crt imported sucessfully"+white)
                	logger.info(out)
			cmd5=KEYTOOL+" -importkeystore -srckeystore "+ndir+CN+".jks -destkeystore "+ndir+CN+".pfx -deststoretype PKCS12 -srcstorepass "+passwd+" -deststorepass "+passw+" <<< yes"
			print("cmd5"+cmd5)
			(status5,out5)=commands.getstatusoutput(cmd5)
			print(status5)
			print(out5)
			if status5 == 0:
				logger.info(green+cname+" "+ndir+CN+".pfx created successfully"+white)
				logger.info(out)
			else :
				logger.error(red+"Failed to create "+ndir+CN+".pfx")
				logger.error(out)
	        else:		
        	        logger.error(red+"Failed to import "+cname+"-chain2.crt in JKS file"+white)
                	logger.error(out)
	else:
		logger.error(red+"Failed to generate "+cname+"-chain2.crt file"+white)
                logger.error(out)

def usage():
	logger.info(white)
	logger.info(yellow+"./create_certs_KF.py for menu based\n"+white)
	logger.info(yellow+"Follow below syntax if you want to run with arguments\n"+white)
	logger.info(yellow+"./create_certs_KF.py <cert_name> <password> <common_name> <new_password>"+white)
	sys.exit()

def main():
	currentTime=time.time()
	startTime=time.time()
	if len(sys.argv) > 1:
		if len(sys.argv) < 5:
			usage()
		else:
			CN=sys.argv[1]
			passw=sys.argv[2]
			cname=sys.argv[3]
			passwd=sys.argv[4]
			certProcess(CN,passw,cname,passwd)
	else:
		mainCall("mainMenu")
	endTime=time.time()
        timer=endTime-startTime
	logger.info("\n")
        logger.info(("Total time taken in secs :- "+cyan+str(timer)+white))
"""try:
	userid=['gg590m','sp052v','sp4279']
	if user not in userid:
		sys.exit(1)
        if accountUser == "tooladm":
                logger.error(pink+ "Please login with websphe user" +white+ "\n")
                sys.exit()
        else:"""
main()
"""except KeyboardInterrupt:
	logger.info("\n")
        logger.warn(lightblue+"Keyboard interrupt"+white)
"""
