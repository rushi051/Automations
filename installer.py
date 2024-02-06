#!/usr/bin/python

import logging
import base64
import commands
import getpass
import sys
import os
cd = commands.getoutput('pwd')
sys.path.append(cd+"/urllib3-1.6")
import urllib3
sys.path.append(cd+"/requests-2.6.0")
import requests
requests.packages.urllib3.disable_warnings()
sys.path.append(cd+"/pytz-2023.3")
proxies = {'http':'http://sub.proxy.att.com:8888',
           'https':'http://sub.proxy.att.com:8888',
           'ALL':'http://sub.proxy.att.com:8888'
        }


DIR = commands.getoutput('pwd')
logger=logging.getLogger("logger")
green="\033[32m"
white="\033[37;1m"
red="\033[31;1m"
f = open(cd+"/CONFIG/config.txt","w")

def det ():

	null = "null"
	false = "false"
	true = "true"
	User_Id = raw_input("Enter Username : ")
	Pas = getpass.getpass(prompt = "Enter Passord : ")
	Password = base64.b64encode(Pas.encode())
	Threshold = raw_input("Enter Threshold Value : ")
	url = "https://att.keyfactorpki.com/KeyfactorApi/CertificateCollections"
	headers = {'Accept':'application/json','x-keyfactor-api-version':'1','x-keyfactor-requested-with':'APIClient'}
	colls = requests.get(url,verify=False,auth=(User_Id,Pas),headers=headers,proxies=proxies)
	if colls.status_code == 401 :
		print("\n"+red+"Please Enter correct Credentials\n"+white)
		det ()
	elif colls.status_code != 200 :
		print("\n"+red+"Something went Wrong\n"+white)
		det ()
	data = colls.content
	data = eval(data)
	for i in data :
		print(green+i['Name']+" : "+str(i['Id'])+white)
	user_input_lines = []
	print("Please Enter a collection Id from above list (type 'done' on a new line when finished):")
	while True:
    		line = raw_input()
    		if line  == "done":
        		break
    		user_input_lines.append(line)

	f.write("User_Id:"+User_Id+"\n")
	f.write("Password:"+Password+"\n")
	f.write("Threshold:"+Threshold+"\n")
	f.write("Collection_Id:"+','.join(user_input_lines)+"\n" )
	f.write("DIR:"+DIR+"/")

det ()
