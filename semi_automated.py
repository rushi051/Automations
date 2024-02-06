#!/usr/bin/python
import commands
cd = commands.getoutput('pwd')
import sys
sys.path.append(cd+"/urllib3-1.6")
import urllib3
sys.path.append(cd+"/requests-2.6.0")
import requests
requests.packages.urllib3.disable_warnings()
sys.path.append(cd+"/pytz-2023.3")
sys.path.append(cd+'/xlrd')
#sys.path.append(cd+'/openpyxl-3.1.2')
#from openpyxl import Workbook
import xlrd
import csv
import smtplib
import string
import re
import base64
import datetime
import commands
import zipfile
from zipfile import ZipFile
from io import BytesIO
import time
import pytz
from collections import defaultdict
import json
import logging
import os
from datetime import datetime
from datetime import date
from requests.auth import HTTPBasicAuth
green="\033[32m"
red="\033[31;1m"
white="\033[37;1m"
yellow="\033[33m"
lightblue="\033[94m"
pink="\033[95m"
cyan="\033[36;1m"

renewed_data = open(cd+"/CONFIG/renewed_data.txt","r+")
deleted_data = open(cd+"/CONFIG/deleted_data.txt","a+")
wb = xlrd.open_workbook(cd+'/CONFIG/cert_details.xlsx')
header = cd+"/HTML/header.html"
final = cd+"/HTML/final.html"
footer = cd+"/HTML/footer.html"
htmlFile=cd+"/HTML/final.html"
combined = cd+"/HTML/combined_data.html"
csv_file = cd+"/CSV/CAT_CSV.csv"
cmd = "rm "+htmlFile
(status,out)=commands.getstatusoutput(cmd)


renewed_serial_number = []
deleted_serial_number = []
serial_number = []
CN = []
days = []
f = 0

hh = commands.getoutput('hostname -f')
today = datetime.now(pytz.utc)

def decode(string):
    k = string.strip().lstrip("b'").rstrip("'")
    return k


values = {}


config_data = open(cd+"/CONFIG/config.txt","r+")
lines = config_data.read().split('\n')
for line in lines:
    if line.strip():
        key, value = line.split(':')
        values[key.strip()] = value.strip()
User_Id = values['User_Id']
Password = base64.b64decode(decode(values['Password'])).decode()
Threshold = int(values['Threshold'])
Collection_Id = values['Collection_Id']
Collection_Id = Collection_Id.split(",")
DIR = values['DIR']
csv_data =  [['Certificate Name','Valid From','Valid Until','Days Left to Expire','Collection']]
renewed_r = renewed_data.read().splitlines()
for i in renewed_r :
        renewed_serial_number.append(i)
renewed_data.close()

proxies = {'http':'http://sub.proxy.att.com:8888',
           'https':'http://sub.proxy.att.com:8888',
           'ALL':'http://sub.proxy.att.com:8888'
        }


loged = commands.getoutput('logname')
f_name = datetime.now().strftime(DIR+"logs/User_Input_Keytool_log_%H-%M-%S_%d%m%Y_"+loged+".log")
logging.basicConfig(filename=f_name,

                    format='%(asctime)s %(message)s',

                    filemode='w')
logger=logging.getLogger("logger")
logger.setLevel(logging.DEBUG)


cert_file = DIR+"certs/cert.crt"
if os.path.exists(cert_file):
        os.remove(cert_file)


def check_ou(ou):
    if ou == "" or "WMQCLIENT" in ou:
        return ou
    else:
        return "OU="

def PA(Common_name):

        sheet = wb.sheet_by_index(0)

        for row_index in range(sheet.nrows):

            row_data = sheet.row_values(row_index)
            if row_data[0] == Common_name :
		Key_Password = row_data[1].encode('ascii')
                Trust_Password = row_data[2].encode('ascii')
                Alias_ = row_data[3].encode('ascii')
		Template = row_data[4].encode('ascii')
                return Key_Password ,Trust_Password ,Alias_ ,Template
        return None, None,None, None

def write_csv ():
	with open(csv_file , mode ='wb') as csvfile:
		csvwriter = csv.writer(csvfile)
		for row in csv_data:
			csvwriter.writerows(csv_data)
			csvfile.write(b'\r\n')

def mailfunc(subject):

        TO = "rushikesh.pawar2@amdocs.com"
        CC = "rhutuja.bhamare@amdocs.com"
        FROM = "CAT-TOOL@list.att.com"
        SUBJECT = "CAT TOOL Report ENT"
        MESSAGE_BODY = subject


        SenderMail = TO + ";" + CC
        TO_LIST = list(SenderMail.split(";"))
        TO_LIST = [x.strip(' ') for x in TO_LIST]
        BODY = string.join((
        "Content-type: text/html ",
        "From: %s" % FROM,
        "To: %s" % TO,
        "Cc: %s" % CC,
        "Subject: %s" % SUBJECT,
        "",
        MESSAGE_BODY
        ), "\r\n")


        server = smtplib.SMTP('localhost')


        server.sendmail(FROM, TO_LIST, BODY)
        server.quit()
        logger.info("MAL SENT SUCCESSFULLY")
	login ()		



def mailfunc_coll():


        with open (header, "r") as f1:
                data1= f1.read()
        with open (final, "r") as f2:
                data2= f2.read()
        with open (footer, "r") as f3:
                data3= f3.read()
        combined_data = data1+data2+data3
        with open (combined,"w") as f4:
                f4.write(combined_data)
        with open (combined,"r") as f5:
                data4=f5.read()

        #def mail_alert(returnString,value):
        TO = "rushikesh.pawar2@amdocs.com"
        CC = "rhutuja.bhamare@amdocs.com"
        FROM = "CAT-TOOL@list.att.com"
        SUBJECT = "Certificate Expiration Report ENT"
        MESSAGE_BODY = "Hi All,<BR/>"+data4


        SenderMail = TO + ";" + CC
        TO_LIST = list(SenderMail.split(";"))
        TO_LIST = [x.strip(' ') for x in TO_LIST]
        BODY = string.join((
        "Content-type: text/html ",
        "From: %s" % FROM,
        "To: %s" % TO,
        "Cc: %s" % CC,
        "Subject: %s" % SUBJECT,
        "",
        MESSAGE_BODY
        ), "\r\n")


        server = smtplib.SMTP('localhost')


        server.sendmail(FROM, TO_LIST, BODY)
        server.quit()
        print "Mail Sent Successfully"


#coll_data_url_l =[]
#for Id in Collection_Id :
#        coll_data_url = "https://att.keyfactorpki.com/KeyfactorApi/Certificates?collectionId="+str(Id)+"&includeMetadata=true&pq.includeRevoked=false&pq.includeExpired=false"
#        coll_data_url_l.append(coll_data_url)



def cert_d ():
    global coll_data_url_l
    logger.info(loged+" selected Download Certificate option")
    cn = raw_input("Please Enter common name of the certificate : ")
    query = {'Accept':'application/json','x-keyfactor-api-version':'1','x-keyfactor-requested-with':'APIClient'}
    for Id in Collection_Id :
        coll_data_url = "https://att.keyfactorpki.com/KeyfactorApi/Certificates?collectionId="+str(Id)+"&includeMetadata=true&pq.includeRevoked=false&pq.includeExpired=false"
	#coll_data_url_l.append(coll_data_url)
	print(coll_data_url)
    #for i in coll_data_url_l:
	#print("JAi HARI")
	#print(i)
    	coll_data = requests.get(coll_data_url,verify=False,auth=(User_Id, Password),headers=query,proxies=proxies)
	#print(coll_data.content)
	dd = coll_data.content
	print(type(dd))
	dd1 = dd[1:-1]
	print(type(dd1))
    	dd =  eval(dd)
    	for i in dd:
    	    data = i
    	    exp_date = datetime.strptime(data['NotAfter'],'%Y-%m-%dT%H:%M:%SZ').replace(tzinfo=pytz.utc)
    	    diff = exp_date - today
    	    diff = diff.days
    	    if data['IssuedCN'] == cn:
	    	print("\n")
	    	print(cyan+"Serial Number : {0} ".format(data['SerialNumber']))
	    	print("Common Name : {0} ".format(data['IssuedCN']))
	    	print("Days Remaining : {0} ".format(diff)+white)
  	    else :
	     	print(cn+" is not present in the Collection :")
    serial_number1 = raw_input(yellow+"\nEnter Serial Number of the certificate you want to renew from the above list : ")
    url_l1 = []
    for Id in Collection_Id :
	url = 'https://att.keyfactorpki.com/KeyfactorApi/Certificates?collectionId='+ID+'&includeLocations=true&includeMetadata=true&pq.includeRevoked=false&pq.includeExpired=true&pq.queryString=SerialNumber%20-eq%20%22'+serial_number1+'%22'
	url_l1.append(url)
    for i in url_l1:
	    details = requests.get(url,verify=False,auth=(User_Id , Password),headers=query,proxies=proxies)
	    data = details.content
	    #print(data)
	    if data == "[]":
		pass
	    else :
 		data1 = data[1:-1]
		data1 = eval(data1)

		cert_data = {'CertID':'',
			 'IncludeChain':'true',
			 'IncludePrivateKey':'true'}
	    	cert_data['CertID'] = data1['Id']
	    	query = {'Content-Type':'application/json','Accept':'application/json','x-keyfactor-api-version':'1','x-keyfactor-requested-with':'APIClient','x-certificateformat':'PEM'}
	    	download = requests.post('https://att.keyfactorpki.com/KeyfactorApi/Certificates/Download?collectionId='+Collection_Id,data= json.dumps(cert_data),verify=False,auth=(User_Id, Password),headers=query,proxies=proxies)
	    	if download.status_code == 200 :
		    logger.info("Certificate downloaded sucessfully")
		    print("Certificate downloaded sucessfully")
		    data = download.content
		    data = json.loads(data)
		    data = data["Content"]
		    base64_message = data
		    message_bytes = base64.b64decode(base64_message)
		    with open (cert_file,"w") as f:
			f.write(message_bytes)
		    cmd1 = 'mv '+DIR+'data/certs/cert.crt '+DIR+'data/certs/'+cn
		    (status,out) = commands.getstatusoutput(cmd1)
        
    login ()


def Details ():
        logger.info(loged+" selected Certificate Details option")
        null = "null"
        false = "false"
        true = "true"
	Details_url = []
        cn = raw_input("Please Enter common name of the certificate : ")	
        query = {'Accept':'application/json','x-keyfactor-api-version':'1','x-keyfactor-requested-with':'APIClient'}
	for Id in Collection_Id :
		coll_data_url = "https://att.keyfactorpki.com/KeyfactorApi/Certificates?collectionId="+str(Id)+"&includeMetadata=true&pq.includeRevoked=false&pq.includeExpired=false"
	  	print(coll_data_url)	
		coll_data = requests.get(coll_data_url,verify=False,auth=(User_Id, Password),headers=query,proxies=proxies)
		data = coll_data.content
		dd =  eval(data)
		for i in dd:
			data = i
			exp_date = datetime.strptime(data['NotAfter'],'%Y-%m-%dT%H:%M:%SZ').replace(tzinfo=pytz.utc)
			diff = exp_date - today
			diff = diff.days
			if data['IssuedCN'] == cn:
				Id1 = Id
				print("\n")
				print(cyan+"Serial Number : {0} ".format(data['SerialNumber']))
				print("Common Name : {0} ".format(data['IssuedCN']))
				print("Days Remaining : {0} ".format(diff)+white)
        serial_number = raw_input(yellow+"\nEnter Serial Number of the certificate you want to renew from the above list : ")
	url_l = []
        query = {'Accept':'application/json'}
	for Id in Collection_Id :
		url = 'https://att.keyfactorpki.com/KeyfactorApi/Certificates?collectionId='+Id+'&includeLocations=true&includeMetadata=true&pq.includeRevoked=false&pq.includeExpired=true&pq.queryString=SerialNumber%20-eq%20%22'+serial_number+'%22'
		#print(url)	
		url_l.append(url)
	for i in url_l:
		#print(i)
		details = requests.get(i,verify=False,auth=(User_Id, Password),headers=query,proxies=proxies)
		#print(details.status_code)
		#print(details.content)
		data = details.content
		#print("data"+data)
		#print(bool(data))
		if data == "[]":
			pass
		else :
                        data = details.content
                        #print(data)
                        #print(type(data))
                        data1 = data[1:-1]
                        data1 = eval(data1)
                        data1 = "\n\n\n1. Server-Type : "+data1['Metadata']['Server-Type']+"\n2. Collection : "+data1['Metadata']['Collection']+"\n3. Requester AttId : "+data1['Metadata']['Requester-ATT-User-ID']+"\n4. Auto Renew : "+data1['Metadata']['Auto-Renew']+"\n5. Issued CN : "+data1['IssuedCN']+"\n6. Issued DN : "+data1['IssuedDN']+"\n7. Import Date : "+data1['ImportDate'].split('T')[0]+"\n8. Serial Number : "+data1['SerialNumber']+"\n9. Template Name : "+data1['TemplateName']+"\n10.Issuer DN :  "+data1['IssuerDN']+"\n11. Expiry Date : "+data1['NotAfter'].split('T')[0]


        print(data1)
	#print(Id1)
        logger.info(data1)
        login ()


def cert_coll ():
	thresh = raw_input("Enter No. of Days : ")
        logger.info(loged+" selected Certificates Expiring in 60 days option")
        null = "null"
        false = "false"
        true = "true"
	htmlString = ""
	for Id in Collection_Id :
        	query = {'Accept':'application/json','x-keyfactor-api-version':'1','x-keyfactor-requested-with':'APIClient'}
        	coll_data_url = "https://att.keyfactorpki.com/KeyfactorApi/Certificates?collectionId="+Id+"&includeMetadata=true&pq.includeRevoked=false&pq.includeExpired=false"
        	coll_data = requests.get(coll_data_url,verify=False,auth=(User_Id, Password),headers=query,proxies=proxies)
        	dd =  eval(coll_data.content)
        	print(coll_data.status_code)
        #data = list(data)
        #print(type(data))
        #print(dd)
        	for i in dd:
                	data = i
                	exp_date = datetime.strptime(data['NotAfter'],'%Y-%m-%dT%H:%M:%SZ').replace(tzinfo=pytz.utc)
                	diff = exp_date - today
                	diff = diff.days
                	#print(diff)
                	#print(data['SerialNumber'])
                	#print(i)
              		if 0 <= diff <= int(thresh) :
				f = open(htmlFile, "w")
				htmlString = htmlString+"<tr><th> "+str(data['IssuedCN'])+" </th><th> "+str(data['NotBefore']).split('T')[0]+" </th><th> "+str(data['NotAfter']).split('T')[0]+" </th><th> "+str(diff)+" </th><th> "+str(data['Metadata']['Collection'])+" </th></tr>"
				c_data = [str(data['IssuedCN']),str(data['NotBefore']).split('T')[0],str(data['NotAfter']).split('T')[0],str(diff),str(data['Metadata']['Collection'])]
				f.write(htmlString)
				f.close()
                        	serial_number.append(data['SerialNumber'])
                        	CN.append(data['IssuedCN'])
                        	days.append(diff)
				csv_data.append(c_data)

        for sn, name, d in zip(serial_number, CN, days):
                print("Serial Number : {0} ".format(sn))
                logger.info("Serial Number : {0}".format(sn))
                print("Certificate Name : {0}".format(name))
                logger.info("Certificate Name : {0}".format(name))
                print("Days Remaining : {0}".format(d))
                logger.info("Days Remaining : {0}".format(d))
                print("\n")
	for h in days:
		if h <= int(thresh):
			write_csv ()
			time.sleep(10)
                	mailfunc_coll()
			login ()
		else :
			break

def PfxEnrol ():
    global f
    logger.info(loged+" selected PFX Enrollment(Download & Post-Process) option")
    null = "null"
    false = "false"
    true = "true"
    cn = raw_input("Please Enter common name of the certificate : ")
    query = {'Accept':'application/json','x-keyfactor-api-version':'1','x-keyfactor-requested-with':'APIClient'}
    for Id in Collection_Id :
	coll_data_url = "https://att.keyfactorpki.com/KeyfactorApi/Certificates?collectionId="+str(Id)+"&includeMetadata=true&pq.includeRevoked=false&pq.includeExpired=false"
	coll_data = requests.get(coll_data_url,verify=False,auth=(User_Id, Password),headers=query,proxies=proxies)
	dd =  eval(coll_data.content)
	for i in dd:
	    data = i
	    exp_date = datetime.strptime(data['NotAfter'],'%Y-%m-%dT%H:%M:%SZ').replace(tzinfo=pytz.utc)
	    diff = exp_date - today
	    diff = diff.days
	    if data['IssuedCN'] == cn:
		diff1 = diff
		print("\n")
		print(cyan+"Serial Number : {0} ".format(data['SerialNumber']))
		print("Common Name : {0} ".format(data['IssuedCN']))
		print("Days Remaining : {0} ".format(diff)+white)
    serial_number = raw_input(yellow+"\nEnter Serial Number of the certificate you want to renew from the above list : "+white)
    renewed_serial_number.append(serial_number)
    pfx_url = []
    query = {'Accept':'application/json'}
    for Id in Collection_Id :
	url = 'https://att.keyfactorpki.com/KeyfactorApi/Certificates?collectionId='+Id+'&includeLocations=true&includeMetadata=true&pq.includeRevoked=false&pq.includeExpired=true&pq.queryString=SerialNumber%20-eq%20%22'+serial_number+'%22'
	pfx_url.append(url)
    for i in pfx_url :
	details = requests.get(i,verify=False,auth=(User_Id, Password),headers=query,proxies=proxies)
	data = details.content
	if data == "[]":
	    pass
	else :
	    #print(data)
	    data1 = data[1:-1]
	    data1 = eval(data1)
	    #print(data1)
	    #print(type(data1))

	    data2 = str(data1['SubjectAltNameElements'])
	    data2 = data2[1:-1]
	    data2 = eval(data2)
	    data1['SubjectAltNameElements']=data2


	    myDate = datetime.now(pytz.utc)
	    date_str= myDate.isoformat()
	    iso_date=date_str.replace('+00:00', 'Z')
	    cn1 = data1['IssuedCN']
	    Key_Password ,Trust_Password ,Alias_, Template = PA(cn1)
	    print(Key_Password ,Trust_Password ,Alias_, Template)
	    if Key_Password is None or Trust_Password is None or Alias_ is None or Template is None :
		subject = 'Hi Team,<br><br><b>CN = '+str(data1['IssuedCN'])+'</b> will be expiring in '+str(diff1)+' days , but it is not present in the cert_details.xlsx excel file.<br><br>Please Check'
		#print(subject)
		logger.error("Password and Alias  not found in the Excel sheet.")
		mailfunc(subject)
		return
	    else:
		f == 1

    pfx_headers = {'Content-Type':'application/json','Accept':'application/json','x-keyfactor-api-version':'1','x-keyfactor-requested-with':'APIClient','x-certificateformat':'Zip'}

    pfx_body = {'CustomFriendlyName':'',
                #'PopulateMissingValuesFromAD':'',
                'Password' :Key_Password, #enter your own password
                'Subject': '',
                'IncludeChain' : True,
                'CertificateAuthority': '', #prod
                'Timestamp': iso_date,
                'Template' :Template,     #prod     choose Sha1 or sha2 root
                'Metadata': {
                        'MOTS-Profile-ID': '',                #required
                        'Requester-ATT-User-ID': User_Id,        #required
                        'Server-Type': '',                   #required
                        'Requester-ATT-Manager-User-ID':'', #required
                        'TLS-Port-Services-Internet-Traffic': '',  #required
                        'Collection':'',
			'Environment':''
                        },
                'SANs': {
                        'dns': [
                                'test1stCert.att.com',
                                'test2dnscert.att.com'
                                ]
                         }
                }

    #print(type(cert_body))
    ou_match = re.search(r'\bOU=([^,]+)', data1['IssuedDN'])
    pfx_body['CustomFriendlyName'] =data1['IssuedCN']
    if ou_match:
        pfx_body['Subject']=data1['IssuedDN']
        ou = ou_match.group(1)
        new_ou = check_ou(ou)
        pfx_body['Subject'] = pfx_body['Subject'].replace(ou, new_ou)
    else :
        pfx_body['Subject'] = data1['IssuedDN']
    pfx_body['CertificateAuthority'] =data1['CertificateAuthorityName']
    #pfx_body['Template'] = data1['TemplateName']
    pfx_body['Metadata']['MOTS-Profile-ID'] = data1['Metadata']['MOTS-Profile-ID']
    pfx_body['Metadata']['Requester-ATT-User-ID'] = User_Id
    pfx_body['Metadata']['Server-Type'] = data1['Metadata']['Server-Type']
    pfx_body['Metadata']['Requester-ATT-Manager-User-ID'] = data1['Metadata']['Requester-ATT-Manager-User-ID']
    pfx_body['Metadata']['TLS-Port-Services-Internet-Traffic'] = data1['Metadata']['TLS-Port-Services-Internet-Traffic']
    pfx_body['Metadata']['Collection'] = data1['Metadata']['Collection']
    #print(data1['SubjectAltNameElements'])
    #print(type(data1['SubjectAltNameElements']))
    if 'p' in data1['IssuedCN'].split('.')[0] :
        pfx_body['Metadata']['Environment'] = 'PROD'
    else :
        pfx_body['Metadata']['Environment'] = 'NPRD'

    if isinstance(data1['SubjectAltNameElements'],dict)  :
    	pfx_body['SANs']['dns'] = [data1['SubjectAltNameElements']['Value']]
    elif isinstance(data1['SubjectAltNameElements'],tuple) :
	data_list = list(data1['SubjectAltNameElements'])
    	for i in data_list :
            pfx_body['SANs']['dns'].append(i['Value'])
    else:
    	pfx_body['SANs']['dns'] = data1['SubjectAltNameElements']['Value']

    print(pfx_body)
    pfx_enroll = requests.post('https://att.keyfactorpki.com/KeyfactorApi/Enrollment/PFX',data= json.dumps(pfx_body),verify=False,auth=(User_Id, Password),headers=pfx_headers,proxies=proxies)
    print(pfx_enroll.status_code)
    #print(pfx_enroll.content)
    if pfx_enroll.status_code  == 200 :
        logger.info(pfx_body['CustomFriendlyName']+" Certificate renewed sucessfully")
	f == 1 
    else :
        logger.error(pfx_body['CustomFriendlyName']+" is not enrolled ")
	subject = 'Hi Team,<br><br> C.A.T. failed to renew <b> CN = '+data1['IssuedCN']+'</b>.<br><br>Please Check'
	mailfunc(subject)
        return

    z = pfx_enroll.content
    #print(type(z))
    z = eval(z)
    pfx_data = z['CertificateInformation']['Pkcs12Blob']
    d_data = message_bytes = base64.b64decode(pfx_data)
    pfx_zip = DIR+"zip_files/"+pfx_body['CustomFriendlyName']+".zip"
    with open (pfx_zip,"w") as f1:
        f1.write(d_data)

    cmd = "python "+DIR+"cert_converter.py "+pfx_body['CustomFriendlyName'].split('.')[0]+" "+pfx_body['Password']+" "+Alias_+" "+Trust_Password
    print(cmd)
    (status,out) = commands.getstatusoutput(cmd)
    print(status)
    print(out)
    if status == 0 and pfx_enroll.status_code == 200 and f == 1 :
        subject = 'Hi Team,<br><br><b> CN = '+data1['IssuedCN']+'</b> is renewed by '+loged+' through the C.A.T. on '+hh+', .<br><br>Please Check'
        logger.info("Please check your Certificate files at /opt/app/iOMIP/scripts/KeyFactor_Tool/Zip_files/"+Alias_)
	print("Please check your Certificate files at /opt/app/iOMIP/scripts/KeyFactor_Tool/Zip_files ")
	mailfunc(subject)
	
    login ()

def revoke ():
    null = "null"
    false = "false"
    true = "true"
    logger.info(loged+" selected Revoke Certificate option")
    cn = raw_input("Please Enter common name of the certificate : ")
    query = {'Accept':'application/json','x-keyfactor-api-version':'1','x-keyfactor-requested-with':'APIClient'}
    for Id in Collection_Id :
	coll_data_url = "https://att.keyfactorpki.com/KeyfactorApi/Certificates?collectionId="+str(Id)+"&includeMetadata=true&pq.includeRevoked=false&pq.includeExpired=false"
	coll_data = requests.get(coll_data_url,verify=False,auth=(User_Id, Password),headers=query,proxies=proxies)
	dd =  eval(coll_data.content)
	for i in dd:
 	    data = i
    	    exp_date = datetime.strptime(data['NotAfter'],'%Y-%m-%dT%H:%M:%SZ').replace(tzinfo=pytz.utc)
	    diff = exp_date - today
       	    diff = diff.days
     	    if data['IssuedCN'] == cn:
		Id1 = Id
		print("\n")
		print(cyan+"Serial Number : {0} ".format(data['SerialNumber']))
		print("Common Name : {0} ".format(data['IssuedCN']))
		print("Days Remaining : {0} ".format(diff)+white)
    serial_number = raw_input(yellow+"\nEnter Serial Number of the certificate you want to renew from the above list : ")
    revoke_url = []
    for Id in Collection_Id :
	url = 'https://att.keyfactorpki.com/KeyfactorApi/Certificates?collectionId='+Id+'&includeLocations=true&includeMetadata=true&pq.includeRevoked=false&pq.includeExpired=true&pq.queryString=SerialNumber%20-eq%20%22'+serial_number+'%22'
	revoke_url.append(url)
    for i in revoke_url :
        details = requests.get(i,verify=False,auth=(User_Id, Password),headers=query,proxies=proxies)
        data = details.content
	if data == "[]":
	    pass
	else :
	    #print(data)
	    data1 = data[1:-1]
	    data1 = eval(data1)
	    #print(data1)
	    revoke_headers = {'Content-Type':'application/json','x-keyfactor-api-version':'1','x-keyfactor-requested-with':'APIClient','Accept':'application/json'}
	    revoke_data = {'CertificateIds':[],'Reason':'5','EffectiveDate':'','CollectionId': Id1,'Comment':'-'}
	    revoke_data['CertificateIds'] = list(revoke_data['CertificateIds'])
	    #print(revoke_data)
	    revoke_data['CertificateIds'].append(data1['Id'])
	    revoke_data['EffectiveDate'] = data1['ImportDate']
	    revoke_url = 'https://att.keyfactorpki.com/KeyfactorApi/Certificates/Revoke'
	    #print(revoke_data)
	    revoke = requests.post(revoke_url,data=json.dumps(revoke_data),verify=False,auth=(User_Id, Password),headers=revoke_headers,proxies=proxies)
	    #print(revoke)
	    #print(revoke.status_code)
	    if revoke.status_code == 200 :
		subject = 'Hi Team,<br><br><b> CN = '+cn+'</b> is revoked by '+loged
		#print(subject)
		logger.info(data1['IssuedCN']+" Certificate has been revoked sucesfully")
		print(data1['IssuedCN']+" Certificate has been revoked sucesfully")		
		mailfunc(subject)
	    else :
		logger.error(data1['IssuedCN']+" Certificate did not revoked")
		subject = 'Hi Team,<br><br> C.A.T. failed to revoke <b> CN = '+cn+'</b>.<br><br>Please Check'
		#print(subject)
		mailfunc(subject)
def delete ():
    null = "null"
    false = "false"
    true = "true"
    logger.info(loged+" selected Delete Certificate option")
    cn = raw_input("Please Enter common name of the certificate : ")
    query = {'Accept':'application/json','x-keyfactor-api-version':'1','x-keyfactor-requested-with':'APIClient'}
    for Id in Collection_Id :
	coll_data_url = "https://att.keyfactorpki.com/KeyfactorApi/Certificates?collectionId="+str(Id)+"&includeMetadata=true&pq.includeRevoked=false&pq.includeExpired=false"
	coll_data = requests.get(coll_data_url,verify=False,auth=(User_Id, Password),headers=query,proxies=proxies)
	dd =  eval(coll_data.content)
	for i in dd:
	    data = i
       	    exp_date = datetime.strptime(data['NotAfter'],'%Y-%m-%dT%H:%M:%SZ').replace(tzinfo=pytz.utc)
	    diff = exp_date - today
	    diff = diff.days
	    if data['IssuedCN'] == cn:
		Id1 = Id
		print("\n")
		print(cyan+"Serial Number : {0} ".format(data['SerialNumber']))
		print("Common Name : {0} ".format(data['IssuedCN']))
		print("Days Remaining : {0} ".format(diff)+white)
    serial_number = raw_input(yellow+"\nEnter Serial Number of the certificate you want to renew from the above list : ")
    for i in renewed_serial_number:
	if i == serial_number:
                 
            renewed_serial_number.remove(i)
            deleted_serial_number.append(i)
        else :
            logger.error(i+" will not be deleted through script")
    serial_number = raw_input("Enter Serial Number : ")
    delete_url = []
    for Id in Collection_Id :
        url = 'https://att.keyfactorpki.com/KeyfactorApi/Certificates?collectionId='+Id+'&includeLocations=true&includeMetadata=true&pq.includeRevoked=false&pq.includeExpired=true&pq.queryString=SerialNumber%20-eq%20%22'+serial_number+'%22'
	delete_url.append(url)
    for i in delete_url:
        details = requests.get(i,verify=False,auth=(User_Id, Password),headers=query,proxies=proxies)
        data = details.content
	if data == "[]":
	    pass
	else:
        #print(data)
            data1 = data[1:-1]
            data1 = eval(data1)

            certId = data1['Id']
            delete_headers = {'x-keyfactor-api-version':'1','x-keyfactor-requested-with': 'APIClient'}
            delete_url = 'https://att.keyfactorpki.com/KeyfactorApi/Certificates/'+str(certId)+'?collectionId='+str(Id1)
            delete = requests.delete(delete_url,verify=False,auth=(User_Id, Password),headers=delete_headers,proxies=proxies)
	    print(delete.status_code)
            if delete.status_code == 204:
		subject = 'Hi Team,<br><br><b> CN = '+cn+'</b> is deleted by '+loged
                print(data1['IssuedCN']+" Certificate has been deleted sucessfully")
                logger.info(data1['IssuedCN']+" Certificate has been deleted sucessfully")
		mailfunc(subject)
            else :
		subject = 'Hi Team,<br><br> C.A.T. failed to revoke <b> CN = '+cn+'</b>.<br><br>Please Check'
                logger.error("Certificate is not deleted")
		mailfunc(subject)



def login ():
    #login_url = "curl -u "+User_Id+":"+Password+" -L -X GET --header 'Accept: application/json' --header 'x-keyfactor-api-version: 1' --header 'x-keyfactor-requested-with: APIClient' 'https://att.keyfactorpki.com/KeyfactorApi/Certificates?collectionId='+Collection_Id+' "
    #print(login_url)
    l_url = "https://att.keyfactorpki.com/KeyfactorApi/CertificateCollections"
    l_headers = {'Accept':'application/json','x-keyfactor-api-version':'1','x-keyfactor-requested-with':'APIClient'}
    login = requests.get(l_url,verify=False,auth=(User_Id,Password),headers=l_headers,proxies=proxies)

    #query = {'Accept':'application/json', 'x-keyfactor-api-version':'1','x-keyfactor-requested-with':'APIClient' }
    #login = requests.get('https://att.keyfactorpki.com/KeyfactorApi/Certificates?collectionId='+Collection_Id,verify=False,auth=(User_Id, Password),params=query,proxies=proxies)

    if login.status_code  == 200 :
        logger.info(loged+" validated")
        print('''\033[1;32m

                     Select Option from Below List
              _____________________________________________
            1.          * Download Certificate *
            2.          * Certificate Details *
            3.  * PFX Enrollment(Download & Post-Process) *
            4.    * Certificates Expiring in 60 days *
            5.          * Revoke Certificate *
            6.          * Delete Certificate *
            7.                * Exit *
    \033[37;1m''')
        ip = input("Please Select Your Choice : ")
        if ip == 1 :
            cert_d ()
        elif ip == 2 :
            Details ()
        elif ip == 3 :
            PfxEnrol ()
        elif ip == 4 :
            cert_coll ()
        elif ip == 5 :
            revoke ()
        elif ip == 6 :
            delete ()
        elif ip == 7:
            exit(0)
    else :
        print("Please Check Creds")
        logger.error("Wrong Credentials Submitted")
        #break ;


login ()

renewed_data = open(DIR+"CONFIG/renewed_data.txt","w")
for i in renewed_serial_number :
        renewed_data.write(i+"\n")
for j in deleted_serial_number :
        deleted_data.write(j+"\n")

logger.info("Completed Successfully")


