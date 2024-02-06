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
import xlrd
import smtplib
import string
import base64
import re
import datetime
import zipfile
from zipfile import ZipFile
from io import BytesIO
import pytz
import logging
from collections import defaultdict
import json
import os
from datetime import datetime
from datetime import date
from requests.auth import HTTPBasicAuth

renewed_data = open(cd+"/CONFIG/renewed_data.txt","r+")
deleted_data = open(cd+"/CONFIG/deleted_data.txt","a+")
wb = xlrd.open_workbook(cd+'/CONFIG/cert_details.xlsx')


hh = commands.getoutput('hostname -f')
renewed_serial_number = []
deleted_serial_number = []
cn = ""
subject = ""
f = 0
s = 0
diff = 0
cn1 = ""
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
#print(Collection_Id)
#print(type(Collection_Id))
DIR = values['DIR']




proxies = {'http':'http://sub.proxy.att.com:8888',
           'https':'http://sub.proxy.att.com:8888',
           'ALL':'http://sub.proxy.att.com:8888'
        }

loged = commands.getoutput('logname')
f_name = datetime.now().strftime(DIR+"logs/Keytool_log_%H:%M:%S_%d%m%Y_"+loged+".log")

logging.basicConfig(filename=f_name,

                    format='%(asctime)s %(message)s',

                    filemode='w')
logger=logging.getLogger("logger")
logger.setLevel(logging.DEBUG)


renewed_r = renewed_data.read().splitlines()
for i in renewed_r :
        renewed_serial_number.append(i)
renewed_data.close()
print(renewed_serial_number)

def check_ou(ou):
    if ou == "" or "WMQCLIENT" in ou:
        return ou
    else:
        return ""


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
        return None, None, None, None


def mailfunc(subject):

        TO = "rushikesh.pawar@amdocs.com"
        CC = "rhutuja.bhamare@amdocs.com"
        FROM = "CAT-TOOL@list.att.com"
        SUBJECT = "Certificate Administration Tool Report"
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



def cert_coll ():
	global renewed_serial_number
	global cn1
        today = datetime.now(pytz.utc)
        null = "null"
        false = "false"
        true = "true"
	for Id in Collection_Id :
		print(Id)
		query = {'Accept':'application/json','x-keyfactor-api-version':'1','x-keyfactor-requested-with':'APIClient'}
		coll_data_url = "https://att.keyfactorpki.com/KeyfactorApi/Certificates?collectionId="+str(Id)+"&includeMetadata=true&pq.includeRevoked=false&pq.includeExpired=false"
		coll_data = requests.get(coll_data_url,verify=False,auth=(User_Id, Password),headers=query,proxies=proxies)
		dd =  eval(coll_data.content)
		#print(dd)
		print(coll_data.status_code)
		for i in dd:
			#print(i)
			data = i
			cn1 =data(['IssuedCN'])
			serial_number = data['SerialNumber']
			exp_date = datetime.strptime(data['NotAfter'],'%Y-%m-%dT%H:%M:%SZ').replace(tzinfo=pytz.utc)
			diff = exp_date - today
			diff = diff.days
			if 0 <= diff <= Threshold  and serial_number not in renewed_serial_number:
				
				print(data['SerialNumber'])
				pfx_enroll (serial_number,diff,Id)
				logger.info(serial_number+" will be renewed")

			elif diff <= 0 and serial_number in renewed_serial_number :
				delete(serial_number,Id)
				logger.info(serial_number+" will be deleted")



def pfx_enroll (serial_number,diff,Id):
    global renewed_serial_number
    global f
    global diff 
    global s
    global cn1
    renewed_serial_number.append(serial_number)
    null = "null"
    false = "false"
    true = "true"
    True = true
    query = {'Accept':'application/json'}
    url = 'https://att.keyfactorpki.com/KeyfactorApi/Certificates?collectionId='+Id+'&includeLocations=true&includeMetadata=true&pq.includeRevoked=false&pq.includeExpired=true&pq.queryString=SerialNumber%20-eq%20%22'+serial_number+'%22'
    details = requests.get(url,verify=False,auth=(User_Id,Password),headers=query,proxies=proxies)
    data = details.content
    data1 = data[1:-1]
    data1 = eval(data1)

    data2 = str(data1['SubjectAltNameElements'])
    data2 = data2[1:-1]
    data2 = eval(data2)
    data1['SubjectAltNameElements']=data2
    print(data1)
    cn1 = data1(['IssuedCN'])
    myDate = datetime.now(pytz.utc)
    date_str= myDate.isoformat()
    iso_date=date_str.replace('+00:00', 'Z')
    cn = data1['IssuedCN']
    print(cn)
    Key_Password ,Trust_Password ,Alias_ ,Template = PA(cn)
    print(Key_Password ,Trust_Password ,Alias_ ,Template)
    if Trust_Password is None or Trust_Password is None or Alias_ is None or Template is None :
	s = 1
        #subject = 'Hi Team,<br><br><b> CN = '+cn+'</b> will be expiring in '+str(diff)+' days , but it is not present in the cert_details.xlsx excel file.<br><br>Please Check'
	#mailfunc(subject)
        logger.error("Password and Alias  not found in the Excel sheet.")
        return
    else:
	f == 1



        pfx_headers = {'Content-Type':'application/json','Accept':'application/json','x-keyfactor-api-version':'1','x-keyfactor-requested-with':'APIClient','x-certificateformat':'Zip'}

        pfx_body = {'CustomFriendlyName':'',
                    'Password' : Key_Password, 
                    'Subject': '',
		    'ChainOrder':'EndEntityFirst',
                    'IncludeChain' : True,
                    'CertificateAuthority': '', 
                    'Timestamp': iso_date,
                    'Template' :Template,     

                    'Metadata': {
                            'MOTS-Profile-ID': '',                #required
                            'Requester-ATT-User-ID': User_Id.split('@')[0],        #required
                            'Server-Type': '',                   #required
                            'Requester-ATT-Manager-User-ID':'', #required
                            'TLS-Port-Services-Internet-Traffic': '',  #required
                            'Collection':'',
			    'Environment':''
			},
		    'SANs': {
                            'dns': [
                                    ]
                             }
                            
                    }

	ou_match = re.search(r'\bOU=([^,]+)', data1['IssuedDN'])
        pfx_body['CustomFriendlyName'] =data1['IssuedCN']
	if ou_match:
		pfx_body['Subject']= data1['IssuedDN']
		ou = ou_match.group(0)
		new_ou = check_ou(ou)
		pfx_body['Subject'] = pfx_body['Subject'].replace(ou, new_ou)
	       
		pfx_body['Subject']= ','.join(filter(lambda x: x.strip(), pfx_body['Subject'].split(',')))
		print(pfx_body['Subject'])
	else :
        	pfx_body['Subject'] = data1['IssuedDN']
        pfx_body['CertificateAuthority'] =data1['CertificateAuthorityName']
        pfx_body['Metadata']['MOTS-Profile-ID'] = data1['Metadata']['MOTS-Profile-ID']
        pfx_body['Metadata']['Server-Type'] = data1['Metadata']['Server-Type']
        pfx_body['Metadata']['Requester-ATT-Manager-User-ID'] = data1['Metadata']['Requester-ATT-Manager-User-ID']
        pfx_body['Metadata']['TLS-Port-Services-Internet-Traffic'] = data1['Metadata']['TLS-Port-Services-Internet-Traffic']
        pfx_body['Metadata']['Collection'] = data1['Metadata']['Collection']
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
        pfx_enroll = requests.post('https://att.keyfactorpki.com/KeyfactorApi/Enrollment/PFX',data=json.dumps(pfx_body),verify=False,auth=(User_Id, Password),headers=pfx_headers,proxies=proxies)
	print(pfx_enroll.status_code)
        if pfx_enroll.status_code  == 200 :
            logger.info(pfx_body['CustomFriendlyName']+" Certificate renewed sucessfully")
        else :
            logger.error(pfx_body['CustomFriendlyName']+" is not enrolled ")
        z = pfx_enroll.content
        z = eval(z)
        pfx_data = z['CertificateInformation']['Pkcs12Blob']
	
        d_data = message_bytes = base64.b64decode(pfx_data)
        pfx_zip = DIR+"zip_files/"+pfx_body['CustomFriendlyName']+".zip"
        with open (pfx_zip,"w") as f1:
            f1.write(d_data)
	if pfx_enroll.status_code != 200 :
	    s = 2 
	    #subject = 'Hi Team,<br><br> C.A.T.  failed to renew <b> CN = '+data1(['IssuedCN'])+'</b>.<br><br>Please Check'
	    #mailfunc(subject)
	    return
        cmd = "python "+DIR+"cert_converter.py "+pfx_body['CustomFriendlyName']+" "+pfx_body['Password']+" "+Alias_+" "+Trust_Password
        (status,out) = commands.getstatusoutput(cmd)
	print(status,cmd)	
        if status == 0 and pfx_enroll.status_code == 200 and f == 1 :
	    s = 3
	    #subject = 'Hi Team,<br><br><b> CN = '+data1(['IssuedCN'])+'</b> is renewed by the C.A.T.  on '+hh+', Please work on post-process.<br><br>Please Check'
	    #mailfunc(subject)
	    #print(subject)
            logger.info("Please check your Certificate files at "+DIR+"Zip_files/"+Alias_)

def delete (serial_number,Id):
    global deleted_serial_number
    global renewed_serial_number
    for i in renewed_serial_number:
        if i == serial_number:

            renewed_serial_number.remove(i)
            deleted_serial_number.append(i)
        else :
            logger.error(i+" will not be deleted through script")
    url = 'https://att.keyfactorpki.com/KeyfactorApi/Certificates?collectionId='+Id+'&includeLocations=true&includeMetadata=true&pq.includeRevoked=false&pq.includeExpired=true&pq.queryString=SerialNumber%20-eq%20%22'+serial_number+'%22'
    details = requests.get(url,verify=False,auth=(User_Id,Password),headers=query,proxies=proxies)
    data = details.content
    data1 = data[1:-1]
    data1 = eval(data1)

    certId = data1['Id']
    delete_headers = {'x-keyfactor-api-version': '1','x-keyfactor-requested-with': 'APIClient'}
    delete_url = 'https://att.keyfactorpki.com/KeyfactorApi/Certificates/'+certId+'?collectionId='+Id
    delete = requests.delete(delete_url,verify=False,auth=(User_Id, Password),headers=delete_headers,proxies=proxies)
    if delete.status_code == 204:
        logger.info(data1['IssuedCN']+" Certificate has been deleted sucessfully")
    else :
        logger.error("Certificate is not deleted")


cert_coll ()


if s ==1 :
	subject = 'Hi Team,<br><br><b> CN = '+cn+'</b> will be expiring in '+str(diff)+' days , but it is not present in the cert_details.xlsx excel file.<br><br>Please Check'
elif s == 2:
	subject = 'Hi Team,<br><br> C.A.T.  failed to renew <b> CN = '+cn1+'</b>.<br><br>Please Check'
elif s == 3 :
	subject = 'Hi Team,<br><br><b> CN = '+cn1+'</b> is renewed by the C.A.T.  on '+hh+', Please work on post-process.<br><br>Please Check'
mailfunc(subject) 
renewed_data = open(DIR+"CONFIG/renewed_data.txt","w")
for i in renewed_serial_number :
        renewed_data.write(i+"\n")
for j in deleted_serial_number :
        deleted_data.write(j+"\n")

logger.info("Completed Successfully")

cert_coll ()
