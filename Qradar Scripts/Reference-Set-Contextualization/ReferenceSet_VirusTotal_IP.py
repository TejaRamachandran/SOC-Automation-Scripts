from __future__ import division
import yaml
import requests
import json
import urllib2
import urllib
import os
from datetime import datetime


with open("config.yml", 'r') as ymlfile:
    cfg = yaml.load(ymlfile)

for section in cfg:
	#print(section)
	qradar = (cfg['config'] ['QradarHost'])
	token = (cfg['config'] ['AuthToken'])
	RF_A = (cfg['config'] ['ReferenceSetName_A'])
	RF_B = (cfg['config'] ['ReferenceSetName_B'])
	vt_api = (cfg['config'] ['Virustotal_API_Key'])
	Detection_Ratio = (cfg['config'] ['Virustotal_Detection_Ratio'])
	pxy_user = (cfg['config'] ['Proxy_Username'])
	pxy_pass = (cfg['config'] ['Proxy_Password'])
	pxy_host = (cfg['config'] ['Proxy_Host'])
	pxy_port = (cfg['config'] ['Proxy_Port'])
	


os.environ['NO_PROXY'] = qradar #Qradar console IP "Uncomment this line if you are not using proxy"
#print (os.environ)

headers = {'SEC': token} #security token for your Qradar get from yaml file

requests.packages.urllib3.disable_warnings() # Warnings
url = "https://{0}/api/reference_data/sets/{1}?fields=data(value)".format(qradar, RF_A)
response = requests.get(url, headers=headers , verify=False)
json_data = json.loads(response.text)


for x in json_data['data']:
	print (x['value'])
	proxy_url = "http://{0}:{1}@{2}:{3}".format(pxy_user, pxy_pass, pxy_host, pxy_port )
	print (proxy_url)
	proxy = urllib2.ProxyHandler({'http': proxy_url})
	print (proxy)
	auth = urllib2.HTTPBasicAuthHandler()
	opener = urllib2.build_opener(proxy, auth, urllib2.HTTPHandler)
	urllib2.install_opener(opener)
	url = 'http://www.virustotal.com/vtapi/v2/ip-address/report'
	parameters = {'ip': x['value'], 'apikey': vt_api }
	try:
		response = urllib2.urlopen('%s?%s' % (url, urllib.urlencode(parameters))).read()
		r_dict = json.loads(response)
		#print r_dict
	except ValueError: #No JSON object could be decoded
		pass
		
	Pve_Results = 0
	Tot_Results = 0

	try:
		for i in r_dict.get("detected_referrer_samples"):
			Pve_Results = Pve_Results + i.get("positives")
			Tot_Results = Tot_Results + i.get("total")
	except TypeError: #if no results found program throws a TypeError
		pass
		#print ("No results")

#Validating Ratio for the IP in Integer 
	try:
		ratio = (Pve_Results/Tot_Results)*100
	#print ratio
		if ratio >= Detection_Ratio:
		#print (x['value'])
			post_url = "https://{0}/api/reference_data/sets/{1}?value={2}".format(qradar, RF_B, x['value']) #posting the IP to Qradar
		#print (post_url)
			response = requests.post(post_url, headers=headers , verify=False)
			print ((x['value']),"Posted reference data succesfully")
		else:
			print ("Nothing to post")
	except ZeroDivisionError:
		ratio = 0

#print (url)
#print (qradar)
#print (token)
#print (RF_A)
#print (RF_B)
