## Qradar Reference Set Contextualization with VirusTotal Detection Ratio##

The main objective of the script take your incoming traffic IPs and contextualize it for detecting threats before attack. 

###How to use the Script###

  - Rename the config.yml.template to confing.yml and give required details in the YAML. 
  - Configuration in Qradar
     - Create a two reference set in Qradar Ref_A and Ref_B and set Time_To_Live for Ref_A as 15 minutes and Ref_B 24 hours.   
     - Create a rule in Qradar with below conditions:
     	- When context Remote to Local. 
 - And when event is (Firewall Deny Etc) add more filters as per your need. 
 - And add source IP in reference set REF_A
      - Use Reference Set REF_B as input to another rules to detect threats. 

Important Note - create some scheduler in your system and run script for each 20 Min. It’s up to you calculate yourself that Ref_A TTL Value lesserthan Script Run time in scheduler. Then only redundancy of the IP will take care automatically in the Qradar.

Happy Detecting !! 

##Future Enhancements for the script##
  - Script will check more than on TI feeds(XFE, MXtoolBox Etc) and will provide you the Risk score 
  - Soon Scripts will create for bellow IOC's too:
    - URLs
    - ASN
    - File Hash
    - File Name
    - Username or UserAccount
    - ASN
    - Domains
    - Phishing URLs 
