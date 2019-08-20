# Hornets-Nest Overview
This repo will function as a repo for a number of resources/brain dumps that I collate relating to a lot of security. I try to learn both red and blue team elements as I believe Red Team informs Blue Team. You cannot detect what you don't know exists or is possible. This is a kind of 'Purple Teaming' emphasis. - ill try to keep it tidy! ;)

# CyberChef Recipes

**Encrypt Strings in Group Policy Preference File format (useful for creating Honey xml files with amusing passwords that PowerSploit etc will decrypt - like the lyrics of a certain Rick Astley song...)**
```
Encode_text('UTF16LE (1200)')

AES_Encrypt({'option':'Hex','string':'4e 99 06 e8  fc b6 6c c9  fa f4 93 10  62 0f fe e8 f4 96 e8 06  cc 05 79 90  20 9b 09 a4  33 b6 6c 1b'},{'option':'Hex','string':''},'CBC','Raw','Raw')

To_Base64('A-Za-z0-9+/=')
```

**Decrypt Strings in Group Policy Preference File format (to check the above, as well as for offensive checks).**
```
From_Base64('A-Za-z0-9+/=',true)

AES_Decrypt({'option':'Hex','string':'4e 99 06 e8  fc b6 6c c9  fa f4 93 10  62 0f fe e8 f4 96 e8 06  cc 05 79 90  20 9b 09 a4  33 b6 6c 1b'},{'option':'Hex','string':''},'CBC','Raw','Raw',{'option':'Hex','string':''})

Decode_text('UTF16LE (1200)')
```


# Honey-all-the-things ideas

## Powersploit landmine:
Powersploit has a script called "Get-GPPPassword" - this file does the following:

Get-GPPPassword searches a domain controller for groups.xml, scheduledtasks.xml, services.xml and datasources.xml and returns plaintext passwords.

This can be used for our advantage by setting up a dummy GPO, or even just a basic xml file named something the above, with a value in it that contains a password of our own design. You would then set up auditing on this folder within SYSVOL on your domain, and alert if this particular file is accessed. 

A baseline example xml file could be the following (from https://adsecurity.org/?p=384 )
```
<?xml version=”1.0″ encoding=”utf-8″?>
<Groups clsid=”{3125E937-EB16-4b4c-9934-544FC6D24D26}”>
<User clsid=”{DF5F1855-51E5-4d24-8B1A-D9BDE98BA1D1}” name=”LocalTestUser” image=”0″ changed=”2013-07-04 00:07:13″ uid=”{47F24835-4B58-4C48-A749-5747EAC84669}”>
<Properties action=”C” fullName=”” description=”” cpassword=”sFWOJZOU7bJICaqvmd+KAEN0o4RcpxxMLWnK7s7zgNR+JiJwoSa+DLU3kAIdXc1WW5NKrIjIe9MIdBuJHvqFgbcNS873bDK2nbQBqpydkjbsPXV0HRPpQ96phie6N9tn4NF3KYyswokkDnj8gvuyZBXqoG94ML8M1Iq7/jhe37eHJiZGyi5IBoPuCfKpurj2″ changeLogon=”0″ noChange=”0″ neverExpires=”0″ acctDisabled=”0″ userName=”LocalTestUser”/>
</User>
</Groups>
```
You could use the cyberchef recipe at the top of this page to create a new string and enter that into the cpassword variable.

Some example files : https://github.com/s0lari/Decoy-sploit

## Honey files
General other honey files can be created in a similar fashion and scattered around file shares deep in the structure that contain strings such as 'password' 'pass' 'secret' 'administrator' etc so that any other automated powershell scripts will find them and trigger audit rules in your SIEM (ELK/Splunk etc).

## Honey users
Create a user that is not used by the business in any way and set the logon hours to full deny. Set up detection for any logon attempts to this user - this will detect password sprays.

Also see the bloodhoud section in the Splunk Detections area below to use this in a similar fashion.

###### Kerberoasting Honey SPN

Set up a service account that is not used by the business in any way and set the logon hours to fully deny. Set up detection for any logon attempts to an SPN that is configured on this account. Whitelist any maintenance/configuration systems. This should be a high fidelity detection on kerberoasting.

Set ServicePrinciple name like so :
```
setspn -U -A http/blah SERVICE_USER_ACCOUNT_HERE
```
See Splunk Detections section for example query.

**COUNTER-POINT: Some red-teamers will check for honey accounts - generally this is done by checking when the account was last used/logged into - if you have a script/manual process that logs into that account once every 14 days or so, you should be alright -whitelist this activity in SIEM**


# Splunk Detections
## Query for Splunk detections for Honey User

(whitelist false positives as necessary)
```
index=winevent_sec EventCode="*"  user=xxxxxxxxx
```
## Honey SPN for kerberoasting attack detection.
(whitelist false positives as necessary)
```
index=winevent_sec EventCode=4769 Service_Name=super_not_shady_SPN
```

## BLOODHOUND:

Some inspiration from http://www.stuffithoughtiknew.com/2019/02/detecting-bloodhound.html

Time period -eg 60 minutes
```
index=winevent_sec EventCode=4662  Accesses="Read Property"  (WHITELIST A SHEDLOAD OF SERVICE ACCOUNTS)
| stats count by Account_Name
| where count >x (where x is a good baseline)
```
This will give a pretty good result, however, if you look at event logs that come from running bloodhound, you can see that there are some other indicators we can alert on:

```
Log Name:      Security
Source:        Microsoft-Windows-Security-Auditing
Date:          20/08/2019 09:00:29
Event ID:      4662
Task Category: Directory Service Access
Level:         Information
Keywords:      Audit Success
User:          N/A
Computer:      dc1.internal.blah123.com
Description:
An operation was performed on an object.

Subject :
	Security ID:		INTERNAL\Administrator
	Account Name:		Administrator
	Account Domain:		INTERNAL
	Logon ID:		0x2FA81

Object:
	Object Server:		DS
	Object Type:		user
	Object Name:		CN=Rhubarb,CN=Users,DC=internal,DC=blah123,DC=com
	Handle ID:		0x0

Operation:
	Operation Type:		Object Access
	Accesses:		Read Property	
	Access Mask:		0x10
	Properties:		Read Property
		General Information
			sAMAccountType
			primaryGroupID
		Account Restrictions
			userAccountControl
		Public Information
			objectClass
	User


Additional Information:
	Parameter 1:		-
	Parameter 2:		
```
```
Log Name:      Security
Source:        Microsoft-Windows-Security-Auditing
Date:          20/08/2019 09:00:29
Event ID:      4662
Task Category: Directory Service Access
Level:         Information
Keywords:      Audit Success
User:          N/A
Computer:      dc1.internal.blah123.com
Description:
An operation was performed on an object.

Subject :
	Security ID:		INTERNAL\Administrator
	Account Name:		Administrator
	Account Domain:		INTERNAL
	Logon ID:		0x2FA81

Object:
	Object Server:		DS
	Object Type:		user
	Object Name:		CN=Rhubarb,CN=Users,DC=internal,DC=blah123,DC=com
	Handle ID:		0x0

Operation:
	Operation Type:		Object Access
	Accesses:		Read Property
				
	Access Mask:		0x10
	Properties:		Read Property
	User
		Public Information
			cn
			distinguishedName
		Group Membership
			member
		General Information
			primaryGroupID
			objectSid
			sAMAccountName
			sAMAccountType
		dNSHostName
			dNSHostName


Additional Information:
	Parameter 1:		-
	Parameter 2:		
```

Using these properties lookups can function like a fingerprint for BloodHound activity - there are a lot of Active Directory queries and operations that query AD attributes and properties that are not in these forms, so you can use this to remove false positives.


**LOOKUP EVENT 1**

Properties:	Read Property

User

Public Information

cn

distinguishedName

Group Membership

member

General Information

primaryGroupID

objectSid

sAMAccountName

sAMAccountType

dNSHostName

dNSHostName

**LOOKUP EVENT 2**


Properties:	Read Property

General Information

sAMAccountType

primaryGroupID

Account Restrictions

userAccountControl

Public Information

objectClass

User


## KERBEROASTING:

**Adjust variables below and whitelist any users that are service accounts that are noisey. This is for any encryption type which allows for failures.**

Time period -eg 60 minutes
```
index=winevent_sec EventCode=4769 Ticket_Options=0x40810000 Service_Name!="*$" Service_Name!="krbtgt" Account_Name!="*$@*"   | dedup Service_Name   | stats  count by user  | where  count>X (where x is a good baseline)
```
**Only for specific RC4 encrypted requested Kerberos requests – this is since they crack faster so are generally the hackers choice.**
```
index=winevent_sec EventCode=4769 Ticket_Options=0x40810000 Ticket_Encryption_Type=0x17 Service_Name!="*$" Service_Name!="krbtgt" Account_Name!="*$@*"   | dedup Service_Name   | stats  count by user  | where  count>X (where x is a good baseline)
```
## DNS High Entropy Domain names - DGA Detection
```
| tstats count(DNS.dest) AS "Count of dest" from datamodel=Network_Resolution where (nodename = DNS) (DNS.query!="**copy and use this as whitelisting entry*")  groupby DNS.query, DNS.src prestats=true | stats dedup_splitvals=t count(DNS.dest) AS "CountD" by DNS.query, DNS.src | sort limit=25000 DNS.query | fields - _span | rename DNS.query AS query |rename DNS.src AS src| fillnull "CountD" | fields query, "CountD", src |where CountD=1 |eval list="mozilla"| `ut_parse(query, list)` | `ut_shannon(ut_domain)` | where ut_shannon>3.5 | table ut_shannon, query,  src | sort ut_shannon desc
```
## Using Splunk Machine Learning Toolkit to show 'weird' destination ports - limited time lengths available depending on your result numbers.
This will attempt to show anomalous destination ports and remove internal destination traffic from the results. Use case - C2 traffic to random hosts on random ports.
```
| tstats count AS "Count of All Traffic" from datamodel=Network_Traffic where (nodename = All_Traffic) groupby All_Traffic.user, All_Traffic.dest_ip, All_Traffic.src_ip, All_Traffic.dest_port, All_Traffic.src_port prestats=true | stats dedup_splitvals=t count AS "Count of All Traffic" by All_Traffic.user, All_Traffic.dest_ip, All_Traffic.src_ip, All_Traffic.dest_port, All_Traffic.src_port   | rename All_Traffic.user AS user All_Traffic.dest_ip AS dest_ip All_Traffic.src_ip AS src_ip All_Traffic.dest_port AS dest_port All_Traffic.src_port AS src_port | fillnull "Count of All Traffic" | fields  src_ip,src_port, user, dest_ip, dest_port,  "Count of All Traffic"| where (NOT cidrmatch("10.0.0.0/8",dest_ip) AND NOT cidrmatch("172.16.0.0/12",dest_ip) AND NOT   cidrmatch("192.168.0.0/16",dest_ip) AND NOT cidrmatch("10.blah.blah.blah/24",src_ip) AND cidrmatch("10.0.0.0/8",src_ip)) | anomalydetection  dest_port | sort - dest_port
```
## Using Splunk Machine Learning Toolkit to show 'weird' connection pairs (rare) - limited time lengths available depending on your result numbers.
```
| tstats count AS "Count of All Traffic" from datamodel=Network_Traffic where (nodename = All_Traffic) groupby All_Traffic.user, All_Traffic.dest_ip, All_Traffic.src_ip, All_Traffic.dest_port, All_Traffic.src_port prestats=true | stats dedup_splitvals=t count AS "Count of All Traffic" by All_Traffic.user, All_Traffic.dest_ip, All_Traffic.src_ip, All_Traffic.dest_port, All_Traffic.src_port   | rename All_Traffic.user AS user All_Traffic.dest_ip AS dest_ip All_Traffic.src_ip AS src_ip All_Traffic.dest_port AS dest_port All_Traffic.src_port AS src_port | fillnull "Count of All Traffic" | fields  src_ip,src_port, user, dest_ip, dest_port,  "Count of All Traffic"| where (NOT cidrmatch("10.0.0.0/8",dest_ip) AND NOT cidrmatch("172.16.0.0/12",dest_ip) AND NOT   cidrmatch("192.168.0.0/16",dest_ip) AND NOT cidrmatch("10.blah.blah.blah/24",src_ip) AND cidrmatch("10.0.0.0/8",src_ip)) | anomalydetection  dest_ip | sort - dest_port
```
## Defense in Depth Security stack

Fundamentally you're going to be in a pretty good place if you manage these things in your environment - aims mainly at Windows Domain environements (brain dump, no priority/order as each environment is different, some are absolute must tho):

0) BACKUPS - Ransomware is real - test your backups, do DR scenarios - tape is old, but at least it is disconnected from environemnt.
1) Remove local admin account usage for standard users
2) Enable host based firewalls on your internal client machines (treat internal network as hostile) & Segment internal networks (eg by department - makes logging easier as well as users generally do the same kinds of activities, so long tailed stat analysis is easier)!
3) Disable LLMNR & NBNS & SMB v1 on your network (do even more with CIS hardening guides), and disable WPAD if it isn't explicitly used.
4) Use AV - ensure it is running - if you can afford NGAV+EDR - awesomesauce!
5) Use application whitelisting - SRP is good when you have no alternative
6) Log all your things - sysmon, Active Directory, web apps - Azure Sentinel, Various ELK Stacks.  Pretty cheap is Rapid 7 InsightIDR, which hooks into 11.
7) Email filtering solution (O365 is not bad) 
8) If you're using anything O365/Azure - get the Advanced Threat Protections/ UEBA solutions - they're pretty good
9) Deploy Sysmon and have that logged to your SIEM - various configs available - see below.
10) Deploy Honey tokens/files/users/admins/SRP/GPO/pots/networks
11) Vuln scanner - Rapid7 InsightVM is good. It also dumps vulnerability data into InsightIDR
12) Patch your stuff! As fast and as much as businessly possible.
13) Get a UTM firewall (Fortigate are pretty good and not as expensive as Palo Alto) - this will allow the following:
14) Internet Web Whitelisting (ie, default deny unless category/site specifically allowed)
15) DNS Filtering
16) Web App firewalling on your webapps & Network IPS all the things!
17) Gateway AV
18) App control at gateway (good for detecting/preventing DNS tunneling & CASBI functionality too)
19) 802.1x/Forticlient has a similar function that denies access
20) Encrypt your laptops with Bitlocker + PIN
21) Lock down windows store
22) Lock down cmd/powershell usage
23) 2FA - DUO is very good. Used in conjuntion with an SSL VPN can work nicely - means your internal webapps are not directly accessible too!
24) Threat intelligence feed for your logs in your SIEM
25) TRAIN YOUR STAFF! All is for naught if your staff aren't well trained, both users and SOC. Pluralsight has some good content - SANS/OSCP = excellent standard. This will enable more advanced functions once you reach maturity, like threat hunting and purple teaming.
26) DLP - don't spend a huge amount of time on this, much bigger wins possible - prevents accidental loss of data.
27) Incident response plans - make some, test them. Tabletop exercises can be useful.
28) Audit domain passwords - use pass-phrases, enforce 15 character minimum after LOTS of training and LOTS of patience. Think https://xkcd.com/936/ - totally do-able and in the past in the entire company only had 1 person need to reset the next day. Dump the ntds.dit file via shadow copy and crack using a decent GPU rig and hashcat. Have those users change their passwords - test and retest. If you can't crack it using some big lists, it will reduce risk quite a bit.
29) haveibeenpwned.com - self explainatory
30) Disallow the use of personal email (gmail/hotmail etc) - no point in spending loads of money on filtering and tech only to have your workstations pwned by a personal phishing email.
31) OSINT/Recon check yourself - see what is available or posted by your users! Especially Linkedin for technologies used by admins/secops.



# Security Resources - Links, books, CTFs, etc

## Blue Team & Threat Hunting

SANS Blue team wiki - helpful cheat sheets & Reference
https://wiki.sans.blue/#!index.md
 
Amazing site for which windows events to log and why.
https://www.malwarearchaeology.com/cheat-sheets
https://www.malwarearchaeology.com/logging
 
Site dedicated to active directory security - red team benefits : know what to target.
https://adsecurity.org/
 
Mitre Attack based SIEM rules (multi format)
https://github.com/Neo23x0/sigma
 
Creator of HELK (Hunting ELK Stack) and the threat hunting playbook
https://github.com/Cyb3rWard0g
 
Guide to setting up enterprise wide SYSMON threat hunting/logging
https://securityaffairs.co/wordpress/81288/security/hunting-mitres-attck-splunk.html
 
Threat Hunting Splunk App (SYSMON necessary, Mitre Attack based)
https://github.com/olafhartong/ThreatHunting
 
SANS SIEM (Security configured ELK stack)
https://github.com/philhagen/sof-elk
 
Book on developing SOC and SIEM - includes working with the business ( very good material here).
https://www.amazon.co.uk/Blue-Team-Field-Manual-BTFM/dp/154101636X/ref=pd_lpo_sbs_14_t_1?_encoding=UTF8&psc=1&refRID=WWDBBTYX9KR3Z7MY9CDP
 
Good blueteam/IR handbook (Less concise, but more theory added)
https://www.amazon.co.uk/Blue-Team-Handbook-condensed-Operations/dp/1726273989/ref=sr_1_2?qid=1552652679&refinements=p_27%3ADon+Murdoch+GSE&s=books&sr=1-2&text=Don+Murdoch+GSE
 
General Overall Security book - not hugely in depth but wide.
https://www.amazon.co.uk/Defensive-Security-Handbook-Lee-Brotherston/dp/1491960388/ref=sr_1_fkmrnull_1?crid=3SX1IOK1H2R6O&keywords=defensive+security+handbook&qid=1552653330&s=gateway&sprefix=defensive+secur%2Cdigital-text%2C185&sr=8-1-fkmrnull

CanaryTokens (Various Canary token type generators)
https://canarytokens.org/generate
 
"The MaGMa framework was designed specifically to support the use case management process. The tool provides a very practical and flexible approach to managing use cases in any security monitoring environment, from simple to complex. In total, 12 L1 use cases, 62 L2 use cases and 169 L3 use cases have been predefined in the tool, giving organizations a jumpstart in use case management.” Use cases are MITRE ATT&CK Matrix based."
https://www.linkedin.com/pulse/magma-use-case-framework-released-today-rob-van-os

 

Sigma rules for splunk (200 use cases various - MITRE ATT&CK Matrix based )

https://github.com/Neo23x0/sigma

 

Saved Searches file for above SIGMA rules:

https://github.com/dstaulcu/TA-Sigma-Searches/blob/master/default/savedsearches.conf 

 

Recommended EDR (commercial):

https://www.carbonblack.com/products/cb-threathunter/
 
https://www.endgame.com/platform
 
OWASP Project
https://www.owasp.org/index.php/Main_Page
 
OWASP Cheat sheets
https://github.com/OWASP/CheatSheetSeries

Some good Active Directory Deception ideas

https://www.labofapenetrationtester.com/2018/10/deploy-deception.html
 

## Purple Team
List of common attacks. 
https://attack.mitre.org/
 
Adversary Emulation tools list
http://pentestit.com/adversary-emulation-tools-list/
 
Large list of IR tools and resources
https://github.com/meirwah/awesome-incident-response
 
Black Hills information security - awesome company that give away a tonne of free resources and tools.
https://www.blackhillsinfosec.com/blog/
https://www.youtube.com/channel/UCJ2U9Dq9NckqHMbcUupgF0A (bhis youtube channel)
 
Great tool to keep track of gap analysis of environment mapped to the MITRE attack matrix
https://nsacyber.github.io/unfetter/
 
Good blueteam/IR handbook (Very concise - more a list of commands and why)
https://www.amazon.co.uk/Blue-Team-Handbook-condensed-Responder/dp/1500734756
 
Pretty much the definitive go to guide for DFIR.
https://www.amazon.co.uk/Incident-Response-Computer-Forensics-Third-ebook/dp/B00JFG7152
 
Dehashed (DeHashed is a hacked database search engine created for security analysts, journalists, security companies, and everyday people to help secure accounts and provide insight on database breaches and account leaks.)
https://dehashed.com
 
HaveIBeenPwned (domain search)
https://haveibeenpwned.com/DomainSearch
 
One of the best if not the best site for the OSINT topic.
https://inteltechniques.com
 
A collection of inspiring lists, manuals, cheatsheets, blogs, hacks, one-liners, cli/web tools and more.
https://github.com/trimstray/the-book-of-secret-knowledge/blob/master/README.md
 
MITRE ATT&CK Testing framework
https://redcanary.com/atomic-red-team/
 
 
Purple Team ATT&CK™ Automation
https://github.com/praetorian-code/purple-team-attack-automation
 
A datasource assessment on an event level to show potential ATT&CK coverage

https://github.com/olafhartong/ATTACKdatamap

 
Applying a Threat Based Approach to Security Testing (great article on red team/purple team)
https://threatexpress.com/blogs/2018/threat-gets-a-vote-applying-a-threat-based-approach-to-security-testing/
Threat Mitigation Strategies: Part 1
https://threatexpress.com/blogs/2018/threat-mitigation-strategies-observations-recommendations/
Threat Mitigation Strategies: Part 2 (great collated list of 'wins' relating to previous two articles)
https://threatexpress.com/blogs/2018/threat-mitigation-strategies-technical-recommendations-and-info-part-2/
 
Purple/Red team security tool validation system (adversary simulation - commercial license)
https://www.scythe.io/platform
 
Complete Mandiant Offensive VM (Commando VM), the first full Windows-based penetration testing virtual machine distribution. Good for attacking windows Active directory based environments.
https://www.fireeye.com/blog/threat-research/2019/03/commando-vm-windows-offensive-distribution.html
 
## Red Team
 
Great list of resources/tools in Attack-chain categories
https://github.com/infosecn1nja/Red-Teaming-Toolkit
 
A huge list of useful payloads and bypasses

https://github.com/swisskyrepo/PayloadsAllTheThings

 
Great list of resources/tools in Attack-chain categories (more)
https://github.com/yeyintminthuhtut/Awesome-Red-Teaming
 
Gap analysis tool containing scripts to test various MITRE attack rules.
https://github.com/redcanaryco/atomic-red-team
 
Same as the Blue team field manual - but for the Red Team (join the dark side -they have cookies).
https://www.amazon.co.uk/Rtfm-Red-Team-Field-Manual/dp/1494295504/ref=pd_lpo_sbs_14_t_0?_encoding=UTF8&psc=1&refRID=WWDBBTYX9KR3Z7MY9CDP
 
Great book detailing hacker playbooks tools and techniques.
https://www.amazon.co.uk/Hacker-Playbook-Practical-Penetration-Testing/dp/1980901759/ref=pd_sim_14_4/260-2231008-3826148?_encoding=UTF8&pd_rd_i=1980901759&pd_rd_r=21b93499-471d-11e9-abbc-f52bf6129af9&pd_rd_w=jwkcz&pd_rd_wg=W97Hb&pf_rd_p=1b8636ae-4f21-4403-a813-e8849dd46de4&pf_rd_r=WWDBBTYX9KR3Z7MY9CDP&psc=1&refRID=WWDBBTYX9KR3Z7MY9CDP
 
Great 'scenario' based book on hacking networks of various types and kinds. 
https://www.amazon.co.uk/Advanced-Penetration-Testing-Hacking-Networks-ebook/dp/B06XCKTKK8/ref=pd_sim_351_7?_encoding=UTF8&pd_rd_i=B06XCKTKK8&pd_rd_r=8263cbb8-471e-11e9-917c-7de6dac306e9&pd_rd_w=TKxVS&pd_rd_wg=MmoJA&pf_rd_p=1b8636ae-4f21-4403-a813-e8849dd46de4&pf_rd_r=ZWBWAA765VN3BG379JQA&psc=1&refRID=ZWBWAA765VN3BG379JQA
 
Pentesting book with practical labs.
https://www.amazon.co.uk/Penetration-Testing-Hands-Introduction-Hacking-ebook/dp/B00KME7GN8
 
Cutting-edge techniques for finding and fixing critical security flaws
https://www.amazon.co.uk/Gray-Hat-Hacking-Ethical-Handbook-ebook/dp/B07D3J9J4H/ref=sr_1_1?keywords=grey+hat+hacking&qid=1556278379&s=digital-text&sr=1-1-catcorr
 
Purple/Red team security tool validation system (adversary simulation)
https://www.scythe.io/platform
 
Complete Mandiant Offensive VM (Commando VM), the first full Windows-based penetration testing virtual machine distribution. Good for attacking windows Active directory based environments.
https://www.fireeye.com/blog/threat-research/2019/03/commando-vm-windows-offensive-distribution.html


## Digital Forensics

Cheat sheets for common DFIR tools
https://digital-forensics.sans.org/community/cheat-sheets
 
Same as above - in twice due to categories and because it is an awesome book.
https://www.amazon.co.uk/Incident-Response-Computer-Forensics-Third-ebook/dp/B00JFG7152
 
A software reverse engineering (SRE) suite of tools developed by NSA's Research Directorate
https://ghidra-sre.org/
 
FLARE VM is a freely available and open sourced Windows-based security distribution designed for reverse engineers, malware analysts, incident responders, forensicators, and penetration testers.
https://www.fireeye.com/blog/threat-research/2017/07/flare-vm-the-windows-malware.html


## General

CIS top 20 security controls  - great for scoring the maturity of a company's security.
https://learn.cisecurity.org/20-controls-download
 
Great resources on here including a free excel tool that helps you 'score' your companies maturity against the CIS Top 20 controls.
https://www.auditscripts.com/free-resources/critical-security-controls/
 
CIS online assessment tool (html version of the excel manual assessment tool).
https://www.cisecurity.org/blog/cis-csat-free-tool-assessing-implementation-of-cis-controls/
 
SANS posters - some great 'quick glance reference' info here.
https://uk.sans.org/security-resources/posters
 
Excellent CTF site including various other challenges (DFIR, malware reversing, Stego etc)
https://www.hackthebox.eu/
 
Yearly CTF that is story driven - very high quality CTF containing a range of challenges.
https://www.holidayhackchallenge.com/2018/
 
A lot of various labs (ctf, blue team, etc) - nice thing is no VPN required, all accessible through web browser.
https://attackdefense.com/
 
## Misc other
 
Great Cron Job building website
https://crontab.guru/#*/10_6-17_*_*_1-5
 
Easily Report Phishing and Malware
https://decentsecurity.com/#/malware-web-and-phishing-investigation/
 
Scan Phishing sites (generates webpage of site)
https://urlscan.io/
 
Open Source Threat intel site
https://pulsedive.com/
 
TCPIP Utils - quick IP/dns lookup check
https://dnslytics.com/
 
Awesome tool - CyberChef is a simple, intuitive web app for carrying out all manner of "cyber" operations within a web browser.
https://gchq.github.io/CyberChef/
 
CTF Walkthroughs (good to watch for thought process)
https://www.youtube.com/channel/UCa6eh7gCkpPo5XXUDfygQQA
 
Various CTF and hack related things.
https://www.youtube.com/channel/UClcE-kVhqyiHCcjYwcpfj9w/videos?disable_polymer=1
 
## Podcasts 
  
Purple Squad Security - Purple Team podcast

Black Hills Information Security - Large range of high quality teaching.

Darknet Diaries - Stories of past hacks.

Malicious life

Paul's Enterprise Security Weekly - General podcast reviewing enterprise news/security products

 
 
Paul's Security Weekly - General podcast containing various enterprise related topics

Sans Internet Stormcenter Daily - 5 Minute or so show on the highlights of security news from SANS

State of the Hack - Mandiant in depth podcast

Beers with TALOS - General news and discussions podcast

Breach - Stories of past hacks.

Defensive Security Podcast - Higher level security news discussions.

Smashing Security - Stories of past hacks and security news.

 
The Cyberwire - Overall news

Digital Forensics Survival Podcast - DFIR Podcast

Hacking Humans - Social Engineering podcast

The Privacy, Security & OSINT Show - OSINT and privacy Podcast

Professor Messers A+ Study Group

Professor Messers Network+ Study Group

Professor Messers Security+ Study Group

Red Team Podcast - Red Team podcast

Tradecraft Security Weekly - Mainly BHIS related podcast on more advanced hacking techniques.

Advanced Persistent Security - Red Team podcast

Hacked - Various

Rally Security Podcast - Mainly a red team podcast.

ROOT ACCESS - Various

TrustedSec Security Podcast - Similar to BHIS, but more general in topics.

