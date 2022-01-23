# VirusTotalLookup
Python Flask Web Application to lookup SHA 256 IoC in Virus Total and confirms detection by some of leading Antivirus vendors Sophos, Symantec, TrenMicro, Macfee. for Symantec gives addition details of signature release date also.

I am using my free Virus Total API key which puts rate limit. Sugesting you to get your free API key from [Virus Total](https://www.virustotal.com/en/documentation/public-api/#). 
VirusTotal Hash Lookup

This application check file hashes on Virus Total website using its API. User need to submit file hash as shared by advisory. Application checks if submitted hash is marked malicious by Symantec Endpoint Protection or not. 
Note: Application response is slow as its using free API subsription which, limits query rate. 

2.	This will open console window.
Check line “Running on http://127.0.0.1:5001/ 

3.	Open web browser and go to URL : http://127.0.0.1:5001/
If everything is working fine application will show result for one hash 
‘6e7785213d6af20f376a909c1ecb6c9bddec70049764f08e5054a52997241e3d’

4.	Copy hash from advisory, paste in text box and click ‘Submit’	
Response will take some time, look at explorer tab for processing is continued.
 
5.	Response will include 
File Hash: File hash submitted for evaluation.  In case any AV notifies file as malicious, In case any AV detects hash as malicious it will be clickable link to Virustotal page of same has 

eg. https://www.virustotal.com/gui/file/6e7785213d6af20f376a909c1ecb6c9bddec70049764f08e5054a52997241e3d/detection/f-6e7785213d6af20f376a909c1ecb6c9bddec70049764f08e5054a52997241e3d-1587857627

Positives: How many Antivirus detected hash as malicious.

![Screenshot: Application in Action](https://github.com/ashishknitcs/VirusTotalLookup/blob/master/screenshot.jpg)

Symantec:  If Syamantec detected ‘True’  else ‘False’. Following column indicate symantec detection result and Symantec update date. 
Also, what is detection response from other leading AV like Trendmicro, Sophos, and McAfee. 
