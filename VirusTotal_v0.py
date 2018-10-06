import requests,time,json, pprint, PyPDF2
from flask import Flask
from flask import render_template
from flask import request

app = Flask(__name__)
DEFAULTS={'hashValue':'6e7785213d6af20f376a909c1ecb6c9bddec70049764f08e5054a52997241e3d'}

api_url = 'https://www.virustotal.com/vtapi/v2/file/report'

headers = {
  "Accept-Encoding": "gzip, deflate",
  "User-Agent" : "gzip,  My Python requests library example client or username"}

proxies = {
    'http': 'http://ashishkushwaha:M@@y2018@10.72.15.60:80',
    'https': 'http://ashishkushwaha:M@@y2018@10.72.15.60:80'
}

# Create the session and set the proxies.
s = requests.Session()
s.proxies = proxies

@app.route('/')
def home():
    pdfFileObject = open('Advisory-SaturnRansomware.pdf','rb')
    pdfReader = PyPDF2.PdfFileReader(pdfFileObject)
    pg=0
    pdfHash=[]
    while(pg<pdfReader.numPages):
        pdfObj = pdfReader.getPage(pg)
        pageText = pdfObj.extractText()
        textLines = pageText.splitlines()
        ln=0
        while(ln<len(textLines)):
            if(len(textLines[ln])>30 and ' ' not in textLines[ln] and '\\' not in textLines[ln] and ':' not in textLines[ln]):
                pdfHash.append(textLines[ln])
                #print(textLines[ln])
            ln = ln+1
        pg=pg+1
    pdfObj = pdfReader.getPage(0)

    textAreaHash = request.args.get('textArea')

    if(textAreaHash is None):
        textAreaHash=DEFAULTS['hashValue']
    textAreaHash=textAreaHash.split('\n')

    i=0
    resultVT=[]
    print(pdfHash)
    print(textAreaHash)
    pdfHash.append(textAreaHash)
    # hashValue = '6e7785213d6af20f376a909c1ecb6c9bddec70049764f08e5054a52997241e3d'
    print(pdfHash)
    while(i < len(pdfHash)):
        time.sleep(16)
        response = findHashatVT(pdfHash[i])
        resultVT.append(response)
        i=i+1
    resultVTjson=json.dumps(resultVT)
    #print(resultVT)

    return render_template('home.html', size=len(pdfHash), resultVT=resultVT,resultVTjson=resultVTjson)


def findHashatVT(hashValue):
    print(hashValue)
    hashValue=hashValue
    params = {'apikey': '84a6cbbb6d23eb392de992c9f8fe3e4451d2745bc5dba240c487e1aea08a4ae8', 'resource': hashValue}
    try:
        response = requests.post(api_url, params=params, headers=headers,proxies=proxies, verify = False)
        # Make the HTTP request through the session.
        #r = s.post(api_url, params=params, headers=headers)
    except ConnectionError as e:
        print(e)
        return e
    # if(response.status_code != 1):
    #     return

    try:
        positives = response.json()['positives']
        total = response.json()['total']
        permalink=response.json()['permalink']
        Symantec_response = response.json()['scans']['Symantec']['detected']
        Symantec_result = response.json()['scans']['Symantec']['result']
        Symantec_update = response.json()['scans']['Symantec']['update']
        Trendmicro_response = response.json()['scans']['TrendMicro']['detected']
        Sophos_response = response.json()['scans']['Sophos']['detected']
        McAfee_response = response.json()['scans']['McAfee']['detected']
    except:
        positives = 'n'
        total = 'a'
        permalink=''
        Symantec_response = ''
        Symantec_result = ''
        Symantec_update =''
        Trendmicro_response = ''
        Sophos_response = ''
        McAfee_response=''

    # print(positives,'/',total,Symantec_response,Symantec_result,Sophos_response,Trendmicro_response)
    pprint.pprint(response.json())
    print(permalink)
    return hashValue,positives,total,Symantec_response, Symantec_result,Symantec_update, Trendmicro_response, Sophos_response,McAfee_response,permalink

if __name__ == '__main__':
    app.run(port=5002,debug=True)