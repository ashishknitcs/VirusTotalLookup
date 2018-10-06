import requests,time,json, pprint, PyPDF2, os, urllib
from flask import Flask
from flask import render_template
from flask import request
from werkzeug.utils import secure_filename

app = Flask(__name__)
DEFAULTS={'hashValue':'6e7785213d6af20f376a909c1ecb6c9bddec70049764f08e5054a52997241e3d'}

api_url = 'https://www.virustotal.com/vtapi/v2/file/report'

UPLOAD_FOLDER = '/uploads'
ALLOWED_EXTENSIONS = set(['pdf'])

headers = {
  "Accept-Encoding": "gzip, deflate",
  "User-Agent" : "gzip,  My Python requests library example client or username"}

proxy_list = {
    'http': 'http://username:password@proxyserver:proxyport',
    'https': 'https://username:password@proxyserver:proxyport'
}


@app.route('/', methods=['GET', 'POST'])
def home():
    pdfHash=[]
    if request.method == 'POST':
        f = request.files['inputFile']
        f.save(os.path.join(app.config['UPLOAD_FOLDER'], secure_filename(f.filename)))
        #pdfFileObject = open('Advisory-SaturnRansomware.pdf','rb')
        pdfFileObject = open(f.filename, 'rb')
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
                    print(textLines[ln])
                ln = ln+1
            pg=pg+1
        pdfObj = pdfReader.getPage(0)

    textAreaHash = request.args.get('textArea')

    if(textAreaHash is None):
        textAreaHash=DEFAULTS['hashValue']
    textAreaHash=textAreaHash.split('\n')
    #print(textAreaHash)

    i=0
    resultVT=[]
    pdfHash.append(textAreaHash)
    allHashes = pdfHash[0]
    # hashValue = '6e7785213d6af20f376a909c1ecb6c9bddec70049764f08e5054a52997241e3d'
    #print(pdfHash,len(pdfHash[0]))
    while(i < len(allHashes)):
        time.sleep(16)
        response = findHashatVT(allHashes[i])
        resultVT.append(response)
        i=i+1
    resultVTjson=json.dumps(resultVT)
    #print(resultVT)

    return render_template('home.html', size=len(pdfHash), resultVT=resultVT,resultVTjson=resultVTjson)


def findHashatVT(hashValue):
    #print(hashValue)
    hashValue=hashValue
    params = {'apikey': '84a6cbbb6d23eb392de992c9f8fe3e4451d2745bc5dba240c487e1aea08a4ae8', 'resource': hashValue}
    try:
        #response = requests.post(api_url, params=params, headers=headers,proxies=proxy_list, verify=False)
        response = requests.post(api_url, params=params, headers=headers, verify=False)
        #response = requests.post(api_url, params=params, headers=headers,proxies=urllib.request.getproxies(), verify=False)
    except ConnectionError as e:
        #print(e)
        return e
    # if(response.status_code != 1):
    #     return

    try:
        positives = response.json()['positives']
        total = response.json()['total']
        permalink=response.json()['permalink']
    except:
        positives = 'n'
        total = 'a'
        permalink=''

    try:
        Symantec_response = response.json()['scans']['Symantec']['detected']
        Symantec_result = response.json()['scans']['Symantec']['result']
        Symantec_update = response.json()['scans']['Symantec']['update']
    except:

        Symantec_response = '-'
        Symantec_result = '-'
        Symantec_update ='-'

    try:
        Trendmicro_response = response.json()['scans']['TrendMicro']['detected']
    except:
        Trendmicro_response = '-'

    try:
        Sophos_response = response.json()['scans']['Sophos']['detected']
    except:
        Sophos_response = '-'

    try:
        McAfee_response = response.json()['scans']['McAfee']['detected']
    except:
        McAfee_response='-'

    # print(positives,'/',total,Symantec_response,Symantec_result,Sophos_response,Trendmicro_response)
    #pprint.pprint(response.json())
    #print(permalink)
    return hashValue,positives,total,Symantec_response, Symantec_result,Symantec_update, Trendmicro_response, Sophos_response,McAfee_response,permalink

if __name__ == '__main__':
    app.run(port=5001,debug=False)
