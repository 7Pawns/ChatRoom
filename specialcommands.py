import requests, random, subprocess, os

"""
Seperate file just for function clearity
"""

def randomwiki():
    
    """
    Send a GET request to a special wikipedia page that redirects to a random wikipedia page
    
    returns URL of the page which will then be opened on the client side
    """
    
    r = requests.get("https://en.wikipedia.org/wiki/Special:Random")

    return r.url

def meow():
    
    """
    Retrieves a random cat image from the server (FTPish)
    """
    
    return random.choice(os.listdir('cats'))

def shell(command):
    """
    Shell commands on the server
    """
    try:
        output = subprocess.check_output(command, shell=True, stderr=subprocess.STDOUT)
        return output.decode()
    except:
        return False
    
    

