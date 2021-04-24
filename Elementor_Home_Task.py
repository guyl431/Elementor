#!/usr/bin/env python
# coding: utf-8

# In[160]:


import requests
import time 
import json 
import sqlite3
from sqlite3 import Error


# In[250]:


urls = [
"www.elementor.com" ,
"www.textspeier.de" ,  
"www.facebook.com"  , 
"www.wordpress.org" ] 
"www.google.com", 
"raneevahijab.id", 
"boots.fotopyra.pl", 
"stackoverflow.com" , 
"www.family-partners.fr", 
"boots.fotopyra.pl"       
]


# In[251]:


#conncet to db 

def create_connection(db_file):
    """ create a database connection to a SQLite database """
    conn = None
    try:
        conn = sqlite3.connect(db_file)
        print(sqlite3.version)
    except Error as e:
        print(e)
#     finally:
#         if conn:
#             conn.close()
            
                
    
    return conn


# In[263]:


def updaterisk(urls):
    connection =  create_connection(r"C:\Elementor\Elementor\Elementor.db")         
    cursor = connection.cursor()
    cursor.execute("update SITES_HEADER set SITE_RISK = SITE_RISK +1 where SITE_URL = ?;",(urls,))
    results = cursor.fetchall()
    for r in results:
        print(r)
    cursor.close()
    connection.close()

def updatesafe(urls):
    connection =  create_connection(r"C:\Elementor\Elementor\Elementor.db")         
    cursor = connection.cursor()
    urls = "www.elementor.com"
    cursor.execute("update SITES_HEADER set SITE_SAFE = SITE_SAFE +1 where SITE_URL = ?;",(urls,))
    results = cursor.fetchall()
    for r in results:
        print(r)
    cursor.close()
    connection.close()    
    
    


# In[262]:


updatesafe(1)


# In[253]:


api = '6911f31c0f19985ffad440007eb953cc571d486f0c5c0ccc630b778603b4d7f0'


# In[254]:


url = 'https://www.virustotal.com/vtapi/v2/url/report'


# In[256]:


for sites in urls:
    params = {'apikey': api ,'resource':sites}
    response = requests.get(url, params=params)
    response_json = json.loads(response.content)
    result = response_json
    
    results = {}
    
    for value in response_json["scans"].values():
        results[value["result"]] = results.get(value["result"],0)+1
    clean_sites = results["clean site"]
    unrated_siites = results["untrated site"]
    print(results)
    
    #print(response_json["scans"].items())
    
    if response_json["positives"] >= 1: 
        updaterisk(sites)  
        
    else:
        updatesafe(sites)

    time.sleep(15)    
    
 


# In[191]:





# In[192]:





# In[ ]:





# In[ ]:





# In[ ]:




