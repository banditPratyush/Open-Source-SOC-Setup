#!/usr/bin/env python3 
from base64 import b64encode 
from cortexutils.responder import Responder 
import requests 
import ipaddress 
import json 
#from requests.packages.urllib3.exceptions import InsecureRequestWarning 
login_endpoint = 'security/user/authenticate' 
#requests.packages.urllib3.disable_warnings(InsecureRequestWarning) 
class Wazuh(Responder): 
   def __init__(self): 
       Responder.__init__(self) 
       self.wazuh_manager = self.get_param('config.wazuh_manager', None, 'https://localhost:55000') 
       self.wazuh_user = self.get_param('config.wazuh_user', None, 'Username missing!') 
       self.wazuh_password = self.get_param('config.wazuh_password', None, 'Password missing!') 
       self.wazuh_agent_id = self.get_param('data.case.customFields.wazuh_agent_id.string', None, "Agent ID Missing :!") 
       self.observable = self.get_param('data.data', None, "Data is empty") 
       self.observable_type = self.get_param('data.dataType', None, "Data type is empty") 
    
   def run(self): 
       Responder.run(self) 
       auth = (self.wazuh_user, self.wazuh_password) 
       headers = {'Content-Type': 'application/json'} 
       # Check observable to ensure valid IP address 
       if self.observable_type == "ip": 
           try: 
               ipaddress.ip_address(self.observable) 
           except ValueError: 
               self.error({'message': "Not a valid IPv4/IPv6 address!"}) 
       else:  
           self.error({'message': "Not a valid IPv4/IPv6 address!"}) 
       payload = '{"command":"firewall-drop1800", "arguments": ["-", "' +  self.observable + '", "' + self.wazuh_agent_id + '", "var/log/test.log"], "alert":{"data": {"srcip": "' + self.observable +'"} }  }' 
 
       login_url = f"{self.wazuh_manager}/{login_endpoint}" 
       basic_auth = f"{self.wazuh_user}:{self.wazuh_password}".encode() 
       login_headers = {'Content-Type': 'application/json', 
                 'Authorization': f'Basic {b64encode(basic_auth).decode()}'} 
       response = requests.get(login_url, headers=login_headers, verify=False) 
       token = json.loads(response.content.decode())['data']['token'] 
       requests_headers = {'Content-Type': 'application/json', 
                    'Authorization': f'Bearer {token}'} 
       r = requests.put(self.wazuh_manager + '/active-response' , headers=requests_headers, data=payload, verify=False) 
       if r.status_code == 200: 
           self.report({'message': "Added DROP rule for " + self.observable  }) 
       else: 
           self.error(r.status_code) 
    
   def operations(self, raw): 
      return [self.build_operation('AddTagToCase', tag='Wazuh: Blocked IP')]  
 
if __name__ == '__main__': 
  Wazuh().run()
