import os, subprocess
import sys
from base64 import b64encode
import crypt

# Opening passwd file in append+ mode
# with open('/etc/passwd','a+') as f:          
    # for line in f:
        # if "test" in line:    
            # for word in line.split(":"):
                # print(word)      

# Opening passwd file in read mode
# with open('/etc/passwd','r') as f:          
    # for line in f:
        # print(line)
with open('/etc/shadow','r') as f:          
    for line in f:
        print(line)        

# copyme = ""
# username = "Sammy"
# passA = "Sammy"
# initToken = "4SDKnKb/0DFu4uJ7R5cUF0"
# endSalt = "password"
# hash = crypt.crypt(passA + initToken, '$6$' + endSalt)        # generating hash
# target = username + ':' + hash + ":17710:0:99999:7:::"
# # Opening shadow file in read mode
# with open('/etc/shadow','r') as f:          
    # for line in f:
        # print(line)
        
        # # Compare username/field to our provided username
        # if line.split(":")[0] == username:
            # copyme = copyme + target
        # else:
            # copyme = copyme + line        

# # Actually write the new data to the Shadow password file
# shadow = open('/etc/shadow','w')
# shadow.write(copyme)
# print(copyme)
# shadow.close()
       