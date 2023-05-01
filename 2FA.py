import os, subprocess
import sys
from base64 import b64encode
import crypt

# Check to see if username already exists; if it does, return true
def checkUsername(uname):
    flag = False
    with open('/etc/shadow','r') as fp:         # Opening shadow file in read mode
        arr=[]
        for line in fp:                         # Enumerating through all the entries in shadow file
            temp=line.split(':')
            if temp[0]==uname:                  # checking whether entered username exist or not
                flag = True
                
    return flag
    
# Verify user's password is correct; requires both username and password
def checkPassword(uname, password):

    with open('/etc/shadow','r') as fp:
        flag = False
        arr=[]
        for line in fp:                                 #Enumerating through all the enteries in shadow file
            temp=line.split(':')
            if temp[0]==uname:                          #checking whether entered username exist or not    
                #print(temp)
                salt_and_pass=(temp[1].split('$'))      #retrieving salt against the user
                #print(salt_and_pass)
                salt=salt_and_pass[2]
                result=crypt.crypt(password,'$6$'+salt)   #calculating hash via salt and password entered by user
                if result==temp[1]:                     #comparing generated salt with existing salt entry
                    #print("Login successful.")
                    return True
                else:
                    #print("Invalid Password")
                    return False
                    
# Verify user's login token is correct; requires username, password, and login token
def checkToken(uname, password, token):
        
    salt = ""
    # Go through the shadow file, look for the user's entry
    with open('/etc/shadow','r') as f:          
        for line in f:
        
            # If we have the correct username, save the salt and expected token value
            if line.split(":")[0] == uname:
                salt = line.split("$")[2]
                hashcode = crypt.crypt(password + token, '$6$' + salt)
                
                # Compare the line to <username>:$6$<8-char salt>$code...
                temp = uname + ':' + hashcode + ":17710:0:99999:7:::"
                if temp == line.replace("\n", ""):
                    return True
                else:
                    # print(temp)
                    # print(line)
                    return False
    
    # Return False is we reach this point, username wasn't detected
    return False
    
# Set the user's password/token to be the provided values, use salt if provided, otherwise use existing value
def updateShadowFile(uname, password, token, salt):
    
    copyme = ""
    # print("Updating shadow file...")
    
    # If we weren't provided salt (just a normal login), find the salt in the shadow file and use that
    if len(salt) < 1:
        with open('/etc/shadow','r') as f:          
            for line in f:
                
                # Compare username/field to our provided username
                if line.split(":")[0] == uname:
                    salt = line.split("$")[2]    
            
    hashcode = crypt.crypt(password + token, '$6$' + salt)        # generating hash
    target = uname + ':' + hashcode + ":17710:0:99999:7:::"
    # Opening shadow file in read mode
    with open('/etc/shadow','r') as f:          
        for line in f:
            
            # Compare username/field to our provided username
            if line.split(":")[0] == uname:
                copyme = copyme + target
            else:
                copyme = copyme + line        

    # Actually write the new data to the Shadow password file
    shadow = open('/etc/shadow','w')
    shadow.write(copyme)
    shadow.close()

# Create a user, ONLY if they don't already exist in the shadow file    
def createUser():
    uname = input("\n Username: ")
        
    # Prompt user to enter password:    
    passA = input(" Password: ")
    passB = input(" Confirm Password: ")
    
    # If passwords don't match, end function
    if passA != passB:
        print("\n I'm afraid these passwords do not match; Returning to main menu.")
        return False
        
    # Prompt user to provide salt info; only accept up to 8 characters
    userSalt = input(" Salt: ")    
    rand1 = os.urandom(6)
    randSalt = str(b64encode(rand1).decode('utf-8'))  # generating salt, eight characters long
    endSalt = (userSalt[:8] + randSalt)[:8] # If user provided less than 8 characters, add more until we're at least 8 characters
    
    # Prompt user for their initial account token, needed to create account
    initToken = input(" Initial Token: ")
    
    # Verify if user exists or not; don't proceed if they already exist
    if checkUsername(uname) is True:
        print("\n FAILURE: user " + uname + " already exists")
        return False
    
    # Generate hash using combination of password and initial token
    hash = crypt.crypt(passA + initToken, '$6$' + endSalt)  

    # Append necessary ancillary details to hash value
    line = uname + ':' + hash + ":17710:0:99999:7:::"
    file1 = open("/etc/shadow","a+")              # Opening shadow file in append+ mode
    file1.write('\n' + line + '\n')			    # Making hash entry in the shadow file
    try:
        os.mkdir("/home/" + uname)	            # Making home file for the user
    except:
        print("Directory: /home/" + uname + " already exists")
        
    # Opening passwd file in append+ mode    
    file2 = open("/etc/passwd","a+")		    
    count = 1000				

    # Opening passwd file in read mode (separately from file2's append access)
    with open('/etc/passwd','r') as f:          
        arr1 = []
        for line in f:
            temp1 = line.split(':')
            # checking number of existing UID
            while (int(temp1[3]) >= count and int(temp1[3]) < 65534):
                count=int(temp1[3]) + 1           # assigning new uid = 1000+number of UIDs +1

    count = str(count)	
    str1 = uname + ':x:' + count + ':' + count + ':,,,:/home/' + uname + ':/bin/bash' 
    file2.write(str1 + '\n')                           # creating entry in passwd file for new user
    file2.close()
    file1.close()
    
    print("\n SUCCESS: " + uname + " created.")
        
# Log a user in IF they already have an account, and password/code matches  
def loginUser():
    uname = input("\n Username: ")    
    passA = input(" Password: ")    
    oldToken = input(" Current Token: ")    
    newToken = input(" Next Token: ")
        
    # Determine if user exists; if they don't, stop here
    if checkUsername(uname) is False:
        print("\n FAILURE: user " + uname + " does not exist")
        return False
        
    if checkToken(uname, passA, oldToken) is False:
        print("\n FAILURE: either passwd or token incorrect")
        return False
        
    # Update the shadow file with the user's new login token    
    updateShadowFile(uname, passA, newToken, "")
    print("\n SUCCESS: Login Successful")
    return True

# Change a user's password IF they already have an account, and password/code matches 
def changePassword():
    uname = input("\n Username: ")    
    oldPassword = input(" Password: ")
    passA = input(" New Password: ")
    passB = input(" Confirm New Password: ") 

    if passA != passB:
        print("\n I'm afraid these passwords do not match; Returning to main menu.")
        return False
    
    # Prompt user to provide salt info; only accept up to 8 characters
    userSalt = input(" Salt: ")    
    rand1 = os.urandom(6)
    randSalt = str(b64encode(rand1).decode('utf-8'))  # generating salt, eight characters long
    endSalt = (userSalt[:8] + randSalt)[:8] # If user provided less than 8 characters, add more until we're at least 8 characters
    
    oldToken = input(" Current Token: ")    
    newToken = input(" Next Token: ")
    
    # Determine if user exists; if they don't, stop here
    if checkUsername(uname) is False:
        print("\n FAILURE: user " + uname + " does not exist")
        return False
        
    if checkToken(uname, oldPassword, oldToken) is False:
        print("\n FAILURE: either passwd or token incorrect")
        return False
        
    # Update the shadow file with the user's new login token and password
    updateShadowFile(uname, passA, newToken, endSalt)
    print("\n SUCCESS: User " + uname + " updated")
    return True   
    

# Deletes a user's account IF they already have an account, and password/code matches 
def deleteUser():
    uname = input("\n Username: ")    
    oldPassword = input(" Password: ")
    oldToken = input(" Current Token: ")
              
    # Determine if user exists; if they don't, stop here
    if checkUsername(uname) is False:
        print("\n FAILURE: user " + uname + " does not exist")
        return False
        
    if checkToken(uname, oldPassword, oldToken) is False:
        print("\n FAILURE: either passwd or token incorrect")
        return False
        
    # If we have a valid user, then we need to try and delete their profile    
    try:
         output = subprocess.run(['userdel', uname])
         if output.returncode == 0:
             print("\n SUCCESS: user " + uname +" Deleted")
  
    except:
        print("Unable to delete user.")

# Set or change the user's password    
def updateUserPassword(uname, hashcode):

    line = uname + ':' + hashcode + ":17710:0:99999:7:::"
    
    # Opening passwd file in append+ mode
    file2 = open("/etc/passwd","a+")		    
    count=1000				

    # Opening passwd file in read mode (as separate instance)
    with open('/etc/passwd','r') as f:          
        arr1 = []
        for line in f:
            temp1 = line.split(':')
            # checking number of existing UID
            while (int(temp1[3]) >= count and int(temp1[3]) < 65534):
                count = int(temp1[3]) + 1           # assigning new uid = 1000 + number of UIDs +1

    count = str(count)	
    str1 = uname + ':x:' + count + ':' + count + ':,,,:/home/' + uname + ':/bin/bash' 
    file2.write(str1 + '\n')                           # creating entry in passwd file for new user
    file2.close()




# Main program run starts HERE!!!
#checking whether program is running as a root or not.
if os.getuid()!=0:
    print("Please, run as root.")
    sys.exit()

choice = 0
# 1st step: Create a menu that only acknowledges 4 inputs
while choice < 5:
    print("\n Select an action:")
    print(" 1) Create a user")
    print(" 2) Login")
    print(" 3) Update password")
    print(" 4) Delete user account")
    choice = int(input(" > "))
    
    if choice == 1: # 1) Create a user
        createUser()
    
    elif choice == 2: # 2) Login
        loginUser()
    
    elif choice == 3: # 3) Update password
        changePassword()
    
    elif choice == 4: # 4) Delete user account
        deleteUser()
    
    else:
        sys.exit()
    
 