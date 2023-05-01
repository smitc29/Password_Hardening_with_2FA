import os, subprocess
import sys
import crypt


#checking whether program is running as a root or not.
if os.getuid()!=0:
    print("Please, run as root.")
    sys.exit()

uname=input("Enter username : ")
passwd=input("Enter Password for the "+uname+" : ")

flag=0

with open('/etc/shadow','r') as fp:	
    arr=[]
    for line in fp:                                 #Enumerating through all the enteries in shadow file
        temp=line.split(':')
        if temp[0]==uname:                          #checking whether entered username exist or not
            flag=1
            print(temp)
            salt_and_pass=(temp[1].split('$'))      #retrieving salt against the user
            print(salt_and_pass)
            salt=salt_and_pass[2]
            result=crypt.crypt(passwd,'$6$'+salt)   #calculating hash via salt and password entered by user
            if result==temp[1]:                     #comparing generated salt with existing salt entry
                print("Login successful.")
            else:
                print("Invalid Password")
	
if flag==0:
	print("The user does not exist.")           #if no user exist
