#!/usr/bin/python

import mraa
import sys
import time
import os
import argparse
import socket
import signal


# Initialize pins
P1 = mraa.Gpio(3)                          
P2 = mraa.Gpio(5)                          
P3 = mraa.Gpio(6)                          
P4 = mraa.Gpio(9)                          
                                 
                                           
P1.dir(mraa.DIR_OUT)                       
P2.dir(mraa.DIR_OUT)                       
P3.dir(mraa.DIR_OUT)                       
P4.dir(mraa.DIR_OUT)          

# Set speed to 0.01 s
sleep = 0.01



def full_drive(steps):           
  print "Full drive: "+str(steps)+" Sleep: "+str(sleep)	                                 
	
  for i in range(1,steps): 
    P4.write(0)      
    P2.write(1)      
    time.sleep(sleep)
                                                                             
    P1.write(0)      
    P3.write(1)      
    time.sleep(sleep)
                                       
    P2.write(0)      	                
    P4.write(1)      
    time.sleep(sleep)
                                       
    P3.write(0)      
    P1.write(1)      
    time.sleep(sleep)
  pins_clear()	                                 

def full_drive_acw(steps):       
  print "Full drive ACW: "+str(steps)	                                 

                                 
  for i in range(1,steps): 
    P2.write(0)      
    P4.write(1)      
    time.sleep(sleep)
                                   
    P1.write(0)      
    P3.write(1)      
    time.sleep(sleep)
                                   
    P4.write(0)      
    P2.write(1)      
    time.sleep(sleep)
                                   
    P3.write(0)      
    P1.write(1)      
    time.sleep(sleep)

  pins_clear()


def close_curtains():
  full_drive_acw(700)

def open_curtains():
  full_drive(700)

def pins_clear():

        P1.write(0)        
        P2.write(0)        
        P3.write(0)              
        P4.write(0)    

def server(sock):
  print "Server Started..."
  while(True):
    print "Waiting for message..."

    msg, addr = sock.recvfrom(1024)

    print "Command from: "+str(addr)+" was:" + msg

    if "open" in msg:
      print "Opening curtains..."
      open_curtains()

    if "close" in msg:
      print "Closing curtains..."
      close_curtains()

  

def main():
  

  parser = argparse.ArgumentParser(description='Curtain Control')
  parser.add_argument('--addr',  action='store', default='192.168.100.51', help='Server IP')
  parser.add_argument('--port',  action='store', type=int, default='14002', help='Server Port')

  parser.add_argument('--close', action='store_true', help='Close curtains.')
  parser.add_argument('--open', action='store_true', help='Open curtains.')

  args = parser.parse_args()

  try:
    sock=socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    sock.bind((args.addr,args.port))
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
  except socket.error, msg:
    print "Failed creating socket: " + str(msg)
    sock.close()
    exit(1)



  if args.close:
    print "Closing curtains."
    close_curtains()

  if args.open:
    print "Opening curtains."
    open_curtains()

  try:
    print "Starting server..."
    server(sock)
  except Exception as e:
    print str(e)

  except KeyboardInterrupt:
    print "ctrl-c pressed."
    pass
  finally:
    print "Closing server..."
    pins_clear()
    sock.close()
    sys.exit(0)


if __name__ == '__main__':
    main()

