#!/usr/bin/python

import phue
import sys
import time
import os
import argparse
import socket
import IoT_control_pb2
import IoT_hub_pb2
import subprocess

from scapy.all import *


_TEST_IP_HUE='192.168.100.1'
_TEST_PORT_HUE=14001

_TEST_IP_ED='192.168.100.51'
_TEST_PORT_ED=14002

_casting=0

def start_cast(sock, address):
   message = IoT_hub_pb2.ControlIoT()
   message.code=IoT_hub_pb2.ControlIoT().CONFIGURE

   #Add first array element
   iot_elem=message.data.add()
   iot_elem.name='lights1'
   iot_elem.type='light'
   iot_elem.ip=_TEST_IP_HUE
   iot_elem.port=str(_TEST_PORT_HUE)
   iot_elem.action='off'
   iot_elem.level='0'

   #Add second array element
   iot_elem=message.data.add()
   iot_elem.name='curtains1'
   iot_elem.type='curtain'
   iot_elem.ip=_TEST_IP_ED
   iot_elem.port=str(_TEST_PORT_ED)
   iot_elem.action='lower'
   iot_elem.level='100'

   print 'message: '+str(message)

   serializedMessage=message.SerializeToString()
   sock.sendto(serializedMessage, address)

def stop_cast(sock, address):
   message = IoT_hub_pb2.ControlIoT()
   message.code=IoT_hub_pb2.ControlIoT().CONFIGURE

   #Add first array element
   iot_elem=message.data.add()
   iot_elem.name='lights1'
   iot_elem.type='light'
   iot_elem.ip=_TEST_IP_HUE
   iot_elem.port=str(_TEST_PORT_HUE)
   iot_elem.action='on'
   iot_elem.level='100'

   #Add second array element
   iot_elem=message.data.add()
   iot_elem.name='curtains1'
   iot_elem.type='curtain'
   iot_elem.ip=_TEST_IP_ED
   iot_elem.port=str(_TEST_PORT_ED)
   iot_elem.action='raise'
   iot_elem.level='100'

   print 'message: '+str(message)

   serializedMessage=message.SerializeToString()
   sock.sendto(serializedMessage, address)


def turn_on_all(sock):
  address=(_TEST_IP_HUE, _TEST_PORT_HUE)
  message=IoT_control_pb2.IoTlights()
  message.name="hub1"
  message.type="light"
  message.action="on"
  serializedMessage=message.SerializeToString()
  sock.sendto(serializedMessage, address)

def turn_off_all(sock):
  address=(_TEST_IP_HUE, _TEST_PORT_HUE)
  message=IoT_control_pb2.IoTlights()
  message.name="hub1"
  message.type="light"
  message.action="off"
  serializedMessage=message.SerializeToString()
  sock.sendto(serializedMessage, address)




def brightness_all(sock,level):
  address=(_TEST_IP_HUE, _TEST_PORT_HUE)
  message=IoT_control_pb2.IoTlights()
  message.name="hub1"
  message.type="light"
  message.action="on"
  message.brightness=level
  serializedMessage=message.SerializeToString()
  sock.sendto(serializedMessage, address)


def color_all(sock,color):
  address=(_TEST_IP_HUE, _TEST_PORT_HUE)
  message=IoT_control_pb2.IoTlights()
  message.name="hub1"
  message.type="light"
  message.action="on"
  message.brightness=level
  serializedMessage=message.SerializeToString()
  sock.sendto(serializedMessage, address)

def close_curtains(sock):
  
  address=(_TEST_IP_ED, _TEST_PORT_ED)
  sock.sendto("close",address)

def open_curtains(sock):
  
  address=(_TEST_IP_ED, _TEST_PORT_ED)
  sock.sendto("open",address)

# Simple and stupid Googlecast detection
# Chromecast assumed to be at 192.168.100.129

def ccastCB(sock,args):
  print "Chromecast CB"
  _casting=0
  casters={}

  def ccastAct(packet):
    global _casting
    if packet.haslayer(UDP):
      if packet[IP].ttl == 1:
        payload = packet.getlayer(Raw)
        print "TTL 1 detected..."
        if "google" in str(payload):
          print "Chromecast search detected!"
          print "Allowing basic communications..."

          if not packet[IP].src in casters:
            casters[packet[IP].src]=[packet[Ether].src,0,0]

      if packet[IP].src in casters and packet[IP].dst == "192.168.100.129" and packet.haslayer(UDP):
        if _casting == 0:

          if packet[IP].src in casters:

            # Detect if packet is from a previous stream
            if packet[UDP].sport == casters[packet[IP].src][1] and packet[UDP].dport == casters[packet[IP].src][2]:
              print "Old stream! Ignoring..."

            else:

              casters[packet[IP].src]=[packet[Ether].src,packet[UDP].sport,packet[UDP].dport]

              print casters

              print "UDP Stream to Chromecast detected!"
              print "Closing curtains and dimming lights!"
              start_cast(sock, (args.addr, args.port))
              #close_curtains(sock)
              #turn_off_all(sock)
              _casting = 1
      
    if _casting == 1 and packet.haslayer(TCP) and packet[IP].dst == "192.168.100.129":
      payload = packet.getlayer(Raw)
      if "GET /setup/eureka_info" in str(payload):
        print "Casting ended."
        _casting = 0
        stop_cast(sock,(args.addr, args.port))
        #open_curtains(sock)
        #turn_on_all(sock)
        

  return ccastAct



def customCB(sock,args):
  print "entry CB"
  def customAct(packet):
    packet.show()

    payload = packet.getlayer(Raw)

    if "args.mpay" in payload:
      print "Detected payload: " + str(payload)

  return customAct

def sniffer(args,sock):
  filter="ip"
  if args.ccast:
    filter="ip"
    sniff(iface=args.iface,filter=filter,prn=ccastCB(sock,args))
  else:
    if args.mmac:
      if len(filter)!=0:
         filter=filter + " and "
      filter=filter+"args.mmac"
    if args.mproto:
      if len(filter)!=0:
        filter=filter + " and "
      filter=filter+" "+args.mproto
    if args.mport:
      if len(filter)!=0:
        filter=filter + " and "
      filter=filter+" port "+str(args.mport)
    if args.mpay:
      if len(filter)!=0:
        filter=filter + " and "
      filter=filter+" "+args.pay


    print filter
    sniff(iface=args.iface,filter=filter,prn=customCB(sock,args))


def main():
  

  parser = argparse.ArgumentParser(description='Network sniffer')
  parser.add_argument('--addr',  action='store', default='192.168.100.1', help='IoT controller IP')
  parser.add_argument('--port',  action='store', type=int, default='14001', help='IoT controller port')

  parser.add_argument('--bridge', dest='bridgeIP', action='store', default='192.168.100.50', help='Hue Bridge IP')

  parser.add_argument('--off', action='store_true', help='Turn off lights.')
  parser.add_argument('--on', action='store_true', help='Turn on ligths.')

  parser.add_argument('--bri', type=int, help='Set brightness.')

  parser.add_argument('--close', action='store_true', help='Close curtains.')
  parser.add_argument('--open', action='store_true', help='Open curtains.')


  parser.add_argument('--sniff', action='store_true', help='Sniff.')
  parser.add_argument('--iface',action='store',help="Interface to monitor")
  parser.add_argument('--mmac',action='store',help="MAC address to monitor")
  parser.add_argument('--mproto',action='store',help="Protocol to monitor")
  parser.add_argument('--mport',action='store',help="Port to monitor")
  parser.add_argument('--mpay',action='store',help="payload to monitor")
  parser.add_argument('--ccast',action='store_true',help="Detect Chromecast")

  args = parser.parse_args()
  print args


  # UDP socket for sending commands to hue, curtains
  try:
    sock=socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
  except socket.error, msg:
    print "Failed creating socket: " + str(msg)
    sock.close()
    exit(1)


  #start_cast(sock,(args.addr,args.port))
  #time.sleep(5)
  #stop_cast(sock,(args.addr,args.port))
  if args.off:
    print "Turning lights off."
    turn_off_all(sock)

  if args.on:
    print "Turning lights on."
    turn_on_all(sock)

  if args.bri:
    print "Turning brightness to: "+str(args.bri)
    brightness_all(sock,args.bri)


  if args.close:
    print "Closing curtains."
    close_curtains(sock)

  if args.open:
    print "Opening curtains."
    open_curtains(sock)

  if args.sniff:
    sniffer(args,sock)

  sock.close()
  sys.exit(0)






if __name__ == '__main__':
    main()


