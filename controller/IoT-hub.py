#!/usr/bin/python

import phue
import sys
import time
import os
import argparse
import socket
import IoT_control_pb2
import IoT_hub_pb2
import select
from scapy.all import *




_TEST_IP='192.168.100.1'
_TEST_PORT=14000

_TEST_IP_HUE='192.168.100.1'
_TEST_PORT_HUE=14001

_TEST_IP_ED='192.168.100.51'
_TEST_PORT_ED=14002



def server(socks):
 
  while(True):
    print "Waiting for message..."

    msg, addr = socks[0].recvfrom(1024)
    message=IoT_hub_pb2.ControlIoT()
    message.ParseFromString(msg)


    if IoT_hub_pb2.ControlIoT().CONFIGURE==message.code:
      print "[CONFIGURE] msg"
      print "Number of IoT elements: "+str(len(message.data))
      elem_nro=1
      for elem in message.data:
        print 'element ['+str(elem_nro)+'/'+str(len(message.data))+']'
        elem_nro=elem_nro+1
        print 'name: '+elem.name
        print 'type: '+elem.type
        print 'ip: '+elem.ip
        print 'port: '+elem.port
        print 'action: '+elem.action
        print 'level: '+elem.level
        print '\n'

        if elem.type == "curtain":
          print "curtains"
          if elem.action == "lower":
            print "Lowering curtains..."
            close_curtains(socks[1],(elem.ip, int(elem.port)))
          
        if elem.action == "raise":
          print "Rising curtains..."
          open_curtains(socks[1],(elem.ip, int(elem.port)))
      
        if elem.type == "light":
          print "lights..."
          if elem.action == "off":
            if elem.level == "0":
              print "Lights off..."
              turn_off_all(socks[1],(elem.ip, int(elem.port)))
            else:
              print "Lights brightness..."
              brightness_all(socks[1],(elem.ip, int(elem.port)),elem.level)

          if elem.action == 'on':
            turn_on_all(socks[1],(elem.ip, int(elem.port)))

        

def turn_on_all(sock,addr):
  address=addr
  message=IoT_control_pb2.IoTlights()
  print 'Address and port: '+str(addr)
  message.name="hub1"
  message.type="light"
  message.action="on"
  serializedMessage=message.SerializeToString()
  sock.sendto(serializedMessage, address)

def turn_off_all(sock,addr):
  print 'Address and port: '+str(addr)
  address=addr
  message=IoT_control_pb2.IoTlights()
  message.name="hub1"
  message.type="light"
  message.action="off"
  serializedMessage=message.SerializeToString()
  sock.sendto(serializedMessage, address)




def brightness_all(sock,addr,level):
  print 'Address and port: '+str(addr)
  address=addr
  message=IoT_control_pb2.IoTlights()
  message.name="hub1"
  message.type="light"
  message.action="on"
  message.brightness=int(level)
  serializedMessage=message.SerializeToString()
  sock.sendto(serializedMessage, address)


def color_all(sock,addr,color):
  print 'Address and port: '+str(addr)
  address=addr
  message=IoT_control_pb2.IoTlights()
  message.name="hub1"
  message.type="light"
  message.action="on"
  message.brightness=level
  serializedMessage=message.SerializeToString()
  sock.sendto(serializedMessage, address)

def close_curtains(sock,addr):
  print 'Address and port: '+str(addr)
  
  address=addr
  sock.sendto("close",address)

def open_curtains(sock,addr):
  
  address=addr
  sock.sendto("open",address)

def customCB(sock,args):
  print "entry CB"
  def customAct(packet):
    packet.show()
    if packet.haslayer(UDP):
      if packet[UDP].dport==12345:
        turn_on_all(sock)
      if packet[UDP].dport==12346:
        turn_off_all(sock)
  return customAct

def sniffer(args,sock):
  filter=""
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

  parser = argparse.ArgumentParser(description='Smart Conference Room Control')

  # Local listener
  parser.add_argument('--server', action='store_true', help='Server, listen incoming api_proto messages.')
  parser.add_argument('--addr',  action='store', default='192.168.100.1', help='Server IP')
  parser.add_argument('--port',  action='store', type=int, default='14001', help='Server Port')
  
  # HUE bridge
  parser.add_argument('--bridge', dest='bridgeIP', action='store', default='192.168.100.50', help='Hue Bridge IP')
  parser.add_argument('--off', action='store_true', help='Turn off lights.')
  parser.add_argument('--on', action='store_true', help='Turn on ligths.')
  parser.add_argument('--bri', type=int, help='Set brightness.')

  # Curtain control
  parser.add_argument('--curtainIP', action='store',default='192.168.100.51',help='Curtain controller')
  parser.add_argument('--curtainPort', action='store',type=int, default=14002,help='Curtain controller')
  parser.add_argument('--close', action='store_true', help='Close curtains.')
  parser.add_argument('--open', action='store_true', help='Open curtains.')


  # network sniffing
  parser.add_argument('--sniff', action='store_true', help='Sniff.')
  parser.add_argument('--iface',action='store',help="Interface to monitor")
  parser.add_argument('--mmac',action='store',help="MAC address to monitor")
  parser.add_argument('--mproto',action='store',help="Protocol to monitor")
  parser.add_argument('--mport',action='store',help="Port to monitor")
  parser.add_argument('--mpay',action='store',help="payload to monitor")

  args = parser.parse_args()
  print args


  # Two UDP sockets, 0 for listening, 1 for sending commands to hue, curtains
  try:
    socks = [socket.socket(socket.AF_INET, socket.SOCK_DGRAM), socket.socket(socket.AF_INET, socket.SOCK_DGRAM)]
    for sock in socks:
      sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
  except socket.error, msg:
    print "Failed creating socket: " + str(msg)
    for sock in socks:
      sock.close()
    exit(1)

  if args.server:
  # Bind first socket for receiving messages
    try:
      if args.addr:
        if args.port:
          socks[0].bind((args.addr, args.port))
        else:
          socks[0].bind((args.addr,_TEST_PORT))
      else:
        socks[0].bind((_TEST_ADDR,_TEST_PORT))

    except socket.error, msg:
      print "Bind failed: "+str(msg)
      for sock in socks:
        sock.close()
      sys.exit(1)
  

    try:
      server(socks)
    except KeyboardInterrupt:
      print "ctrl-c pressed, closing server..."
      for sock in socks:
        sock.close()
      sys.exit(0)

#  bridge=connect_br(args.bridgeIP)

  if args.off:
    print "Turning lights off."
    turn_off_all(socks[1])

  if args.on:
    print "Turning lights on."
    turn_on_all(socks[1])

  if args.bri:
    print "Turning brightness to: "+str(args.bri)
    brightness_all(socks[1],args.bri)


  if args.close:
    print "Closing curtains."
    close_curtains(socks[1])

  if args.open:
    print "Opening curtains."
    open_curtains(socks[1])

  if args.sniff:
    sniffer(args,sock)

  if args.server:
    try:
      server(socks)
    except KeyboardInterrupt:
      print "ctrl-c pressed, closing server..."
      for sock in socks:
        sock.close()
      sys.exit(0)

  for sock in socks:
    sock.close()
  sys.exit(0)






if __name__ == '__main__':
    main()


