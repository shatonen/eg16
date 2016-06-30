#!/usr/bin/python

import phue
import sys
import time
import os
import argparse
import socket
import IoT_control_pb2
import signal

#print(lights)


def signal_handler(signal, frame):
  print('You pressed Ctrl+C!')

  sys.exit(0)



def connect_br(bridgeIP):
  bridge = phue.Bridge(bridgeIP)
  try:
    bridge.connect()
  except Exception:
    print str(Exception)
  return bridge


def turn_on_all(lights):
  for light in lights:
    lights[light].on = True

def turn_off_all(lights):
  for light in lights:
    lights[light].on = False

def brightness_all(lights,level):
  for light in lights:
    lights[light].brightness = level

def color_all(lights,color):
  for light in lights:
    lights[light].hue = color

def get_lights(bridge):
  return bridge.get_light_objects('id')

def server(bridge,sock):
  print "Server Started..."
  lights=get_lights(bridge);
  while(True):
    print "Waiting for message..."

    msg, addr = sock.recvfrom(1024)
    message=IoT_control_pb2.IoTlights()
    message.ParseFromString(msg)

    print 'Name: ' + str(message.name)
    print 'Type: ' + str(message.type)
    print 'action: ' + str(message.action)


    if str(message.action) == "on":
      print "Turning lights ON."
      turn_on_all(lights)

    if str(message.action) == "off":
      print "Turning lights OFF."
      turn_off_all(lights)

  
    if message.brightness:

      print 'brightness: ' + str(message.brightness)
      turn_on_all(lights)
      brightness_all(lights,message.brightness)



def main():
  
  # Add signal handler
  #  signal.signal(signal.SIGINT, signal_handler)


  parser = argparse.ArgumentParser(description='Hue Bridge Control')
  parser.add_argument('--addr',  action='store', default='192.168.100.1', help='Server IP')
  parser.add_argument('--port',  action='store', type=int, default='14001', help='Server Port')

#  parser.add_argument('--brport', action='store', type=int, default='15005', help='Hue Bridge IP')
  parser.add_argument('--bridge', dest='bridgeIP', action='store', default='192.168.100.50', help='Hue Bridge IP')

#  parser.add_argument('--add', dest='action', action='store_true',  help='Action: add flow')
#
  parser.add_argument('--off', action='store_true', help='Turn off lights.')
  parser.add_argument('--on', action='store_true', help='Turn on ligths.')
  parser.add_argument('--bri', type=int, help='Set brightness.')
#  parser.add_argument('--proto', dest='proto', action='store', default='UDP', help='Protocol: ICMP/TCP/UDP.')
#  parser.add_argument('--sport', dest='srcPort', action='store', help='TCP/UDP src port.')
#  parser.add_argument('--dport', dest='dstPort', action='store', help='TCP/UDP dst port.')
#  parser.add_argument('--delete', dest='ruleId', action='store',  help='Action: delete RuleID')

  args = parser.parse_args()
#  print args

  try:
    sock=socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    sock.bind((args.addr,args.port))
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
  except socket.error, msg:
    print "Failed creating socket: " + str(msg)
    sock.close()
    exit(1)


#  bridge=connect_br(args.bridgeIP)

  if args.off:
    print "Turning lights off."
    turn_off_all(lights)

  if args.on:
    print "Turning lights on."
    turn_on_all(lights)

  if args.bri:
    print "Turning brightness to: "+str(bri)
    brightness_all(lights,args.bri)

  bridge=phue.Bridge(args.bridgeIP)		 	
  bridge.connect()
#  try:
#    print "Connecting Hue bridge.."
#print "Fake bridge connected"

#    bridge=connect_br(args.bridgeIP)
#bridge="fake"
#  except Exception as e:
#    print "Connecting to bridge failed: "+str(e)
#    sock.close()
#    sys.exit(1)

  try:
    print "Starting server..."
    server(bridge,sock)
  except Exception as e:
    print str(e)

  except KeyboardInterrupt:
    print "ctrl-c pressed."
    pass
  finally:
    print "Closing server..."
    sock.close()
    sys.exit(0)

#    print "Adding flows..."
#    if not args.srcAddr or not args.dstAddr:
#      print "Missing source or destination!"
#      sys.exit(1)
#
#    # Add ARP between hosts
#    if args.arp:
#      command1 = "curl -X POST -d '{"
#      command2 = "curl -X POST -d '{"
##
#      command1 += ("\"src-ip\":\"%s/32\"," % (args.srcAddr))
#      command2 += ("\"dst-ip\":\"%s/32\"," % (args.srcAddr))
#
#      command1+= ("\"dst-ip\":\"%s/32\"," % (args.dstAddr))
#      command2 +=("\"src-ip\":\"%s/32\"," % (args.dstAddr))






if __name__ == '__main__':
    main()


