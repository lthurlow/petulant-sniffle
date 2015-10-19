import logging
import socket
import datetime
import time
import os
import threading
import pdb
import sys
import bisect
import traceback

sys.path.insert(0, "./netfilterlib/")
from netfilterqueue import NetfilterQueue
sys.path.append("scapy")
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import *

FORMAT = "[%(filename)s:%(lineno)s - %(threadName)s %(funcName)10s] %(levelname)7s %(message)s"
class SingleLevelFilter(logging.Filter):
    def __init__(self, passlevel, reject):
        self.passlevel = passlevel
        self.reject = reject

    def filter(self, record):
        if self.reject:
            return (record.levelno != self.passlevel)
        else:
            return (record.levelno == self.passlevel)

logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)

filelog = logging.FileHandler(filename='debug.out',mode='w')
filelog.setFormatter(logging.Formatter(FORMAT))
filelog.setLevel(logging.DEBUG)
logger.addHandler(filelog)

console = logging.StreamHandler(sys.__stdout__)
console.addFilter(SingleLevelFilter(logging.INFO,False))
console.setFormatter(logging.Formatter(FORMAT))
logger.addHandler(console)


# Table = [(rules),(actions)], {statistics:value}
# Rules =  (type) | (pkt value) ()
# Actions = Drop, Accept, Cache, Forward

class table:
  table = ([],{})
  def __init__():
    self.table = ([],{})
  ## create a new rule/action in the flow table
  def create_rule(self, rule,action):
    self.table[0].append((rule,action))
  ## update the statistics field in the flow table
  def update_rule(self, stat):
    k = stat[0]
    v = stat[1]
    self.table[1][k] = v
  ## string of the flow table
  def __str__(self):
    i = 0
    rstr = ""
    t = self.table
    for entry in t:
      rstr += "# %s: rule: (%s)\t\taction: (%s)\n" % (i,entry[0], entry[1])
    return rstr

flowTable = table()

def match(pkt):
  global flowTable
  for f_entry in flowTable[0]:
    if 

def openflow(pkt):
  logger.debug("Handling data packet")
  sp = IP(pkt.get_payload())
  if match(sp):
  except Exception, e:
    logger.error("error handling packet")
    logger.error(str(e))
    logger.error(traceback.format_exc())
    pkt.accept()

def print_and_accept(packet):
  print packet
  sp = IP(packet.get_payload())
  logger.debug("%s:%s -> %s:%s" % (sp[IP].src,sp[TCP].sport,sp[IP].dst,sp[TCP].dport))
  packet.accept()

def start_openflow(ilist,qname="NFQUEUE",qval=1):
  for interface in ilist:
    ## if the host is the destination (to forward above ip)
    subprocess.call("sudo iptables -I INPUT -i eth%s -j %s --queue-num %s"\
                    % (interface,qname,int(qval)))
    ## our base station should use this
    subprocess.call("sudo iptables -I FORWARD -i eth%s -j %s --queue-num %s"\
                    % (interface,qname,int(qval)))

  nfqueue = NetfilterQueue()
  nfqueue.bind(qval, openflow)
  try:
    nfqueue.run()
  except Exception,e:
    logger.error("Error in Snoop start: %s" % str(e))
  except KeyboardInterrupt:
    return

def debug():
  nfqueue = NetfilterQueue()
  #nfqueue.bind(1, print_and_accept)
  nfqueue.bind(1, openflow)
  try:
    nfqueue.run()
  except Exception,e:
    logger.error("Error in Snoop start: %s" % str(e))
    logger.error(traceback.format_exc())
  logger.info("stopped.")


debug()
