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

"""
sys.path.insert(0, "./netfilterlib/")
from netfilterqueue import NetfilterQueue
sys.path.append("scapy")
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import *
"""

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
console.addFilter(SingleLevelFilter(logging.DEBUG,False))
console.setFormatter(logging.Formatter(FORMAT))
logger.addHandler(console)


# Table = ({rules:actions}, {statistics:value})
## rules = (string,list) -> ip.src, ['if','>','128.114.*.*']
# Rules = (pkt value) (conditional)
## pkt value: header field value, special value for statistics
## conditional: contains the logic, if ip.src == 128.114.62.150
# Actions = Drop, Accept, Cache, Forward

class Table:
  table = ({},[])
  def __init__(self):
    stats = {}
    ## create stats entry for the 5 NICs
    for i in xrange(0,5):
      stra = "eth"
      stats[stra+str(i)] = {}
    ## create each of the statistics to track per NIC
    for i in xrange(0,5):
      stats[stra+str(i)]['count'] = 0
      stats[stra+str(i)]['loss'] = 0
      stats[stra+str(i)]['bytes'] = 0
    ## key = pkt header
    ## value = [ conditional + action ] 
    rules = {}
    self.table = (rules,stats)

  ## create a new rule/action in the flow table
  ## -1 if the rule is already in place even if the action is different.
  def add_rule(self, key,rule,action):
    if key in self.table[0]:
      for rule_entry in self.table[0][key]:
        if rule_entry[0] == rule:
          ## same rule already in place
          return -1
      self.table[0][key].append((rule,action))
      return 0
    else:
      self.table[0][key] = [(rule,action)]
      return 0

  def update_rule(self, key, rule, action):
    if key in self.table[0]:
      for rule_entry in self.table[0][key]:
        if rule_entry[0] == rule:
          index = self.table[0][key].index(rule_entry)
          self.table[0][key][index] = (rule,action)
          return 0
      ## rule not found
      return -1
    ## key not found
    else:
      return -2
    
  def delete_rule(self, key, rule):
    if key in self.table[0]:
      for rule_entry in self.table[0][key]:
        if rule_entry[0] == rule:
          index = self.table[0][key].index(rule_entry)
          del self.table[0][key][index]
      ## rule not found
      return -1
    ## key not found
    else:
      return -2
    
  def __str__(self):
    rstr = "\nStatistics:\n"
    t = self.table
    for entry in t[1]:
      rstr += "\t"+entry+":\n"
      for value in t[1][entry]:
        rstr += "\t\t"+value+":\t"+str(t[1][entry][value])+"\n"
    rstr += "Rules:\n"
    for entry in t[0]:
      rstr += "\t"+entry+":\n"
      for value in t[0][entry]:
        rstr += "\t\t"+value[0]+":\t"+value[1]+"\n"
      
    #i = 0
    #rstr = ""
    #t = self.table
    #for entry in t:
    #  rstr += "# %s: rule: (%s)\t\taction: (%s)\n" % (i,entry[0], entry[1])
    #return rstr
    return rstr

## need to allow compound and disjoint statements such as ip == X and port == Y or port == Z


flowTable = Table()
flowTable.add_rule("ip.addr","ip.addr == 128.114.58.12","A")
logger.debug(flowTable)

#  seqnum = int(sp["TCP"].getfieldval('seq'))
#  acknum = int(sp["TCP"].getfieldval('ack'))
#  ips = (sp["IP"].getfieldval('src'),sp["IP"].getfieldval('dst'))

def match(sp):
  global flowTable
  # create a list of each key value stored in the packet that can be pulled out
  # iterate over that list and the flowTable list
  # if a header and a rule match, select it


#XXX
def openflow(pkt):
  logger.debug("Handling data packet")
  sp = IP(pkt.get_payload())
  #if match(sp):
  try:
    
    
  except Exception, e:
    logger.error("error handling packet")
    logger.error(str(e))
    logger.error(traceback.format_exc())
    pkt.accept()

"""
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
"""
