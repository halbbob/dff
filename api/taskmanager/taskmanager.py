# DFF -- An Open Source Digital Forensics Framework
# Copyright (C) 2009-2011 ArxSys
# This program is free software, distributed under the terms of
# the GNU General Public License Version 2. See the LICENSE file
# at the top of the source tree.
#  
# See http://www.digital-forensic.org for more information about this
# project. Please do not directly contact any of the maintainers of
# DFF for assistance; the project provides a web site, mailing lists
# and IRC channels for your use.
# 
# Author(s):
#  Solal J. <sja@digital-forensic.org>
#

from api.vfs.libvfs import DEventHandler
from api.taskmanager.scheduler import sched 
from api.taskmanager.processus import *
from api.env import *
from api.loader import *
from api.exceptions.libexceptions import *
import threading

class TaskManager():
  class __TaskManager(DEventHandler):
    def __init__(self):
      DEventHandler.__init__(self)
      self.loader = loader.loader()
      self.sched = sched
      self.lprocessus = []
      self.npid = 0
      self.env = env.env() 
      self.VFS = VFS.Get()
      self.VFS.connection(self)
      self.modPP = []

#ici add .......... list des post processing
#penser a pouvoir afficher une conf graphique facile etc....

    def addPostProcess(self, mod, args = None, exec_flags = None):
       self.modPP += [( mod, args, exec_flags)]

    def removePostProcess(self, mod, args = None, exec_flags = None):
       self.modPP.remove( [( mod, args, exec_flags)] )

    def createProcessNode(self, mod, args, exec_flags, node):
       #print args, exec_flags, node.absolute()
       print "Create post process"
       print node.absolute()
       print "is compatible"
       #print node.isCompatibleModule(mod)
       if node.isCompatibleModule(mod):
         if args == None:
           args = libenv.argument("post_process")
         if exec_flags == None:
           exec_flags = ["console", "thread"]
         args.add_node("file", node) #rajoute tjrs ds le meme args ....
				     #XXX manque d autre arg genre fat ce plance pas 
         self.add(mod, args, exec_flags)

    def postProcess(self, node, recursive = False):
      #print self.modPP
      for (mod, args, exec_flags) in self.modPP:
        self.createProcessNode(mod, args, exec_flags, node)
#	print node.absolute()
        if node.hasChildren():
	  childrens = node.children() 
 	  for child in childrens:
	  #for child in node.children(): #XXX fix me swig delete thread pb ou ds notre .i ...
	    self.postProcess(child, True) #ok pour le rec mais ca va d abord faire le for donc appliquer tous les differents module de post processing sur un repertoire puis sur c fils, on peut prefere appliquer un module sur tous les fils puis apres les autre module sur tout les fils pour faire ca virer le for de la fonction a recurse ...
      

    def Event(self, e):
      #print "Get event"
      #print e.value.absolute()
      self.postProcess(e.value, True) #peut etre pas ici pour le recursif mais plus ds addpostproecss?
      #XXX pusiqu on revois une list virtuel.... fo suivre les fils on peut pas lesavoir mais c comme sa donc fo faire un for ou rajouter une list ou specifier recursif au module attention au gros partage en couille quand il va avoir des modules sur le quel ca va etre reapplllliquer .............
###donc le mieux recreer une list puisque on les a pu et par contre puisqu on a les list de node ds les modules -> passer cette list au modules batch qui prenne une list directe et font juste une instance ou alors les modules prenne qu une node mais c le taskmanager qui s en occupe a l ancinne mais essayer d avoir qu une instnace c mieux (et de update ....) -> c pas pres d etre finie ..........



    def add(self, cmd, args, exec_flags):
      mod = self.loader.modules[cmd] 
      proc = None
      #XXX Processus singleton c pas top  
      if "single" in mod.flags:
         for p in self.lprocessus:
           if p.mod == mod:
	    #print "Found singleton processus"
	    proc = p
	    proc.args = args #ben ouaip si non c tjrs le meme fichier
         if not proc:
           proc = Processus(mod, self.npid, args, exec_flags)
           self.lprocessus.append(proc)
           self.npid += 1
      else:
        proc = Processus(mod, self.npid, args, exec_flags)
        self.lprocessus.append(proc)
        self.npid += 1
      if not "thread" in exec_flags:
        try :
          if "gui" in proc.mod.flags and not "console" in proc.mod.flags:
            #print "This script is gui only"
	    self.lprocessus.remove(proc)
	    proc.event.set()
	    return proc
        except AttributeError:
	    pass
      sched.enqueue(proc)
      return proc
  __instance = None

    
  def __init__(self):
    if TaskManager.__instance is None:
       TaskManager.__instance = TaskManager.__TaskManager()

  def __setattr__(self, attr, value):
	setattr(self.__instance, attr, value)

  def __getattr__(self, attr):
	return getattr(self.__instance, attr) 

  def add(self, cmd, args, exec_flags):
       return self.__instance.add(cmd, args, exec_flags)
