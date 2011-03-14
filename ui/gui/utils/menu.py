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
#  Francois Percot <percot@gmail.com>
# 

from PyQt4.QtGui import QMenu, QIcon
from PyQt4.QtCore import SIGNAL, SLOT

from api.loader import loader

from action import Action
from ui.gui.utils.utils import Utils

class MenuRelevant(QMenu):
  def __init__(self, parent, mainWindow, node = None, selectItem = None):
       QMenu.__init__(self, mainWindow)
       self.loader = loader.loader()
       self.callbackSelected = self.selectNode
       self.parent = parent
       self.mainWindow = mainWindow
       self.node = node
       self.Load()
       actions = []
 
  def selectNode(self):
     return [self.node]

  def Load(self):   
       self.listMenuAction = []
       actions = []
       self.parent.submenuRelevant.clear()
       if self.node:      
	 modules = self.node.compatibleModules()
	 if len(modules):
	   self.parent.submenuRelevant.setEnabled(True)
	   for modname in modules:
		module = self.loader.modules[modname]
                self.parent.submenuRelevant.addAction(Action(self, self.mainWindow,  modname, module.tags, module.icon))
           for i in range(0,  len(actions)) :
              if actions[i].hasOneArg :
                self.addAction(actions[i])
           self.addSeparator()
           for i in range(0,  len(actions)) :
              if not actions[i].hasOneArg :
                self.addAction(actions[i])
           return 
       self.parent.submenuRelevant.setEnabled(False)

class MenuTags():
   def __init__(self, parent, mainWindow, selectItem = None):
       """ Init menus"""
       self.parent = parent
       self.mainWindow = mainWindow
       self.selectItem = selectItem	
       self.Load()
       self.parent.menuModule.connect(self.parent.menuModule, SIGNAL("aboutToShow()"), self.refreshQMenuModules)
 
   def Load(self):   
       self.listMenuAction = []
       setags = Utils.getSetTags()
       for tags in setags:
          if not tags == "builtins":
            self.listMenuAction.append(self.parent.menuModule.addMenu(MenuModules(self.parent, self.mainWindow, tags, self.selectItem)))
        
   def refreshQMenuModules(self):
        setags = Utils.getSetTags()
	for menu in self.listMenuAction:
	   self.parent.menuModule.removeAction(menu)
	self.Load()
   
class MenuModules(QMenu):
    def __init__(self, parent, mainWindow, tags, selectItem = None):
        QMenu.__init__(self, tags,  parent)
	self.tags = tags
        self.__mainWindow = mainWindow
        self.callbackSelected = selectItem
        self.loader = loader.loader()
        self.Load()
 
    def Load(self):
        modules = self.loader.modules
        actions = []
        for mod in modules :
	     m = modules[mod]
	     try :
	       if m.tags == self.tags:
                 actions.append(Action(self, self.__mainWindow, mod, self.tags, m.icon))
             except AttributeError, e:
		pass
        for i in range(0,  len(actions)) :
            if actions[i].hasOneArg :
                self.addAction(actions[i])
        self.addSeparator()
        for i in range(0,  len(actions)) :
            if not actions[i].hasOneArg :
                self.addAction(actions[i])
                
    def refresh(self):
        self.clear()
        self.Load()

        
