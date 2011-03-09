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
#  Frederic B. <fba@digital-forensic.org>

from api.module.module import Module
from api.module.script import Script
from api.events.libevents import EventHandler, event
from api.types.libtypes import typeId, Argument, Parameter

from typeSelection import filetypes

import string

import time

from predef import predefPattern
from userdef import userPattern


class CarverUi(Script):
    def __init__(self):
        Script.__init__(self, "carverui")

    def start(self, args):
        pass

    def c_display(self):
        pass


class carverui(Module):
  """Search for header and footer of a selected mime-type in a node and create the corresponding file.
     You can use this modules for finding deleted data or data in slack space or in an unknown file system."""
  def __init__(self):
    Module.__init__(self, 'carverui', CarverUi)
    self.conf.addArgument({"name": "file",
                           "input": typeId.Node|Argument.Single|Argument.Required,
                           "description": "Node to search data in"})
    for mimetype in filetypes.keys():
        predefined = []
        for subtype in filetypes[mimetype].keys():
            predefined.append(subtype)
        self.conf.addArgument({"name": mimetype,
                               "input": typeId.String|Argument.List|Argument.Optional,
                               "description": "managed types",
                               "parameters": {"type": Parameter.NotEditable,
                                              "predefined": predefined}
                               })
    self.tags = "Search"
