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
#  Christophe Malinge <cma@digital-forensic.org>
# 

import sys
from PyQt4.QtCore import QDir

class Conf():
    class __Conf():
        def __init__(self):
            """ Initial configuration

            FIXME based on an ini file, args provided, etc.
            """
            self.initLanguage()

            # indexes configuration
            self.root_index = QDir.homePath() + "/.dff/indexes"
            self.index_name = "default"
            self.index_path = self.root_index + "/" + self.index_name

        def initLanguage(self):
            self.language = "en"
            
    __instance = None
    
    def __init__(self):
        if Conf.__instance is None:
            Conf.__instance = Conf.__Conf()

    def __setattr__(self, attr, value):
	setattr(self.__instance, attr, value)
  
    def __getattr__(self, attr):
	return getattr(self.__instance, attr)
    
    def setLanguage(self, lang):
        self.language = lang

    def getLanguage(self):
        return self.language

