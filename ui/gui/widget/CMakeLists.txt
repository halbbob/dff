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
#  Solal Jacob <sja@digital-forensic.org>

set(widget_srcs
  __init__.py
  help.py
  taskmanager.py
  modif_index.py
  SelectMimeTypes.py
  mime_types.py
  modules.py
  modulesmanager.py
  interpreter.py
  shell.py
  stdio.py
  preview.py
)

install_file(widget ${widget_srcs})
