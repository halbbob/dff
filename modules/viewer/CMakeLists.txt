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
#  Frederic Baguelin <fba@digital-forensic.org>

add_subdirectory(hexedit)
add_subdirectory(bindiff)
add_subdirectory(timeline)
add_subdirectory(web)

set(viewer_srcs
  __init__.py
  cat.py
  viewerimage.py
  player.py
)

install_file(viewer ${viewer_srcs})
