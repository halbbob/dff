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
#  Solal Jacob <sja@digital-forensic.org>


# compiled

add_subdirectory (exceptions)
add_subdirectory (events)
add_subdirectory (loader)
add_subdirectory (module)
add_subdirectory (types)
add_subdirectory (vfs)
add_subdirectory (search)
add_subdirectory (filters)
if (ENABLE_INDEXER)
   add_subdirectory (index)
endif (ENABLE_INDEXER)
add_subdirectory (tree)
add_subdirectory (magic)
# python only
add_subdirectory (taskmanager)
add_subdirectory (manager)
add_subdirectory (datatype)
add_subdirectory (gui)
add_subdirectory (devices)
add_subdirectory (apswvfs)

#### Deploying python __init__ script
set(api_srcs
  __init__.py
)

install_file(api ${api_srcs})
