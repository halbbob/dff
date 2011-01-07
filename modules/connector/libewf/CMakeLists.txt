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
#	How to build libewf dlls for Windows
# Download http://zlib.net/zlib125.zip
# Download http://ovh.dl.sourceforge.net/project/libewf/libewf2-alpha/libewf-alpha-20110104/libewf-alpha-20110104.tar.gz
# Extract libewf-alpha-20110104.tar.gz  to libewf-20110104
# Extract zlib125.zipzlib125.zip to libewf-20110104\msvscpp
# Build libewf-20110104\msvscpp\libewf.sln (Release)
# Copy
#   - libewf-20110104\msvscpp\Release\zlib.dl
#   - libewf-20110104\msvscpp\Release\libewf.dll
# To modules\connector\libewf (here)
#

if (UNIX AND NOT WIN32)
	set(libewf_srcs
		ewf.py
	)
else (UNIX AND NOT WIN32)
	set(libewf_srcs
		ewf.py
		libewf.dll
		zlib.dll
	)
endif (UNIX AND NOT WIN32)

install_file(libewf ${libewf_srcs})
