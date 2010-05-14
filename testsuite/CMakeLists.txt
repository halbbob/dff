# DFF -- An Open Source Digital Forensics Framework
# Copyright (C) 2009-2010 ArxSys
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


# unittest
ADD_TEST(modules.fs.local python local.py)
ADD_TEST(modules.parser.hash python hashtest.py)
ADD_TEST(modules.fs.fat python fattest.py)
ADD_TEST(modules.api.env.error python enverrortest.py)
ADD_TEST(modules.api.vfs.error python vfserrortest.py)
