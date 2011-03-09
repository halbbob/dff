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


from modules.search.carver.CARVER import CARVER

from api.types.libtypes import Argument, typeId, Variant

class carver(Module):
    """Search for header and footer of a selected mime-type in a node and create the corresponding file.
    You can use this modules for finding deleted data or data in slack space or in an unknown file system."""
    def __init__(self):
        Module.__init__(self, 'carver', CARVER)
        
        needle = Argument("needle", Argument.Required|Argument.Single|typeId.CArray, "represents the needle to search in the haystack")
        needle.thisown = False

        wildcard = Argument("wildcard", Argument.Required|Argument.Single|typeId.Char, "represents wildcard character used to match anything")
        wildcard.thisown = False

        size = Argument("size", Argument.Required|Argument.Single|typeId.UInt32, "size of the needle. Needed in order to take into account \0")
        size.thisown = False

        header = Argument("header", Argument.Required|Argument.Single|typeId.Argument, "represents the header, generally corresponding to the starting magic value")
        header.addSubArgument(needle)
        header.addSubArgument(wildcard)
        header.addSubArgument(size)

        footer = Argument("footer", Argument.Optional|Argument.Single|typeId.Argument, "represents the footer, generally corresponding to the ending magic value")
        footer.addSubArgument(needle)
        footer.addSubArgument(wildcard)
        footer.addSubArgument(size)

        filetype = Argument("filetype", Argument.Required|Argument.Single|typeId.String, "name of the filetype corresponding to the current pattern automaton")
        filetype.thisown = False

        window = Argument("window", Argument.Required|Argument.Single|typeId.UInt32, "maximum size to associate when no footers found or not defined")
        window.thisown = False

        aligned = Argument("aligned", Argument.Empty, "defines if headers have to be aligned to sectors")
        aligned.thisown = False

        base64 = Argument("b64", Argument.Empty, "defines if matching base64 encoded files")
        base64.thisown = False

        blksize = Argument("blksize", Argument.Optional|Argument.Single|typeId.UInt32)
        blksize.thisown = False

        pattern = Argument("pattern", Argument.Required|Argument.List|typeId.Argument, "defines a matching context for carving files. Associate a header and a footer")
        pattern.addSubArgument(filetype)
        pattern.addSubArgument(header)
        pattern.addSubArgument(footer)
        pattern.addSubArgument(window)
        pattern.addSubArgument(aligned)
        pattern.addSubArgument(base64)
        pattern.addSubArgument(blksize)
        pattern.thisown = False

        patterns = Argument("patterns", Argument.Required|Argument.List|typeId.Argument, "defines a matching context for carving files")
        patterns.thisown = False
        patterns.addSubArgument(pattern)

        self.conf.addArgument(patterns)
