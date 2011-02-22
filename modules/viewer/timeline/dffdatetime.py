# DFF -- An Open Source Digital Forensics Framework
# Copyright (C) 2009-2011 ArxSys
# 
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

from datetime import datetime
from PyQt4.QtCore import QDateTime

class DffDatetime(datetime):
    """Inherit from datetime, add micro second value,
    providing powerfull computation.
    """
    usec = 0
    
    def __init__(self, *args):
        datetime.__init__(args)
        self.usec = self.toordinal() * 86400 * 1000000 + self.hour * 3600 * 1000000 + self.minute * 60 * 1000000 + self.second * 1000000 + self.microsecond

#    def usec(self):
# Avoid impossible datetime computation like division
#  return number of microsecond of this datetime
#     pass

    def toQDateTime(self):
        """Returns a QDateTime object usable by PyQt4
        """
        # XXX what about microsecond display ?!??
        return QDateTime(self.year, self.month, self.day, self.hour, self.minute, self.second)


if __name__ == "__main__":
    import doctest
    doctest.testfile("dffdatetime.txt")
