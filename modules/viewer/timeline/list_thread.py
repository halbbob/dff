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

from PyQt4.QtCore import QString, QThread, SIGNAL

from datetime import datetime
from api.types.libtypes import vtime, typeId

class DataThread(QThread):
    def __init__(self, parent, callback):
        QThread.__init__(self)
        self.timeline = parent
        self.configuration = None
        self.node = None
        self.count = 0
        parent.connect(self, SIGNAL("finished()"), callback)

    def insert(self, data, node, root, dateLimits):
        ''' List insert using dichotomy

        There is two lists, one for ordered dates, and one other for
        corresponding nodes. If several nodes have the same timestamp, they are
        registered in the same list entry in an array.
        '''
        data = self.timeline.toUSec(datetime(data.year, data.month, data.day, data.hour, data.minute, data.second, data.usecond))

        if not root['dates']:
            root['dates'] = [data]
            root['nodes'] = [[node.this]]
            dateLimits[0] = data
            dateLimits[1] = data
        else:
            iMin, iMax = 0, len(root['dates']) - 1
            iCurrent = iMax / 2
            while iMin != iMax or not iMax:
                if data == root['dates'][iCurrent]:
                    root['nodes'][iCurrent].append(node.this)
                    break
                elif data > root['dates'][iCurrent] and iCurrent == len(root['dates']) - 1:
                    root['dates'].append(data)
                    root['nodes'].append([node.this])
                    dateLimits[1] = data
                    break
                elif data > root['dates'][iCurrent] and data < root['dates'][iCurrent + 1]:
                    root['dates'].insert(iCurrent + 1, data)
                    root['nodes'].insert(iCurrent + 1, [node.this])
                    break
                elif data < root['dates'][iCurrent] and not iCurrent:
                    root['dates'].insert(0, data)
                    root['nodes'].insert(0, [node.this])
                    dateLimits[0] = data
                    break
                elif data < root['dates'][iCurrent] and data > root['dates'][iCurrent - 1]:
                    root['dates'].insert(iCurrent, data)
                    root['nodes'].insert(iCurrent, [node.this])
                    break
                elif data > root['dates'][iCurrent]:
                    iMin = iCurrent
                    iCurrent = iCurrent + ((iMax - iCurrent) / 2)
                    if iCurrent == iMin:
                        iCurrent += 1
                elif data < root['dates'][iCurrent]:
                    iMax = iCurrent
                    iCurrent = iMin + ((iCurrent - iMin) / 2)

        return root, dateLimits


    def addNode(self, node):
        """
        TODO Make it work for VList !
        Especially take care of VMap embeded in VList.
        Also see compute_thread.CountThread.attrRecCount.
        """
        nodeList = node.children()
        for oneNode in nodeList:
          countMe = False
          attr = oneNode.attributes()
          for family in self.configuration:
            if family[0] and family[1]:
              # module name is family[0]
              for time in family[1]:
                try:
                  a = attr[family[0]].value()
                  for k in time[0]:
                    try:
                      a = a[k]
                    except IndexError:
                      break
                    except TypeError:
                      break
                    if a.type() == typeId.VTime:
                      time[1][5][1], time[1][6][1] = self.insert(a.value(), oneNode, time[1][5][1], time[1][6][1])
                      countMe = True
                      v = a.value()
                      break
                    else:
                      a = a.value()
                except IndexError:
                  pass

          if countMe:
            self.count += 1
            if not self.count % 100:
                # XXX % 100 realy improve speed ?
                percent = (self.count * 100) / self.timeline.nodeCount
                self.timeline.setStateInfo(str(percent) + "% registering nodes dates")


    def populate(self, node):
        if node.hasChildren():
          self.addNode(node)
        nodeList = node.children()
        for oneNode in nodeList:
          if oneNode.hasChildren():
            self.populate(oneNode)


    def run(self):
      self.timeline.setStateInfo('Registering nodes dates')
      self.configuration = self.timeline.options.configuration
      self.node = self.timeline.node
      self.populate(self.node)
      self.timeline.setStateInfo('Done - ' + str(self.timeline.timesCount) + ' dates from ' + str(self.timeline.nodeCount) + ' nodes registered')

      
    def dump(self, root, dateLimits):
        current = root
        print "min:", dateLimits[0], dateLimits[0].usec, "max:", dateLimits[1], dateLimits[1].usec
        while current:
            print len(current.nodeArray), " ", current.data, current.data.usec
            current = current.next

class Element():
    def __init__(self, data, node):
        """
        nodeArray stores nodes of same date
        nodeNames stores names of nodes stored
        """
        self.prev = None
        self.next = None
        self.nodeArray = []
        self.nodeNames = []

        self.data = data
        self.nodeArray.append(node.this)
#        self.nodeNames.append(node.absolute())

    def addNode(self, node):
        """ Add a node in both array (data + names).
        If multiple node have same date we store it in one Element
        """
        self.nodeArray.append(node)
        self.nodeNames.append(node.absolute())

    def getNodesNames(self, origPath = ''):
        """ Return node names contained in this element, one per line,
        if origPath is provided we clear it from the begining of node name
        """
        outString = ''
        for oneName in self.nodeNames:
            outString += oneName[len(origPath):] + '\n'
        return outString

    def getSize(self):
        return len(self.nodeArray)

    def elementsInRange(self, min, max, root):
        if not min or not max:
          return 0
        current = root
        while current.prev:
          current = current.prev
        nodesCount = 0
        while current:
            if current.data >= min and current.data < max:
                nodesCount += len(current.nodeArray)
            current = current.next
        return nodesCount
                
    def elementsInRangeToString(self, min, max, root, origPath = ''):
        current = root
        nodesNames = None
        while current:
            if current.data >= min and current.data < max:
                if nodesNames:
                    nodesNames += current.getNodesNames(origPath)
                else:
                    nodesNames = current.getNodesNames(origPath)
            current = current.next
        return nodesNames

    def elementsInRangeToNodesArray(self, min, max, root, origPath = ''):
        current = root
        while current.prev:
          current = current.prev
        nodes = []
        while current:
            if current.data >= min and current.data < max:
                nodes.append(current)
            current = current.next
        return nodes
