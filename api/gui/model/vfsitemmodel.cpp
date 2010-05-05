#include <QtGui>
#include <vfsitemmodel.hpp>


VFSItemModel::VFSItemModel()
{
  VFS& vfs = VFS::Get();
  thumbnails = false;
//XXX
//  vfs.set_callback("refresh_tree", this->refresh)l;
}

void VFSItemModel::Refresh(void)
{
//XXX
//   this->emit(layoutChanged());
}

void VFSItemModel::setDirPath(Node *node)
{
  Node* rootItem = node;
  this->reset();
}

int  VFSItemModel::rowCount(const QModelIndex &parent)
{
	//if not parent.isValid():
	//parentItem = this->rootItem;
	//else:
	//parentItem = parent.internalPointer();
	//return parentItem.next.size();
}


QVariant headerData(int section, Qt::Orientation orientation, int role = Qt::DisplayRole)
{
	//if role != Qt.DisplayRole:
	//return QVariant();
	//if orientation == Qt.Horizontal:
	//if section == HNAME:
	//return QVariant('Name');
	//if section == HSIZE:
	//return QVariant('Size');
	//if section == HACCESSED:
	//return QVariant('Accessed time');
	//if section == HCHANGED:
	//return QVariant('Changed time');
	//if section == HMODIFIED:
	//return QVariant('Modified time');
	//if section == HMODULE:
	//return QVariant('Module');
}

QVariant data(const QModelIndex & index, int role = Qt::DisplayRole)
{
	//if not index.isValid():
	//return QVariant(); 
	//node = index.internalPointer();
	//column = index.column();
	//if role == Qt.DisplayRole :
	//if column == HNAME:
	//return QVariant(node.name);
	//if column == HSIZE:
	//return QVariant(node.attr.size);
	//time = node.attr.time;
	//try :
	//if column == HACCESSED:
	//return QVariant(QDateTime(time['accessed'].get_time()));
	//if column == HCHANGED:
	//return QVariant(QDateTime(time['changed'].get_time()));
	//if column == HMODIFIED:
	//return QVariant(QDateTime(time['modified'].get_time()));
	//except IndexError:
	//pass
	//if column == HMODULE:
	//return QVariant(node.fsobj.name)
	//if role == Qt.TextColorRole:
	//if column == 0:
	//if node.attr.deleted:
	//return  QVariant(QColor(Qt.red))
	//if role == Qt.DecorationRole:
	//if column == HNAME:
	//if node.next.empty():
	//if self.thumbnails:
	//icon = self.createThumbnails(node)
	//if icon:
	//return QVariant(QIcon(icon))
	//return QVariant(QIcon(":folder_empty_128.png"))
	//else:
	//if node.attr.size != 0: 
	//return QVariant(QIcon(":folder_documents_128.png"))
	//else:
	//return QVariant(QIcon(":folder_128.png"))
	//return QVariant() 
}


int VFSItemModel::columnCount(const QModelIndex & parent)
{
     return 6; 
}


QModelIndex  VFSItemModel::index(int row, int column, const QModelIndex & parent)
{
	//if not self.hasIndex(row, column, parent):
	//return QModelIndex()
	//
	//if parent.isValid():
	//parentItem = parent.internalPointer()
	//else:
	//parentItem = self.rootItem 
	//childItem = parentItem.next[row]
	//
	//try :
	//childItem, row = self.map[childItem.absolute()]
	//except KeyError:
	//self.map[childItem.absolute()] = (childItem, row)
	//
	//index = self.createIndex(row, column, childItem)
	//return index
}


QModelIndex 	VFSItemModel::parent(const QModelIndex & index)
{
	//if not index.isValid(): 
	//return QModelIndex()
	//childItem = index.internalPointer()
	//parentItem = childItem.parent
	// 
	//if parentItem.absolute() == self.rootItem.absolute():
	//return QModelIndex()
	//
	//parentItem, n = self.map[parentItem.absolute()]
	//index = self.createIndex(n , 0, parentItem)
	//return index
}

bool hasChildren (const QModelIndex & parent)  
{
	//if not parent.isValid():
	//self.parentItem = self.rootItem
	//return not self.rootItem.empty_child()
	//else:
	//self.parentItem = parent.internalPointer()
	//return not self.parentItem.empty_child()
}

