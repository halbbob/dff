%Module vfsitemmodel 0
%Import QtGui/QtGuimod.sip
%Import QtCore/QtCoremod.sip

%UnitCode
#include <vfsitemmodel.hpp>
%End

class VFSItemModel : QAbstractItemModel
{

 public:
     VFSItemModel();

     void 		setDirPath(Node* node);
     void 		Refresh(void);
     int 		rowCount(const QModelIndex &parent = QModelIndex());
     QVariant 		headerData(int section, Qt::Orientation orientation, int role = Qt::DisplayRole);
     QVariant 		data(const QModelIndex & index, int role = Qt::DisplayRole);
     QModelIndex 	index(int row, int column, const QModelIndex & parent = QModelIndex());
     QModelIndex 	parent(const QModelIndex & index ); 
     bool 		hasChildren (const QModelIndex & parent = QModelIndex());  
     /*private slots:*/
     /*void filterRegExpChanged();*/
     /*void filterColumnChanged();*/
     /*void sortChanged();*/
     int 		columnCount(const QModelIndex & parent = QModelIndex());
     bool thumbnails;
 
};
