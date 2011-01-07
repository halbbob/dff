/* 
 * DFF -- An Open Source Digital Forensics Framework
 * Copyright (C) 2009-2011 ArxSys
 * 
 * This program is free software, distributed under the terms of
 * the GNU General Public License Version 2. See the LICENSE file
 * at the top of the source tree.
 * 
 * See http://www.digital-forensic.org for more information about this
 * project. Please do not directly contact any of the maintainers of
 * DFF for assistance; the project provides a web site, mailing lists
 * and IRC channels for your use.
 * 
 * Author(s):
 *  Christophe Malinge <cma@digital-forensic.org>
 *
 */

#ifndef __NTFSNONE_HPP__
#define __NTFSNONE_HPP__

#include "node.hpp"
#include "vfile.hpp"
#include "mftentry.hpp"
#include "attributes/data.hpp"
#include "attributes/filename.hpp"

class NtfsNode : public Node
{
public:

  NtfsNode(std::string, uint64_t, Node *, fso *, bool, AttributeFileName *,
	   AttributeStandardInformation *, MftEntry *);
  NtfsNode(std::string, uint64_t, Node *, fso *, bool, AttributeFileName *,
	   AttributeStandardInformation *, MftEntry *, uint32_t, uint64_t);
  ~NtfsNode();
  virtual void			fileMapping(FileMapping *);
  virtual void			extendedAttributes(Attributes *);
  virtual void			modifiedTime(vtime *);
  virtual void			accessedTime(vtime *);
  virtual void			changedTime(vtime *);

  void				node(Node *node) { _node = node; };
  void				contentOffset(uint64_t offset) { _contentOffset = offset; };
  void				data(AttributeData *data) { _data = data; };
  uint32_t			getMftEntry() { return _mftEntry; };

private:

  FileMapping	*_fm;
  Node		*_node;
  MftEntry	*_mft;
  AttributeData	*_data;
  uint64_t	_contentOffset;

  void		_offsetResident(FileMapping *);
  void		_offsetFromRunList(FileMapping *);
  std::pair<std::string, class Variant *>	_dataToAttr(std::string, uint32_t);
  Variant					*_dataToAttr(uint32_t);
  std::pair<std::string, class Variant *>	_dataToAttr(std::string, uint64_t);
  Variant					*_dataToAttr(uint64_t);
  std::pair<std::string, class Variant *>	_dataToVTime(std::string, uint64_t);
  std::pair<std::string, class Variant *>	_dataToAttr(std::string, uint8_t);
  std::pair<std::string, class Variant *>	_dataToAttr(std::string, uint16_t);

  std::map<std::string, class Variant *>	_headerToAttribute(Attribute *);
  void						_standardInformation(std::map<std::string, class Variant *> *, AttributeStandardInformation *);
  
  bool			_isFile;
  AttributeFileName	*_metaFileName;
  AttributeStandardInformation	*_SI;
  uint32_t	_mftEntry;
  uint64_t	_physOffset;
};

#endif
