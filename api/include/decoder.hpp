/*
 * DFF -- An Open Source Digital Forensics Framework
 * Copyright (C) 2009-2011 ArxSys
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
 *  Frederic Baguelin <fba@digital-forensic.org>
 */

#ifndef __DECODER_HPP__
#define __DECODER_HPP__

// #include "variant.hpp"
// #include "export.hpp"
// #include <vector>

// /*
// TODO:
// + Hypothetic:
//    - It could be interesting to add a type flag in order to create categories of
//      decoder for UI views and for automatic application of preselected types

// + Further release:
// */

// typedef struct
// {
//   class Node*	from;
//   uint64_t	start;
//   uint64_t	end;
// }		chunck;

// class FileMapping
// {
// private:
//   uint64_t		current;
//   std::vector<chunck *>	chuncks;
// public:
//   FileMapping();
//   ~FileMapping();
//   chunck*		getNextChunck();
//   chunck*		getPrevChunck();
//   std::vector<chunck *>	getChuncks();
//   void			push(class Node* from, uint64_t start, uint64_t end);
// };

// class Attributes
// {
// private:
//   std::map<std::string, class Variant*>	*attrs;
// public:
//   Attributes();
//   ~Attributes();
//   void					push(std::string key, class Variant *value);
//   std::list<std::string>		getKeys();
//   Variant*				getValue(std::string key);
//   std::map<std::string, class Variant*>	*get();	  
// };

// class Metadata
// {
// public:
//   Metadata(){}
//   virtual				~Metadata(){}
//   //EXPORT std::string				getName();
//   //  virtual uint32_t				getNeededSize() = 0;
//   //  Implementation de ces methodes plus tard
//   //  Pour le moment, gerer le getAttributes
//   //  virtual bool				isRelevant(class VFile *vfile, uint64_t offset) = 0;
//   //  virtual bool				isRelevant(uint8_t *buffer) = 0;

//   //unsigned char				*getMagic();
//   virtual class FileMapping*			getFileMapping(class Node* node) = 0;
//   virtual class Attributes*			getAttributes(class Node* node) = 0;
//   //virtual uint64_t				getNextChunckOffset(uint64_t current) = 0;
//   //virtual uint64_t				getBlockSize() = 0;
//   //virtual uint64_t				getSize(class Node* node) = 0;
//   //Variant*					getValue(std::string key);
//   //virtual Variant*				isRelevant(class VFile* vfile, uint64_t offset) = 0;
//   //virtual bool				isRelevant(class Node* node) = 0;
//   //virtual Variant*		getAttributes(class VFile* vfile, uint64_t offset) = 0;
//   //virtual Variant*		getAttributes();
//   //virtual Variant*		getAttributes() = 0;
//   //std::list<std::string>	getKeys();
// };


// // class FsMetadata
// // {
// // public:
// //   virtual uint64_t		getBlockCount() = 0;
// //   map<string, DVariant*>	getBase();
// //   virtual bool			isDir() = 0;
// //   virtual bool			isFile() = 0;
// //   virtual bool			isLink() = 0;
// //   virtual map<string, vtime*>	getMACTimes() = 0;
// //   virtual vtime*		getModifiedTime() = 0;
// //   virtual vtime*		getAccessedTime() = 0;
// //   virtual vtime*		getCreatedTime() = 0;
// //   virtual string*		getOwners();
// //   virtual DVariant		getUid();
// //   virtual DVariant		getGid() = 0;
// //   virtual DVariant		getPermissions() = 0;
// //   virtual bool			isReadable(string who) = 0;
// //   virtual bool			isWritable(string who) = 0;
// //   virtual bool			isExecutable(string who) = 0;
// // };

#endif
