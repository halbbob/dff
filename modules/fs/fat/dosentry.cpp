/*
 * DFF -- An Open Source Digital Forensics Framework
 * Copyright (C) 2009-2010 ArxSys
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

#include "dosentry.hpp"

dosEntry::dosEntry()
{
}

dosEntry::~dosEntry()
{
}

bool		dosEntry::sanitizeEntry(dectx* ctx)
{
}

dectx*		dosEntry::createDentryCtx(Node* n)
{
  VFile*	vfile;
  dosentry*	dentry;
  dectx*	ctx;

  try
    {
      dentry = new dosentry;
      vfile = n->open();
      vfile->seek(n->getOffset());
      if (vfile->read(dentry, sizeof(dosentry)) != sizeof(dosentry))
	return NULL;
      ctx = new dectx;
      memcpy(ctx->name, dentry->name, 8);
      memcpy(ctx->ext, dentry->ext, 3);
      ctx->attrib = dentry->attrib;
      ctx->lowercase = dentry->lowercase;
      ctx->ctimeten = dentry->ctimeten;       /* create times */
      ctx->ctime = *((uint16_t*)dentry->ctime);
      ctx->cdate = *((uint16_t*)dentry->cdate);
      ctx->adate = *((uint16_t*)dentry->adate);/* access time */
      ctx->highclust = *((uint16_t*)dentry->highclust);
      ctx->wtime = *((uint16_t*)dentry->wtime);       /* last write time */
      ctx->wdate = *((uint16_t*)dentry->wdate);
      ctx->startclust = *((uint16_t*)dentry->startclust);
      ctx->size = *((uint32_t*)dentry->size);
      delete dentry;
      return (ctx);
    }
  catch(vfsError e)
    {
      throw ("Fat module: dosEntry::isRelevant cannot open node" + e.error);
    }  
}

FileMapping*	dosEntry::getFileMapping(class Node* node)
{
}

Attributes*	dosEntry::getAttributes(Node *n)
{
  Attributes*	attr;

  attr = new Attributes();
  return attr;

//   ctx = this->createDentryCtx(n);
//   if (this->sanitizeEntry(ctx))
//     return new Variant();
}
