# DFF -- An Open Source Digital Forensics Framework
# Copyright (C) 2011 ArxSys
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

FORMS           += ../../../ui/gui/resources/about.ui
FORMS           += ../../../ui/gui/resources/applymodule.ui
FORMS           += ../../../ui/gui/resources/bookmarkdialog.ui
FORMS           += ../../../ui/gui/resources/devicesdialog.ui
FORMS           += ../../../ui/gui/resources/errors.ui
FORMS           += ../../../ui/gui/resources/evidencedialog.ui
FORMS           += ../../../ui/gui/resources/extractdialog.ui
FORMS           += ../../../ui/gui/resources/ide.ui
FORMS           += ../../../ui/gui/resources/idewizard.ui
FORMS           += ../../../ui/gui/resources/interpreter.ui
FORMS           += ../../../ui/gui/resources/mainwindow.ui
FORMS           += ../../../ui/gui/resources/modules.ui
FORMS           += ../../../ui/gui/resources/nodebrowser.ui
FORMS           += ../../../ui/gui/resources/nodefilterbox.ui
FORMS           += ../../../ui/gui/resources/nodeviewbox.ui
FORMS           += ../../../ui/gui/resources/output.ui
FORMS           += ../../../ui/gui/resources/preferences.ui
FORMS           += ../../../ui/gui/resources/shell.ui
FORMS           += ../../../ui/gui/resources/taskmanager.ui
FORMS           += ../../../ui/gui/resources/varianttreewidget.ui

SOURCES         += ../../../ui/gui/ide/ide.py
SOURCES         += ../../../ui/gui/ide/idewizard.py
SOURCES         += ../../../api/gui/dialog/extractor.py
SOURCES         += ../../../api/gui/model/vfsitemmodel.py
SOURCES 	+= ../../../api/gui/widget/nodebrowser.py
SOURCES         += ../../../api/gui/widget/propertytable.py
SOURCES         += ../../../ui/gui/widget/taskmanager.py
SOURCES         += ../../../ui/gui/mainwindow.py
SOURCES         += ../../../ui/gui/dialog/preferences.py
SOURCES         += ../../../api/gui/box/nodeviewbox.py
SOURCES         += ../../../ui/gui/widget/preview.py

TRANSLATIONS    += ../../../ui/gui/i18n/Dff_de.ts
TRANSLATIONS    += ../../../ui/gui/i18n/Dff_en.ts
TRANSLATIONS    += ../../../ui/gui/i18n/Dff_es.ts
TRANSLATIONS    += ../../../ui/gui/i18n/Dff_fr.ts
TRANSLATIONS    += ../../../ui/gui/i18n/Dff_it.ts
TRANSLATIONS    += ../../../ui/gui/i18n/Dff_nl.ts
TRANSLATIONS    += ../../../ui/gui/i18n/Dff_zh.ts

