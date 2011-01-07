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
#  Solal Jacob <sja@digital-forensic.org>
#  Christophe Malinge <cma@digital-forensic.org>

# BASH / UNIX commands to check for files with translatable strings :
# echo $(grep -R 'QApplication.translate(' * | grep '.py:' | grep -v '.sh:' | cut -d ':' -f 1 | sort | uniq | sed 's/^\(.*\)$/${CMAKE_HOME_DIRECTORY}\/\1/')

# FIXME :
#  - Dynamic specification of available languages in configuration

# please keep the list of supported languages sorted alphabetically
set(DFF_SUPPORTED_LANGUAGES "en" "es" "fr")

set(TRANSLATABLE_STRINGS_IN_FILES ${CMAKE_HOME_DIRECTORY}/api/gui/button/pushbutton.py ${CMAKE_HOME_DIRECTORY}/api/gui/dialog/applymodule.py ${CMAKE_HOME_DIRECTORY}/api/gui/dialog/extractor.py ${CMAKE_HOME_DIRECTORY}/api/gui/dialog/property.py ${CMAKE_HOME_DIRECTORY}/api/gui/dialog/uiapplymodule.py ${CMAKE_HOME_DIRECTORY}/api/gui/dialog/uiproperty.py ${CMAKE_HOME_DIRECTORY}/api/gui/dialog/uiselectnodes.py ${CMAKE_HOME_DIRECTORY}/api/gui/widget/applymoduletable.py ${CMAKE_HOME_DIRECTORY}/modules/viewer/hexedit/bookmark.py ${CMAKE_HOME_DIRECTORY}/modules/viewer/hexedit/decodeValues.py ${CMAKE_HOME_DIRECTORY}/modules/viewer/hexedit/navigation.py ${CMAKE_HOME_DIRECTORY}/ui/gui/configuration/_configure.py ${CMAKE_HOME_DIRECTORY}/ui/gui/configuration/configure.py ${CMAKE_HOME_DIRECTORY}/ui/gui/ide/actions.py ${CMAKE_HOME_DIRECTORY}/ui/gui/ide/dockide.py ${CMAKE_HOME_DIRECTORY}/ui/gui/ide/ide.py ${CMAKE_HOME_DIRECTORY}/ui/gui/ide/idewizardpages.py ${CMAKE_HOME_DIRECTORY}/ui/gui/widget/info.py ${CMAKE_HOME_DIRECTORY}/ui/gui/widget/interpreter.py ${CMAKE_HOME_DIRECTORY}/ui/gui/widget/shell.py ${CMAKE_HOME_DIRECTORY}/ui/gui/mainwindow.py ${CMAKE_HOME_DIRECTORY}/api/gui/widget/nodebrowser.py ${CMAKE_HOME_DIRECTORY}/api/gui/widget/propertytable.py ${CMAKE_HOME_DIRECTORY}/api/gui/box/nodefilterbox.py ${CMAKE_HOME_DIRECTORY}/api/gui/model/vfsitemmodel.py ${CMAKE_HOME_DIRECTORY}/api/gui/button/pushbutton.py ${CMAKE_HOME_DIRECTORY}/ui/gui/dialog/dialog.py ${CMAKE_HOME_DIRECTORY}/ui/gui/ide/idewizard.py)

foreach(LANGUAGE ${DFF_SUPPORTED_LANGUAGES})
# Configure step
  execute_process(COMMAND ${PYTHON_QT4_LANGUAGE} -verbose ${TRANSLATABLE_STRINGS_IN_FILES} -ts ${CMAKE_CURRENT_SOURCE_DIR}/Dff_${LANGUAGE}.ts)
  set(QM_OUTPUT_FILES ${QM_OUTPUT_FILES} Dff_${LANGUAGE}.qm)
# Build step
  add_custom_target(gui_translation_${LANGUAGE} ALL
    COMMAND ${QT_LANGUAGE_COMPILER} ${CMAKE_CURRENT_SOURCE_DIR}/Dff_${LANGUAGE}.ts -qm ${CMAKE_CURRENT_BINARY_DIR}/Dff_${LANGUAGE}.qm
    SOURCES ${CMAKE_CURRENT_SOURCE_DIR}/Dff_${LANGUAGE}.ts
    )
endforeach(LANGUAGE ${DFF_SUPPORTED_LANGUAGES})

set(i18n_srcs
  ${QM_OUTPUT_FILES}
)

install_file(i18n ${i18n_srcs})
