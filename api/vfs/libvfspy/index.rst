.. libvfs documentation master file, created by
   sphinx-quickstart on Thu Sep 23 18:21:37 2010.
   You can adapt this file completely to your liking, but it should at least
   contain the root `toctree` directive.

Welcome to DFF Api documentation!
==================================

This documentation purpose is to describe the different classes composing DFF
Application Programming Interface. Developing a DFF modules implied that you
use this API and implement several methods provided by it.

Classes are devided into several modules. The main three of them are :

1. Env : this module is used to set up the environment in which the module will
run. The different classes of it are designed to configure the module and access
parameters which could have been passed to it, and then generate results about
its execution.

2. Vfs : this module also has a major importance in the vibe.

3. Variant


.. toctree::
   :maxdepth: 2

   libvfs.rst

   libvariant.rst

   libenv.rst

Indices and tables
==================

* :ref:`genindex`
* :ref:`modindex`
* :ref:`search`
