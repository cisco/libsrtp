# Makefile for libSRTP documentation
#
# David A. McGrew
# Cisco Systems, Inc.
#
# This makefile does not use the autoconf system; we don't really need
# it.  We just run doxygen then latex.  If you don't have either of
# these, then there is no way that you can make your own
# documentation.  Of course, you can just go online at pick up the
# documentation from http://srtp.sourceforge.net.

# Determine the version of the library

version = $(shell cat ../VERSION)


.PHONY: libsrtpdoc cryptodoc clean
libsrtpdoc: 
	sed 's/LIBSRTPVERSION/$(version)/' header.template > header.tex
	doxygen
	sed 's/\subsection/\section/' latex/index.tex > latex/index.tmp
	mv latex/index.tmp latex/index.tex
	cd latex; make
	cp latex/refman.pdf libsrtp.pdf


cryptodoc: clean
	doxygen crypto.dox
	cd latex; make
	cp latex/refman.pdf crypto.pdf

clean:
	rm -rf latex/ header.tex
	for a in * ; do			                \
              if [ -f "$$a~" ] ; then rm -f $$a~; fi;	\
        done;
