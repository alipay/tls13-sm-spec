SOURCES := ${wildcard *.md}
TEXT    := ${SOURCES:.md=.txt}
HTML    := ${SOURCES:.md=.html}
XML     := ${SOURCES:.md=.xml}
NITS    := ${SOURCES:.md=.nits}

all: text html xml

clean:
	rm -f $(TEXT) $(HTML) $(XML) $(NITS)

text:	$(TEXT)
html:   $(HTML)
xml:    $(XML)
nits:   $(NITS)

%.xml:	%.md
	kramdown-rfc2629 $< > $@

%.html: %.xml
	xml2rfc --html $< $@

%.txt:	%.xml
	xml2rfc --text $< $@

%.nits: %.txt
	idnits --verbose $(TEXT) > $(NITS)

open: %.txt
	open $(TEXT)
