# Makefile for the PuTTY icon suite.

ICONS = putty puttycfg puttygen pscp pageant pterm ptermcfg puttyins
SIZES = 16 32 48 128 256

MODE = # override to -it on command line for opaque testing

PAMS = $(foreach I,$(ICONS),$(foreach S,$(SIZES),$(I)-$(S).pam))
MONOPAMS = $(foreach I,$(ICONS),$(foreach S,$(SIZES),$(I)-$(S)-mono.pam))
TRUEPAMS = $(foreach I,$(ICONS),$(foreach S,$(SIZES),$(I)-$(S)-true.pam))

PNGS = $(patsubst %.pam,%.png,$(PAMS))
MONOPNGS = $(patsubst %.pam,%.png,$(MONOPAMS))
TRUEPNGS = $(patsubst %.pam,%.png,$(TRUEPAMS))

ICOS = putty.ico puttygen.ico pscp.ico pageant.ico pageants.ico puttycfg.ico \
       puttyins.ico
ICNS = PuTTY.icns Pterm.icns
CICONS = xpmputty.c xpmpucfg.c xpmpterm.c xpmptcfg.c

base: icos cicons pngs

all: pngs monopngs base icns # truepngs currently disabled by default

pngs: $(PNGS)
monopngs: $(MONOPNGS)
truepngs: $(TRUEPNGS)

icos: $(ICOS)
icns: $(ICNS)
cicons: $(CICONS)

install: icos cicons
	cp $(ICOS) ../windows
	cp $(CICONS) ../unix

$(PAMS): %.pam: mkicon.py
	./mkicon.py $(MODE) $(join $(subst -, ,$(basename $@)),_icon) $@
	sleep 1

$(PNGS) $(MONOPNGS) $(TRUEPNGS): %.png: %.pam
	magick $< $@
	sleep 1

$(MONOPAMS): %.pam: mkicon.py
	./mkicon.py -2 $(MODE) $(join $(subst -, ,$(subst -mono,,$(basename $@))),_icon) $@

$(TRUEPAMS): %.pam: mkicon.py
	./mkicon.py -T $(MODE) $(join $(subst -, ,$(subst -true,,$(basename $@))),_icon) $@

putty.ico: putty-256.png 
	magick $< -colors 16 -background transparent -define icon:auto-resize=64,48,32,16 $@

puttycfg.ico: puttycfg-256.png 
	magick $< -colors 16 -background transparent -define icon:auto-resize=64,48,32,16 $@

puttygen.ico: puttygen-256.png
	magick $< -colors 16 -background transparent -define icon:auto-resize=64,48,32,16 $@

pageant.ico: pageant-256.png
	magick $< -colors 16 -background transparent -define icon:auto-resize=64,48,32,16 $@

pageants.ico: pageant-256.png
	magick $< -colors 16 -background transparent -define icon:auto-resize=16 $@

pscp.ico: pscp-256.png
	magick $< -colors 16 -background transparent -define icon:auto-resize=64,48,32,16 $@

# Because the installer icon makes heavy use of brown when drawing
# the cardboard box, it's worth having 8-bit versions of it in
# addition to the 4- and 1-bit ones.
puttyins.ico: puttyins-256.png
	magick $< -colors 256 -background transparent -define icon:auto-resize=64,48,32,16 $@

# Icon for the website. (This isn't linked into "make all".)
website.ico: putty-256.png
	magick $< -colors 16 -background transparent -define icon:auto-resize=16 $@

xpmputty.c: putty-16.png putty-32.png putty-48.png
	perl ./cicon.pl main_icon $^ > $@

xpmpucfg.c: puttycfg-16.png puttycfg-32.png puttycfg-48.png
	perl ./cicon.pl cfg_icon $^ > $@

xpmpterm.c: pterm-16.png pterm-32.png pterm-48.png
	perl ./cicon.pl main_icon $^ > $@

xpmptcfg.c: ptermcfg-16.png ptermcfg-32.png ptermcfg-48.png
	perl ./cicon.pl cfg_icon $^ > $@

PuTTY.icns: putty-16-mono.pam putty-16.pam \
	    putty-32-mono.pam putty-32.pam \
	    putty-48-mono.pam putty-48.pam \
	    putty-128.pam
	./macicon.py mono:putty-16-mono.pam colour:putty-16.pam \
	             mono:putty-32-mono.pam colour:putty-32.pam \
	             mono:putty-48-mono.pam colour:putty-48.pam \
	                                    colour:putty-128.pam \
		output:$@

Pterm.icns: pterm-16-mono.pam pterm-16.pam \
	    pterm-32-mono.pam pterm-32.pam \
	    pterm-48-mono.pam pterm-48.pam \
	    pterm-128.pam
	./macicon.py mono:pterm-16-mono.pam colour:pterm-16.pam \
	             mono:pterm-32-mono.pam colour:pterm-32.pam \
	             mono:pterm-48-mono.pam colour:pterm-48.pam \
	                                    colour:pterm-128.pam \
		output:$@

clean:
	rm -f *.pam *.png *.ico *.icns *.c
