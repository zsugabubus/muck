all :
	meson compile -C build

bootstrap :
	meson build

install :
	meson install -C build

README : muck.1
	roff2text $< | col >$@ -bx

.PHONY: all bootstrap install
