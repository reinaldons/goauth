include $(GOROOT)/src/Make.inc

TARG=reinaldons/goauth
GOFILES=oauth.go\
		http.go\
		url.go\
		helpers.go\
		persist.go\
		error.go\

include $(GOROOT)/src/Make.pkg

