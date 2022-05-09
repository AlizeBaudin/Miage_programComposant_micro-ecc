LIBSO = component_uECC.so
LIBSO_OBJS = uECC.o

include ../gcc.mk

all: $(LIBSO)
clean:
	rm -f ${LIBSO}  ${LIBSO_OBJS}


${DESTINATION_LIBSO}: ${LIBSO}
	cp $< $@
