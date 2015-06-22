
TARGET=tcpreplay
SRC=$(wildcard *.c)
OBJS=${SRC:%.c=%.o}
NAME=${SRC:%.c=%}
DEPS=$(SRC:%.c=.dep/*.d)

LDFLAGS += -lpcap -lpthread

${TARGET}:  ${OBJS} $(HSB_LIBS)
	${CC}  -o $@ ${OBJS} ${LDFLAGS}

-include ${DEPS}

.PHONY: dep 

all :  ${TARGET} 
	cp $(TARGET) ${EXEDIR}
	
%.o: %.c
	${CC} ${CFLAGS} -c $< ${SSLCFLAGS}
	@mkdir -p .dep
	${CC} -MM $(CFLAGS) $*.c > .dep/$*.d 
#	@mv -f .dep/$*.d  .dep/$*.d.tmp
#	@sed -e 's|.*:|$*.o:|' < .dep/$*.d.tmp > .dep/$*.d
#	@sed -e 's/.*://' -e 's/\\$$//' < .dep/$*.d.tmp | fmt -1 | \
#	 sed -e 's/^ *//' -e 's/$$/:/' >> .dep/$*.d
#	@rm -f .dep/$*.d.tmp

clean:
	@rm -fr ${TARGET} *.o core .dep


dep: 
	@mkdir -p .dep
	for i in ${NAME} ; do  \
	${CC} -MM $(CFLAGS) "$${i}".c > .dep/"$${i}".d ;\
	done
#	mv -f .dep/$${i}.d  .dep/$${i}.d.tmp ;\
#	sed -e 's|.*:|$${i}.o:|' < .dep/$${i}.d.tmp > .dep/$${i}.d ; \
#	sed -e 's/.*://' -e 's/\\$$//' < .dep/$${i}.d.tmp | fmt -1 |  sed -e 's/^ *//' -e 's/$$/:/' >> .dep/$${i}.d ; \
#	rm -f .dep/$${i}.d.tmp ; \
#	done

