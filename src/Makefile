default: pam_mpa.so

pam_mpa.so: pam_mpa.o
	gcc -shared -o pam_mpa.so pam_mpa.o -lpam

pam_mpa.o: pam_mpa.c
	gcc -Wall -Werror -fPIC -c pam_mpa.c

clean:
	rm -f pam_mpa.o pam_mpa.so
