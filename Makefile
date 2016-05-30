

all: 
	nitrestful client_exemple.nit
	nitc client_exemple_rest.nit

clean:
	rm client_exemple_rest
	rm client_exemple_rest.nit