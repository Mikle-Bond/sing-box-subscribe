.PHONY: all fire


%:
	redo $@

all:
	redo all
	flask run

fire:
	env CURL_CA_BUNDLE="`cygpath -w /etc/ssl/certs/ca-bundle.crt`" winpty python main.py --template_index 2 
	
