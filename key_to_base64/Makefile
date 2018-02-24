all:
	@gcc src/*.c sm2_sign_key_to_base64.c -I internal/ -I src/ -o test -lcrypto -lssl -L /usr/local/lib/

clean:
	@rm -rf test
