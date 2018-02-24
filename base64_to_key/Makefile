all:
	@gcc src/*.c sm2_sign_base64_to_key.c -I internal/ -I src/ -o test -lcrypto -lssl -L /usr/local/lib/

clean:
	@rm -rf test
