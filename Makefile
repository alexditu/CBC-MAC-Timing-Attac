build:
	g++ cbc_main.cpp -o cbc_main

run: build
	./cbc_main

clean:
	rm -rf cbc_main
