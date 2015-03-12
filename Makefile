decode_wrapper.so: decode_wrapper.c 
	gcc -shared -o $@ -fPIC $< libopcodes.so

clean:
	rm -f decode_wrapper.so
