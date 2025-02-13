cd build
pintos-mkdisk filesys.dsk --filesys-size=2
pintos -f -q
#pintos --filesys-size=2 -p ../../examples/echo -a echo -- -f -q run 'echo asdf'
pintos -v -k --qemu --filesys-size=2 -p tests/userprog/create-empty -a create_empty -- -q -f run create_empty
