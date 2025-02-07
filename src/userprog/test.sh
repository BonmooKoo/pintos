cd build
pintos-mkdisk filesys.dsk --filesys-size=2
pintos -f -q
pintos --filesys-size=2 -p ../../examples/echo -a echo -- -f -q run 'echo x'
