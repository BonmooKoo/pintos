cd build
#pintos-mkdisk filesys.dsk --filesys-size=2
#pintos -f -q
#pintos --filesys-size=2 -p ../../examples/echo -a echo -- -f -q run 'echo asdf'
#pintos -v -k --qemu --filesys-size=2 -p tests/userprog/read-bad-ptr -a create_empty -- -q -f run read_bad_ptr
pintos -v -k -T 360 --qemu  --filesys-size=2 -p tests/userprog/no-vm/multi-oom -a multi-oom -- -q    -f run multi-oom < /dev/null 2> tests/userprog/no-vm/multi-oom.errors |tee tests/userprog/no-vm/multi-oom.output
perl -I../.. ../../tests/userprog/no-vm/multi-oom.ck tests/userprog/no-vm/multi-oom tests/userprog/no-vm/multi-oom.result
