CFLAGS="-I./src -I./src/daemon -D HAVE_CONFIG_H -g -O0 -Werror"
rm test_blueflood ./src/tests/test_blueflood.o -f
gcc -c ./src/tests/mock/plugin.c -o ./src/tests/mock/plugin.o $CFLAGS
gcc -c ./src/tests/test_blueflood.c -o ./src/tests/test_blueflood.o $CFLAGS
gcc -o test_blueflood ./src/tests/test_blueflood.o ./src/tests/mock/plugin.o -lyajl -lcurl -lpthread 

