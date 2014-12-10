SCRIPT=$(readlink -f "$0")
CURDIR=`dirname "$SCRIPT"`

GCOV_FLAGS="-Wdisabled-optimization -O0 --coverage -fprofile-arcs -ftest-coverage"
GCOV_LDFLAGS="-fprofile-arcs"

#real curl
CFLAGS="-I./src -I./src/daemon -D HAVE_CONFIG_H -g -O0 -Werror -Wall $GCOV_FLAGS"
rm test_blueflood ./src/tests/test_blueflood2.o -f
find -name "*.gcno" -or -name "*.gcda" | xargs rm -f
gcc -c ./src/tests/mock/plugin.c -o ./src/tests/mock/plugin.o $CFLAGS
gcc -c ./src/tests/test_blueflood2.c -o ./src/tests/test_blueflood2.o $CFLAGS
gcc -o $CURDIR/test_blueflood ./src/tests/test_blueflood2.o ./src/tests/mock/plugin.o -lyajl -lcurl -lpthread $GCOV_LDFLAGS
#check compilation error
if [ $? -ne 0 ]; then
    exit
fi
#run test
$CURDIR/test_blueflood

echo "mocks yajl, curl"
rm test_blueflood ./src/tests/test_blueflood1.o -f
gcc -c ./src/tests/test_blueflood1.c -o ./src/tests/test_blueflood1.o -DTEST_MOCK $CFLAGS
gcc -c ./src/tests/test_blueflood_mock.c -o ./src/tests/test_blueflood_mock.o $CFLAGS
gcc -o $CURDIR/test_blueflood ./src/tests/test_blueflood1.o ./src/tests/mock/plugin.o ./src/tests/test_blueflood_mock.o -lpthread $GCOV_LDFLAGS
#check compilation error
if [ $? -ne 0 ]; then
    exit
fi
#run test
$CURDIR/test_blueflood

GCOV_HTML_FOLDER=$CURDIR/blueflood_coverage_html
#prepare html document covering only sources from lib folder
lcov --gcov-tool=gcov --directory=$CURDIR --capture --output-file $GCOV_HTML_FOLDER/app.info
genhtml --output-directory $GCOV_HTML_FOLDER $GCOV_HTML_FOLDER/app.info

echo open $GCOV_HTML_FOLDER/index.html