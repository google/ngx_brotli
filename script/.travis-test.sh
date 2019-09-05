#!/bin/bash

# Setup shortcuts.
ROOT=`pwd`
NGINX=$ROOT/nginx/objs/nginx
BROTLI=$ROOT/deps/brotli/out/brotli
SERVER=http://localhost:8080
FILES=$ROOT/script/test
HR="---------------------------------------------------------------------------"

# fail / count
STATUS="0 0"

add_result() {
  is_success=$3
  num_success=`expr $1 + $is_success`
  num_tests=`expr $2 + 1`
  echo "$num_success $num_tests"
}

get_failed() {
  echo $1
}

get_count() {
  echo $2
}

expect_equal() {
  status=$1
  expected=$2
  actual=$3
  if cmp $expected $actual; then
    echo "OK" >&2
    echo $(add_result $status 0)
  else
    echo "FAIL (equality)" >&2
    echo $(add_result $status 1)
  fi
}

expect_br_equal() {
  status=$1
  expected=$2
  actual_br=$3
  if $BROTLI -dfk ./${actual_br}.br; then
    echo $(expect_equal "$status" $expected $actual_br)
  else
    echo "FAIL (decompression)" >&2
    echo $(add_result $status 1)
  fi
}

# Start server.
echo "Statring NGINX"
$NGINX -c $ROOT/script/test.conf
# Fetch vanilla 404 response.
curl -s -o ./notfound.txt $SERVER/notfound

# Run tests.
echo $HR

echo "Test: long file with rate limit"
curl -s -H 'Accept-encoding: br' -o ./war-and-peace.br --limit-rate 300K $SERVER/war-and-peace.txt
STATUS=$(expect_br_equal "$STATUS" $FILES/war-and-peace.txt ./war-and-peace)

echo "Test: compressed 404"
curl -s -H 'Accept-encoding: br' -o ./notfound.br $SERVER/notfound
STATUS=$(expect_br_equal "$STATUS" ./notfound.txt ./notfound)

echo "Test: A-E: 'gzip, br'"
curl -s -H 'Accept-encoding: gzip, br' -o ./ae-01.br $SERVER/small.txt
STATUS=$(expect_br_equal "$STATUS" $FILES/small.txt ./ae-01)

echo "Test: A-E: 'gzip, br, deflate'"
curl -s -H 'Accept-encoding: gzip, br, deflate' -o ./ae-02.br $SERVER/small.txt
STATUS=$(expect_br_equal "$STATUS" $FILES/small.txt ./ae-02)

echo "Test: A-E: 'gzip, br;q=1, deflate'"
curl -s -H 'Accept-encoding: gzip, br;q=1, deflate' -o ./ae-03.br $SERVER/small.txt
STATUS=$(expect_br_equal "$STATUS" $FILES/small.txt ./ae-03)

echo "Test: A-E: 'br;q=0.001'"
curl -s -H 'Accept-encoding: br;q=0.001' -o ./ae-04.br $SERVER/small.txt
STATUS=$(expect_br_equal "$STATUS" $FILES/small.txt ./ae-04)

echo "Test: A-E: 'bro'"
curl -s -H 'Accept-encoding: bro' -o ./ae-05.txt $SERVER/small.txt
STATUS=$(expect_equal "$STATUS" $FILES/small.txt ./ae-05.txt)

echo "Test: A-E: 'bo'"
curl -s -H 'Accept-encoding: bo' -o ./ae-06.txt $SERVER/small.txt
STATUS=$(expect_equal "$STATUS" $FILES/small.txt ./ae-06.txt)

echo "Test: A-E: 'br;q=0'"
curl -s -H 'Accept-encoding: br;q=0' -o ./ae-07.txt $SERVER/small.txt
STATUS=$(expect_equal "$STATUS" $FILES/small.txt ./ae-07.txt)

echo "Test: A-E: 'br;q=0.'"
curl -s -H 'Accept-encoding: br;q=0.' -o ./ae-08.txt $SERVER/small.txt
STATUS=$(expect_equal "$STATUS" $FILES/small.txt ./ae-08.txt)

echo "Test: A-E: 'br;q=0.0'"
curl -s -H 'Accept-encoding: br;q=0.0' -o ./ae-09.txt $SERVER/small.txt
STATUS=$(expect_equal "$STATUS" $FILES/small.txt ./ae-09.txt)

echo "Test: A-E: 'br;q=0.00'"
curl -s -H 'Accept-encoding: br;q=0.00' -o ./ae-10.txt $SERVER/small.txt
STATUS=$(expect_equal "$STATUS" $FILES/small.txt ./ae-10.txt)

echo "Test: A-E: 'br ; q = 0.000'"
curl -s -H 'Accept-encoding: br ; q = 0.000' -o ./ae-11.txt $SERVER/small.txt
STATUS=$(expect_equal "$STATUS" $FILES/small.txt ./ae-11.txt)

# Report.

FAILED=$(get_failed $STATUS)
COUNT=$(get_count $STATUS)
echo $HR
echo "Results: $FAILED of $COUNT tests failed"

echo $HR
echo "Stopping NGINX"
# Stop server.
$NGINX -c $ROOT/script/test.conf -s stop

# Restore status-quo.
cd $ROOT

exit $FAILED
