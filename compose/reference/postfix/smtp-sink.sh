#!/bin/sh
set -eu

printf '220 outbound-sink.example.test ESMTP\r\n'
in_data=0
while IFS= read -r raw; do
  line=${raw%"$(printf '\r')"}
  if [ "$in_data" -eq 1 ]; then
    if [ "$line" = "." ]; then
      : > /tmp/gotth-mail-outbound-sink.accepted
      in_data=0
      printf '250 2.0.0 accepted\r\n'
    fi
    continue
  fi
  command=${line%% *}
  case "$command" in
    EHLO|HELO)
      printf '250-outbound-sink.example.test\r\n250 8BITMIME\r\n'
      ;;
    MAIL|RCPT|RSET|NOOP)
      printf '250 2.0.0 ok\r\n'
      ;;
    DATA)
      in_data=1
      printf '354 end with <CRLF>.<CRLF>\r\n'
      ;;
    QUIT)
      printf '221 2.0.0 bye\r\n'
      exit 0
      ;;
    *)
      printf '500 5.5.1 unsupported\r\n'
      ;;
  esac
done
