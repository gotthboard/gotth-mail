#!/bin/sh
set -eu

printf '220 outbound-sink.example.test ESMTP\r\n'
in_data=0
recipient_count=0
while IFS= read -r raw; do
  line=${raw%"$(printf '\r')"}
  if [ "$in_data" -eq 1 ]; then
    if [ "$line" = "." ]; then
	  printf '%s\n' "$recipient_count" >> /tmp/gotth-mail-outbound-sink.accepted
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
    RCPT)
	  recipient_count=$((recipient_count + 1))
	  printf '250 2.0.0 ok\r\n'
	  ;;
    MAIL|RSET|NOOP)
	  if [ "$command" = "RSET" ]; then
	    recipient_count=0
	  fi
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
