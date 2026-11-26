#!/bin/sh
# phone.sh NAME [URI]: run linphonec as NAME (log in /out/NAME.log), with
# files instead of a sound card. Without URI it auto-answers and waits;
# with URI it calls it, talks for 10 seconds and hangs up.
set -e
name=$1
uri=${2:-}
export HOME=/tmp/home
mkdir -p "$HOME/.local/share/linphone" "$HOME/.config"
cp /linphone/linphonerc "$HOME/linphonerc"
log=/out/$name.log
rm -f "$log"
if [ -z "$uri" ]; then
    (sleep 2; echo "soundcard use files"; exec sleep infinity) \
        | linphonec -c "$HOME/linphonerc" -a -d 6 -l "$log" >/dev/null 2>&1
else
    (sleep 2; echo "soundcard use files"; sleep 1; echo "call $uri"; sleep 12; echo terminate; sleep 2; echo quit) \
        | timeout 40 linphonec -c "$HOME/linphonerc" -d 6 -l "$log" >/dev/null 2>&1 || true
fi
