#!/usr/bin/env bash
# Try DENIS's industrial-protocol decoders and OT rules on REAL captures from public collections, without any plant.
#
#   tools/ot-samples.sh                 uses target/release/denis (or DENIS_BIN)
#   OFFLINE=1 tools/ot-samples.sh       only the self-made encrypted sample (no download)
#
# The captures are downloaded from the public ICS-pcap collection (https://github.com/automayt/ICS-pcap: samples from the
# Wireshark wiki, Digital Bond, 4SICS and others; each keeps its own licence, which is why they are fetched, never
# copied into this repository). Every one is a small file except EIP-FirmwareChange (3 MB). Each is run through
# `denis replay` and the answer is checked for what the capture is known to contain. A failure here means a decoder
# no longer understands a real device's traffic: worth reading before a release.
set -euo pipefail
cd "$(dirname "$0")/.."
BIN="${DENIS_BIN:-target/release/denis}"
[ -x "$BIN" ] || BIN=target/debug/denis
T=$(mktemp -d); trap 'rm -rf "$T"' EXIT
BASE="https://media.githubusercontent.com/media/automayt/ICS-pcap/master"
fail=0
check() { # name, file, pattern...
  local name="$1" file="$2"; shift 2
  local out; out=$("$BIN" replay "$file" 2>&1) || { echo "  FAIL  $name: replay failed: $out"; fail=1; return; }
  for p in "$@"; do
    if ! grep -qF -- "$p" <<<"$out"; then echo "  FAIL  $name: expected \"$p\""; echo "$out" | sed 's/^/        /' | head -25; fail=1; return; fi
  done
  echo "  ok    $name"
}
fetch() { curl -sfL -m 120 -o "$T/$2" "$BASE/$(python3 -c 'import urllib.parse,sys; print(urllib.parse.quote(sys.argv[1]))' "$1")"; }

echo "encrypted traffic (a capture made here from real OpenSSL handshakes)"
python3 tools/make-encrypted-sample.py "$T/encrypted.pcap" >/dev/null
check "secured OPC UA and TLS to a PLC: the paths, the protocol version and the server name, and office TLS ignored" "$T/encrypted.pcap" \
  "opcua-tls/4843" "TLS 1.3 handshake (server name plc1.plant.local)" "tls/8443" "TLS 1.2 handshake" "New opcua-tls path" "Conversations (2)"

if [ "${OFFLINE:-0}" = 0 ]; then
  echo "public captures of real devices"
  while IFS='|' read -r path name; do fetch "$path" "$name" || { echo "  FAIL  could not download $path"; fail=1; }; done <<'LIST'
MODBUS/Modbus/Modbus.pcap|modbus.pcap
MODBUS/MODBUS-TestDataPart1/MODBUS-TestDataPart1.pcap|modbus2.pcap
IEC 60870/iec104/iec104.pcap|iec104.pcap
S7/1-S7comm-VarService-Read-DB1DBD0/1-S7comm-VarService-Read-DB1DBD0.pcap|s7read.pcap
S7/4-S7comm-Download-DB1-with-password-request/4-S7comm-Download-DB1-with-password-request.pcap|s7download.pcap
BACNET/BACnetARRAY-elements/BACnetARRAY-elements.pcap|bacnet.pcap
EIP/EIP-FirmwareChange/EIP-FirmwareChange.pcap|eip.pcap
FINS (OMRON)/omron/omron.pcap|fins.pcap
LIST
  check "Modbus/TCP: a master polling a PLC" "$T/modbus.pcap" "modbus/502" "read holding registers (3)" "Devices (2)"
  check "Modbus/TCP test data: reads, writes, diagnostics, and a device that starts writing" "$T/modbus2.pcap" \
    "write single coil (5)" "diagnostics (8)" "ot_control_command" "ot_write_escalation" "modbus:server+client"
  check "IEC 60870-5-104: an RTU receiving commands" "$T/iec104.pcap" "iec104/2404" "command (type 45)" "ot_control_command"
  check "Siemens S7comm: reading a variable" "$T/s7read.pcap" "s7/102" "read variable (0x04)"
  check "Siemens S7comm: a program download is a control command" "$T/s7download.pcap" "program download (0x1a)" "ot_control_command" "New s7 path"
  check "BACnet/IP: Who-Is, I-Am and reads between building controllers" "$T/bacnet.pcap" "bacnet/47808" "Who-Is" "I-Am" "read property (12)"
  check "EtherNet/IP: a firmware change of a Logix controller (thousands of tag writes, then a reset)" "$T/eip.pcap" \
    "enip/44818" "CIP write (service 0x4d)" "CIP reset (service 0x05)" "ot_control_command"
  check "Omron FINS: memory reads/writes and a RUN command (the one that matters most)" "$T/fins.pcap" \
    "fins/9600" "memory area read (0x01.0x01)" "run (0x04.0x01)" "ot_control_command"
fi

echo "HART-IP (Wireshark wiki sample capture, fetched separately: not part of ICS-pcap)"
if [ "${OFFLINE:-0}" = 0 ]; then
  curl -sfL -m 60 -o "$T/hart_ip.pcap" "https://wiki.wireshark.org/uploads/__moin_import__/attachments/SampleCaptures/hart_ip.pcap" \
    && check "HART-IP: a session and wrapped HART commands between a host and a field instrument" "$T/hart_ip.pcap" \
      "hart-ip/5094" \
    || { echo "  FAIL  could not download the HART-IP sample"; fail=1; }
fi
[ "$fail" = 0 ] && echo "all OT sample checks passed" || { echo "OT sample checks FAILED"; exit 1; }
