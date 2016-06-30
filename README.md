# eg16
Exact Greenhouse course 2016

Automated lights and curtains based on network traffic

NOTE: Running controllers or sniffer, the Google Protobuf .proto -files need to be converted.
"protobuf --python_out=. <name>.proto"

## Running:

(Addresses and ports need to be specified if not running in the same environment as I do...)

Edison:

python curtain-control.py

Controller:

python bridge-control.py

python IoT-hub.py --server

Sniffer: (Scapy requires sudo rights to monitor network traffic)

sudo python sniffer.py --sniff --ccast --iface wlan2


## Wiring Edison and the stepper motor driver board:

IN1 -> 3

IN2 -> 5

IN3 -> 6

IN4 -> 9

GND -> Digital GND

plus -> 5V

