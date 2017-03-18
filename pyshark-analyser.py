import pyshark
import sys, getopt

filename = ''
try:
    if(len(sys.argv) > 1):
        opts, args = getopt.getopt(sys.argv[1:],"hf:",["filename=",])
    else:
        print('Usage: pyshark-analyser.py -f <logfile>')
        sys.exit(2)
except(getopt.GetoptError):
    print('pyshark-analyser.py -f <logfile>')
    sys.exit(2)
for opt, arg in opts:
    if opt == '-h':
        print('pyshark-analyser.py -f <logfile>')
        sys.exit()
    elif opt in ("-f", "--filename"):
        filename = arg

captures = pyshark.FileCapture(filename)

#['__class__', '__contains__', '__delattr__', '__dict__', '__dir__', '__doc__', '__format__', '__getattr__', '__getattribute__', '__getitem__', '__getstate__', '__hash__', '__init__', '__module__', '__new__', '__reduce__', '__reduce_ex__', '__repr__', '__setattr__', '__setstate__', '__sizeof__', '__str__', '__subclasshook__', '__weakref__', '_packet_string',
#'bluetooth', 'bthci_evt', 'captured_length', 'frame_info', 'get_multiple_layers', 'hci_h4', 'highest_layer', 'interface_captured', 'layers', 'length', 'number', 'pretty_print', 'sniff_time', 'sniff_timestamp', 'transport_layer']
#'destination', 'info', 'length', 'no', 'protocol', 'source', 'summary_line', 'time']

mac_mapping = {}
for capture in captures:
    if(capture.hci_h4.direction == '0x00000001'):
        try:
            if(mac_mapping.has_key(capture.bthci_evt.bd_addr)):
                mac_mapping[capture.bthci_evt.bd_addr].append(str(capture.bthci_evt.btcommon_eir_ad_entry_device_name).replace('\\x', '_'))
            else:
                mac_mapping[capture.bthci_evt.bd_addr] = [str(capture.bthci_evt.btcommon_eir_ad_entry_device_name).replace('\\x', '_'),]
        except AttributeError as e:
            pass

for key, value in mac_mapping.items():
    #Ignoring watches, laptops, TVs (hardcoded)
    if(key not in ['e7:8d:69:da:77:8c', 'dc:1a:c5:4d:8c:3c', '20:91:48:43:4c:35', '40:16:3b:bc:f9:da', '30:3a:64:85:23:1a', '3c:77:e6:53:26:7a', 'cc:b1:1a:25:30:c1', 'ca:43:20:d1:5b:7e', '18:f4:6a:e3:3d:81', 'c8:0f:10:08:3b:d5', '38:59:f9:ec:4e:4a', 'e0:2a:82:d6:12:3a']):
        print(key)
        print("\n".join(value))
        print("\n\n")
