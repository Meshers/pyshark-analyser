import pyshark
captures = pyshark.FileCapture('btsnoop_hci_smartron.log')

#['__class__', '__contains__', '__delattr__', '__dict__', '__dir__', '__doc__', '__format__', '__getattr__', '__getattribute__', '__getitem__', '__getstate__', '__hash__', '__init__', '__module__', '__new__', '__reduce__', '__reduce_ex__', '__repr__', '__setattr__', '__setstate__', '__sizeof__', '__str__', '__subclasshook__', '__weakref__', '_packet_string',
#'bluetooth', 'bthci_evt', 'captured_length', 'frame_info', 'get_multiple_layers', 'hci_h4', 'highest_layer', 'interface_captured', 'layers', 'length', 'number', 'pretty_print', 'sniff_time', 'sniff_timestamp', 'transport_layer']
#'destination', 'info', 'length', 'no', 'protocol', 'source', 'summary_line', 'time']

mac_mapping = {}
for capture in captures:
    if(capture.length > 245 and capture.hci_h4.direction == '0x00000001'):
        try:
            if(mac_mapping.has_key(capture.bthci_evt.bd_addr)):
                mac_mapping[capture.bthci_evt.bd_addr].append(str(capture.bthci_evt.btcommon_eir_ad_entry_device_name))
            else:
                mac_mapping[capture.bthci_evt.bd_addr] = [str(capture.bthci_evt.btcommon_eir_ad_entry_device_name),]
        except AttributeError as e:
            pass

for key, value in mac_mapping.items():
    #Ignoring my watch, laptops, scanner devices
    if(key not in ['14:f6:5a:6d:92:52', 'ac:c3:3a:00:c6:e6', '20:91:48:43:4c:35', '50:fc:9f:6b:7e:3a', '24:a0:74:ea:ad:cf']):
        print(key + ":" + str(value))
        print("\n\n")
