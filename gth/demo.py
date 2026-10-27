"""Generate an offline Demo. No radio frame is sent."""
from scapy.layers.dot11 import RadioTap, Dot11, Dot11Beacon, Dot11Elt, Dot11Deauth, Dot11ProbeReq
from scapy.layers.eap import EAPOL, EAPOL_KEY
from scapy.layers.l2 import LLC, SNAP
from gth.packets import parse_packet, initialize_capture_layers

AP='02:00:00:00:00:01'
UNKNOWN_AP='02:00:00:00:00:02'
STA='02:00:00:00:10:01'
BC='ff:ff:ff:ff:ff:ff'
EPOCH=1760000000
RSN=bytes.fromhex('0100000fac040100000fac040100000fac020000')

def radio(signal=-45):
    return RadioTap(present='Flags+Channel+dBm_AntSignal',Flags=0,ChannelFrequency=2412,ChannelFlags=0x00a0,dBm_AntSignal=signal)

def make_packets():
    packets=[]
    def add(packet,offset):
        packet.time=EPOCH+offset
        packets.append(packet)
    for i in range(10):
        add(radio()/Dot11(type=0,subtype=8,addr1=BC,addr2=AP,addr3=AP,SC=i<<4)/Dot11Beacon(timestamp=1000000+i*102400,cap='ESS+privacy')/Dot11Elt(ID=0,info=b'LabNet')/Dot11Elt(ID=3,info=b'\x01')/Dot11Elt(ID=48,info=RSN),i*0.1)
    for i in range(4):
        add(radio(-55)/Dot11(type=0,subtype=4,addr1=BC,addr2=STA,addr3=BC,SC=(10+i)<<4)/Dot11ProbeReq()/Dot11Elt(ID=0,info=b'LabNet' if i%2 else b''),1+i*0.2)
    for message in (1,2,3,4):
        from_ap=message in (1,3)
        key=EAPOL_KEY(key_descriptor_type=2,key_descriptor_type_version=2,key_type=1,key_ack=int(from_ap),has_key_mic=int(message!=1),install=int(message==3),secure=int(message in (3,4)),key_replay_counter=1 if message<3 else 2,key_nonce=b'N'*32 if from_ap else b'S'*32)
        add(radio()/Dot11(type=2,subtype=0,FCfield=2 if from_ap else 1,addr1=STA if from_ap else AP,addr2=AP if from_ap else STA,addr3=AP,SC=(20+message)<<4)/LLC(dsap=0xaa,ssap=0xaa,ctrl=3)/SNAP(OUI=0,code=0x888e)/EAPOL(version=2,type=3)/key,2+message*0.01)
    for i in range(50):
        add(radio(-52)/Dot11(type=0,subtype=4,addr1=BC,addr2=STA,addr3=BC,SC=(100+i)<<4)/Dot11ProbeReq()/Dot11Elt(ID=0,info=f'Synthetic{i%12:02}'.encode()),10+i*0.15)
    for i in range(30):
        add(radio(-38)/Dot11(type=0,subtype=12,addr1=BC,addr2=AP,addr3=AP,SC=(200+i)<<4)/Dot11Deauth(reason=7),20+i*0.08)
    for i in range(8):
        add(radio(-41)/Dot11(type=0,subtype=8,addr1=BC,addr2=UNKNOWN_AP,addr3=UNKNOWN_AP,SC=(300+i)<<4)/Dot11Beacon(timestamp=i*102400,cap='ESS')/Dot11Elt(ID=0,info=b'LabNet')/Dot11Elt(ID=3,info=b'\x01'),25+i*0.2)
    return sorted(packets,key=lambda p:float(p.time))

def policy():
    return {'trusted_aps':[{'ssid':'LabNet','bssid':AP,'security':'wpa2','pmf_required':False}],'detection':{}}


def events():
    initialize_capture_layers()
    for packet in make_packets():
        event=parse_packet(packet)
        if event is not None:yield event
