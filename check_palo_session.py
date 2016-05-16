#!/usr/bin/python
#
# Author: Ryan Ratkiewicz (<ryan@ryanrat.com>)
# check_palo_session.py
# Last-Modified:  2015-12-23
#
# get_session.py was originally intended to pull a specific session from the Palo Alto Networks firewall via the Palo's restful API from a Nagios host.
# The script relies upon version 2.7 of Python, although earlier versions may also work. 
# 
# Example:
# python check_palo_session.py myfirewall.corp.com
#       Will return all sessions in the firewall in a pretty print format.
#
# python check_palo_session.py myfirewall.corp.com --src_address x.x.x.x --dst_address y.y.y.y --dst_port 80 --protocol tcp
#       Will return all sessions that match specified criteria.
#
# python check_palo_session.py myfirewall.corp.com --src_address x.x.x.x --dst_address y.y.y.y --dst_port 80 --protocol tcp --nagios
#       Will return all sessions that match specified criteria, but evaluate only the first match in a Nagios output format.
#       Output Example:
#           SESSION OK - Session ID 31432 | bytes=4786
#



import sys
import argparse
from lxml import etree
import xml.etree.ElementTree as ET
import requests
from requests.packages.urllib3.exceptions import InsecureRequestWarning
import pprint

# get_session returns a list of dictionary items that contain Juniper SRX session data based upon the input criteria given.
# device is the only mandatory field for this, as if no other options are specified, all sessions will be returned.
# if the SRX is clustered, Backup sessions from the passive device are not included in the list.
# Since the SRX returns XML data, we parse the XML using etree, and place the corresponding data session elements inside a 
# dictionary.  We then also parse each flow or wing element of the session and add it to the dictionary.  
# In order to distinguish between 'in' and 'out' wings, we prepend the dictionary with the 'direction' element of the wing,
# thus giving us a unique key for the flow.

def get_session(source_ip,destination_ip,destination_port,protocol,device,apikey):
    
    session_identifier = ''
    requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
    
    try:
        resp = requests.get('https://'+ device + '/api/?key=' + apikey + '&type=op&cmd=<show><session><all><filter><destination>' + destination_ip + \
    '</destination><source>' + source_ip + '</source><destination-port>' + destination_port +'</destination-port><protocol>' + protocol + \
    '</protocol></filter></all></session></show>', verify=False)
    
    except requests.exceptions.RequestException as e:
        print e
        sys.exit(2)
    
    session_list = []

    if resp.text.find("idx") == -1 :
        return session_list;

    root = ET.fromstring(resp.text)

    for session in root.findall('./result/entry') :
        session_state = session.find('state')
        byte_count = session.find('total-byte-count')
        session_identifier = session.find('idx')
        policy = session.find('security-rule')
        start_time = session.find('start-time')
        application = session.find('application')
        source_address = session.find('source')
        destination_address = session.find('dst')
        destination_port = session.find('dport')
        source_port = session.find('sport')
        protocol = session.find('proto')

    
    session_dict = {'session-id' : session_identifier.text, 'session-state' : session_state.text, 'policy' : policy.text, 'application' : application.text, \
            'start-time' : start_time.text, 'source-address' : source_address.text, 'destination-address' : destination_address.text, 'source-port' : source_port.text, \
             'destination-port' : destination_port.text, 'protocol' : protocol.text, 'total-byte-count' : byte_count.text, 'policy' : policy.text }
            
    if session_state.text == 'ACTIVE' :
        session_list.append(session_dict.copy())

    return session_list;


# Main declares a standard parser and passes the arguments to get_session.  Once the output is returned back to main, we evaluate if args.nagios
# is being used, and if so, it returns output that will allow Nagios to evaluate the health of the service, and also pass perf data after the '|'
# (pipe) delimiter.  If Nagios is not specified, the main function returns a pretty printed version of the session data.

def main(argv):
    source_ip = None
    destination_ip = None
    destination_port = None
    protocol = None
    device = None


    parser = argparse.ArgumentParser()
    nagiosGroup = parser.add_mutually_exclusive_group()
    parser.add_argument("device",help="Specify the hostname or IP address of your Palo Alto Networks Firewall")
    parser.add_argument("--src_address", help="Source address of desired session(s)")
    parser.add_argument("--dst_address", help="Destination address of desired session(s)")
    parser.add_argument("--dst_port", help="Destination port of desired session(s)")
    parser.add_argument("--protocol", help="IP Protocol Number (TCP = 6, UDP = 17")
    nagiosGroup.add_argument("--nagios_bytes", dest="nagios_bytes", action="store_true",  help="Nagios formatted output to return byte counts")
    parser.add_argument("--api_key", help="API Key for AuthN")

    args = parser.parse_args()

    session = get_session(args.src_address, args.dst_address, args.dst_port, args.protocol, args.device, args.api_key)

    if args.nagios_bytes :
        if len(session) == 0:
            print 'CRITICAL:  No session found'
            sys.exit(2)
        
        print 'OK - Session ID ' + session[0].get('session-id') + '; | bytes=' + session[0].get('total-byte-count') + ';'
        print 'Policy=' + session[0].get('policy') + ';'
        print 'Application=' + session[0].get('application') + ';'
        print 'StartTime=' + session[0].get('start-time') + ';'
        (sys.exit(0))
        
    else :
        pp = pprint.PrettyPrinter(indent=4)
        pp.pprint(session)

if __name__ == "__main__":
    main(sys.argv[1:])


