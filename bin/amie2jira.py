#!/usr/bin/env python3
"""
"""
#from xom
import http.client as httplib
import json
import logging
import logging.handlers
import os
import pdb
import pwd
import signal
import ssl
import sys

#from packetstat
from configparser import ConfigParser

from amieclient import AMIEClient
import json
import requests
from fuzzywuzzy import process
from datetime import date
import datetime
import time

FoS = {
        "100": 13105,
        "110": 11736,
        "111": 11737,
        "112": 11738,
        "113": 11739,
        "114": 11740,
        "115": 11741,
        "116": 11742,
        "117": 12239,
        "118": 11744,
        "120": 11745,
        "121": 11746,
        "122": 11747,
        "123": 11748,
        "124": 11749,
        "130": 11750,
        "131": 11751,
        "132": 11752,
        "133": 11753,
        "134": 11754,
        "135": 11755,
        "140": 11756,
        "141": 11757,
        "142": 11758,
        "143": 11759,
        "144": 11760,
        "150": 11761,
        "152": 11762,
        "154": 11763,
        "156": 11764,
        "300": 12124,
        "310": 11765,
        "311": 11766,
        "312": 11767,
        "313": 11768,
        "314": 11769,
        "315": 11770,
        "320": 11771,
        "321": 11772,
        "322": 11773,
        "323": 11774,
        "324": 11775,
        "330": 11776,
        "331": 11777,
        "332": 11778,
        "333": 11779,
        "334": 11780,
        "335": 11781,
        "340": 11782,
        "341": 11783,
        "342": 11784,
        "343": 11785,
        "344": 11786,
        "345": 11787,
        "350": 11788,
        "360": 11789,
        "361": 11790,
        "362": 11791,
        "363": 11792,
        "364": 11793,
        "365": 11794,
        "401": 11795,
        "402": 11796,
        "410": 11797,
        "411": 11798,
        "412": 12202,
        "413": 11800,
        "414": 11801,
        "430": 11802,
        "431": 11803,
        "433": 11804,
        "440": 11805,
        "441": 11806,
        "442": 11807,
        "442": 12533,
        "450": 11808,
        "451": 11809,
        "452": 11810,
        "453": 11811,
        "454": 11812,
        "455": 11813,
        "456": 11814,
        "457": 11815,
        "460": 11816,
        "470": 11817,
        "471": 11818,
        "472": 11819,
        "473": 11820,
        "480": 11821,
        "490": 11822,
        "500": 11823,
        "510": 11824,
        "511": 12205,
        "512": 11826,
        "514": 11827,
        "515": 11828,
        "516": 11829,
        "517": 11830,
        "518": 11831,
        "520": 11832,
        "521": 11833,
        "522": 11834,
        "523": 11835,
        "524": 11836,
        "525": 12234,
        "526": 11838,
        "527": 11839,
        "528": 11840,
        "530": 11841,
        "531": 11842,
        "532": 11843,
        "533": 11844,
        "534": 11845,
        "540": 11846,
        "541": 11847,
        "542": 11848,
        "543": 11849,
        "544": 11850,
        "545": 11851,
        "546": 11852,
        "600": 11853,
        "610": 11854,
        "611": 11855,
        "612": 11856,
        "613": 11857,
        "614": 11858,
        "620": 11859,
        "621": 11860,
        "622": 11861,
        "623": 11862,
        "625": 11863,
        "630": 11864,
        "631": 11865,
        "632": 11866,
        "633": 11867,
        "634": 11868,
        "635": 11869,
        "640": 11870,
        "641": 11871,
        "642": 11872,
        "643": 11873,
        "650": 11874,
        "651": 11875,
        "652": 11876,
        "653": 11877,
        "654": 11878,
        "660": 11879,
        "670": 11880,
        "680": 11881,
        "700": 12157,
        "710": 11882,
        "720": 11883,
        "910": 11884}

# Used during initialization before login is enabled
def eprint(*args, **kwargs):
    print(*args, file=sys.stderr, **kwargs)

class AMIE2JIRA():
    def __init__(self):

        # Load configuration file
        self.config = ConfigParser(allow_no_value=True)
        try:
            self.config.read('conf/config.ini')
        except IOError as e:
            eprint('Error "{}" reading config={}'.format(e, config_path))
            sys.exit(1)

        # Get each section of the config file and give it a friendly name.
        try:
            self.site_config = self.config['XSEDE']
        except ValueError as e:
            eprint('Error "{}" parsing config={}'.format(e, config_path))
            sys.exit(1)

        self.site_name=self.site_config['site_name']
        self.amie_url=self.site_config['amie_url']
        self.api_key=self.site_config['api_key']
        self.jira_url = self.site_config['jira_url']
        self.jira_key = self.site_config['jira_key']
        self.no_post = self.site_config['no_post']
        self.no_npc = self.site_config['no_npc']

        if not self.site_name:
            eprint('Config is missing site_name')
            sys.exit(1)

        if not self.amie_url:
            eprint('Config is missing amie_url')
            sys.exit(1)

        if not self.api_key:
            eprint('Config is missing api_key')
            sys.exit(1)

        if not self.jira_url:
            eprint('Config is missing jira_url')
            sys.exit(1)

        if not self.jira_key:
            eprint('Config is missing jira_key')
            sys.exit(1)

# These clients all use the default value for the base URL, which is
# https://amieclient.xsede.org/v0.10/





    def Setup(self):
        # Initialize log level from arguments, or config file, or default to WARNING
        #loglevel_str = (self.args.log or self.config.get('LOG_LEVEL', 'INFO')).upper()
        loglevel_str = 'INFO'
        loglevel_num = getattr(logging, loglevel_str, None)
        self.logger = logging.getLogger('CronLog')
        self.logger.setLevel(loglevel_num)
        self.formatter = logging.Formatter(fmt='%(asctime)s.%(msecs)03d %(levelname)s %(message)s', \
                                           datefmt='%Y/%m/%d %H:%M:%S')
        self.LOG_FILE = self.site_config.get('LOG_FILE', 'var/xsede-oauth-mapfile.log')
        self.handler = logging.handlers.TimedRotatingFileHandler(self.LOG_FILE, \
            when='W6', backupCount=999, utc=True)
        self.handler.setFormatter(self.formatter)
        self.logger.addHandler(self.handler)

        signal.signal(signal.SIGINT, self.exit_signal)
        signal.signal(signal.SIGTERM, self.exit_signal)

        self.logger.critical('Starting program={}, pid={}, uid={}({})'.format(os.path.basename(__file__), os.getpid(), os.geteuid(), pwd.getpwuid(os.geteuid()).pw_name))

        self.today = time.strftime('%F', time.localtime())
        self.logger.info('Instantiating amie client {} {} {}'.format(self.site_name, self.amie_url, self.api_key))
        self.ecss_client = AMIEClient(site_name=self.site_name,
                                      amie_url=self.amie_url,
                                      api_key=self.api_key)

    def exit_signal(self, signum, frame):
        self.logger.critical('Caught signal={}({}), exiting with rc={}'.format(signum, signal.Signals(signum).name, signum))
        sys.exit(signum)

    def exit(self, rc):
        if rc:
            self.logger.error('Exiting with rc={}'.format(rc))
        sys.exit(rc)

    def process_packets(self):
        for packet in self.packets:
            #We're only looking to process RPCs
            packet_type = packet.packet_type
            self.logger.info('Found packet of type {}'.format(packet_type))
            if packet_type == "request_project_create":
                self.create_epic(packet)
                continue
            else:
                if packet_type == "data_project_create":
            #print("DATA_PROJECT_CREATE")
                    itc=packet.reply_packet()
                    itc.StatusCode = 'Success'
                    itc.DetailCode = '1'
                    itc.Message = 'OK'
                    if not itc.missing_attributes():
                        self.ecss_client.send_packet(itc)
                    else:
                        self.logger.info('ITC missing {}'.format(itc.missin_attributes()))

                if packet_type == "request_account_create":
            #print("REQUEST_ACCOUNT_CREATE")
                    self.ecss_client.set_packet_client_state(packet,"completed")
                continue

    def create_epic(self, packet):
        #Request Type (customfield_12029) has enumerated allowed values, but
        #AMIE values might not exactly match, so we fuzzy match here
        RequestTypeList = ["New", "Renewal", "Supplemental", "Justification"]
        RequestType = packet.RequestType.capitalize()
        if RequestType not in ["New", "Renewal", "Supplemental", "Justification"]:
           highest = process.extractOne(RequestType,RequestTypeList)
           RequestType = highest[0]
           self.logger.info('RequestType chosen as {} for {}'.format((RequestType, packet.RequestType)))
        if packet.PfosNumber not in FoS.keys():
            fieldofscience = ""
        else:
            fieldofscience = str(FoS[packet.PfosNumber])
        if packet.BoardType not in  ["XRAC", "Startup", "In-House", "Industry", "TRAC", "Research"]:
            requestmechanism = ""
        else:
            requestmechanism = packet.BoardType

        epic = {
        "fields": {
           "project":
           {
              "key": "ECSS3"
           },
           "summary": packet.ProjectTitle,
           "issuetype": {
              "name": "Epic"
           },
           "customfield_10505" : packet.GrantNumber,
           "customfield_12020" : packet.StartDate.strftime('%F'),
           "customfield_12021" : packet.EndDate.strftime('%F'),
           "customfield_12025" : packet.PiFirstName+" "+packet.PiLastName,
           "customfield_12026" : packet.PiEmail,
           "customfield_12027" : packet.PiOrganization,
           "customfield_12028" : {
               "value": requestmechanism
           },
           "customfield_12029" : {
               "value": RequestType
           },
           "customfield_12030" : {
               "id": ""
           },
           "customfield_12031" : packet.GrantNumber,
           "customfield_12034" : packet.Abstract,
           "customfield_12215" : "https://xras-admin.xsede.org/search_all?utf8=%E2%9C%93&q="+packet.GrantNumber+"&button=",
           #Request Date could be timestamp of RPC packet, but there's no way to
           #get that currently from the AMIE API.
           # "customfield_12019" : packet timestamp
           "customfield_12019" : self.today,
           "assignee" : {"name":"mbland"}
           }
        }

        self.logger.debug('Epic Json {}'.format((json.dumps(epic))))

        jira_headers = {'Authorization': 'Basic '+self.jira_key}
        if not self.no_post:
            r = requests.post(self.jira_url, headers=jira_headers, json=epic)
            if not r.ok:
                self.logger.info('Error in Jira Response {}'.format((r)))
                #continue
                return
        else:
            self.logger.info('Configured not to post to JIRA')
            #continue
            return

        jira_issue_id = r.json()['key']
        jira_json = json.dumps(r.json())
        self.logger.debug('Jira Response Json {}'.format((jira_json)))

        try: 
            self.ecss_client.set_packet_client_json(packet, jira_json)
        except Exception as e:
            self.logger.info('Error "{}" setting client_json {}'.format(e, jira_json))
        self.send_npc(packet)
        return

    def send_npc(self, packet):
        npc = packet.reply_packet()
        #use X-PORTAL login from SiteLoginList for PiPersonID and PiRemoteSiteLogin, as PiRequestedLoginList might be empty
        PiPersonID = ""
        for siteperson in packet.SitePersonId:
            if siteperson["Site"] == "X-PORTAL":
                PiPersonID = siteperson["PersonID"]
        if PiPersonID:
            npc.PiPersonID = PiPersonID
            npc.PiRemoteSiteLogin = PiPersonID
            npc.ProjectID=packet.GrantNumber
        if not npc.missing_attributes():
            self.logger.info('Sending NPC for {}:PiPersonID {} PiRemoteSiteLogin {} ProjectID {}'.format((packet.packet_id, PiPersonID, PiPersonID, packet.GrantNumber)))
            if not self.no_npc:
                self.ecss_client.send_packet(npc)        
                return
            else:
                self.logger.info('Configured not to send NPC')
                #continue
                return
        else:
            self.logger.info('Cannot send NPC for {}: missing {}'.format((packet.packet_id, npc.missing_attributes())))
            return


    def AMIE2JIRA(self):
        """
        Query for packets and create JIRA epics
        """
        try: 
            self.packets = self.ecss_client.list_packets().packets
        except Exception as e:
            self.logger.critical('Error "{}" getting packets'.format(e))
            sys.exit(1)
        self.logger.info('Retrieved {} packets'.format(len(self.packets)))
        self.process_packets()


        return(1)

if __name__ == '__main__':
    program = AMIE2JIRA()
    rc = program.Setup()
    rc = program.AMIE2JIRA()
    program.exit(rc)
