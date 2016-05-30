import requests, json, logging

# Queries the ThreadCrowd API for information on domains and IPs
class ThreatCrowd(object):
    """Queries ThreatCrowd API for domain or ip details
    """
    
    BASE_URL = "https://www.threatcrowd.org/searchApi/v2"
    """ThreatCrowd's base url"""
    
    IP_URL = BASE_URL + "/ip/report/"
    """The api endpoint for IP addresses"""
    
    DOMAIN_URL = BASE_URL + "/domain/report/"
    """The api endpoint for domains"""
    
    LOGGER = logging.getLogger(__name__)
    
    @staticmethod
    def _query(url, data):
        """Retrieve json data from a url, internal use only."""
        try:
            text = requests.get(url, params=data).text
            return json.loads(text)
        except Exception as e:
            ThreatCrowd.LOGGER.warn("Error retrieving data from ThreatCrowd: " + str(e))
            return {'error':str(e)}

    @staticmethod
    def queryDomain(domain):
        """Query ThreatCrowd for details on provided domain
        
            Args:
                domain (str): The domain to query for
            
            Returns (dict): The response from the TC API or, if an error occurred, the dictionary
                will have a key named 'error' with the error message.
        """
        ThreatCrowd.LOGGER.info("Querying ThreatCrowd for domain: " + domain)
        return ThreatCrowd._query(ThreatCrowd.DOMAIN_URL,{"domain":domain})
    
    @staticmethod
    def queryIp(ip):
        """Query ThreatCrowd for details on provided ip
        
            Args:
                ip (str): The ip to query for
            
            Returns (dict): The response from the TC API or, if an error occurred, the dictionary
                will have a key named 'error' with the error message.
        """
        ThreatCrowd.LOGGER.info("Querying ThreatCrowd for ip: " + ip)
        return ThreatCrowd._query(ThreatCrowd.IP_URL,{"ip":ip})
