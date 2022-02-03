import sys
import logging
import json
import jsonschema
import datetime


CLIENT = None


class Index:
    """Alert's write-back index.

    All raised alerts (== sent alerts) should be written back.
    """
    def __init__(self, name, mapping):
        """Initializes object instance.

        Arguments:
            name (str): index name.
            mapping (dict): index mapping.
        """
        self.logger = logging.getLogger("soc.siemapp.elk.Index")
        self.client = self.client = getattr(sys.modules[__name__], "CLIENT")
        self.name = name
        self.mapping = mapping

    def create(self):
        """Create or re-create the underling Elasticsearch index.
        """
        self.logger.info("creating write-back index '{}'".format(self.name))
        self.client.es.indices.create(index=self.name, ignore=[400, ], body=self.mapping)


class Client:
    def __init__(self, es, index, mapping, noindex=False):
        """Initializes a client instance.

        Arguments:
            es (object): Elasticsearch API client instance.
            index (str): Results index name (will be (re)created on the fly).
            mapping (dict): Results index mapping.
        """
        self.logger = logging.getLogger("soc.siemapp.elk.Client")
        self.es = es
        setattr(sys.modules[__name__], "CLIENT", self)
        # ---
        self.index = Index(name=index, mapping=mapping)
        if noindex is False:
            self.index.create()
        else:
            self.logger.info("bypassing write-back index creation (noindex='{}')".format(noindex))


class Alert:
    def __init__(self, name, human_time, attacker_ip="0.0.0.0", target_ip="0.0.0.0", target_user="", alert_desc="", extra_values=[]):
        """Initializes the instance.

        Arguments:
            name (str): Underlying usecase name.
            human_time (str): Alert timestamp in Excellium format.
            attacker_ip (str, optional): Attacker IP address.
            target_ip (str, optional): Target IP address.
            target_user (str, optional): Target user name.
            alert_desc (str, optional): Subsidiary data.
        """
        self.logger = logging.getLogger("soc.siemapp.elk.Alert({})".format(name))
        self.client = getattr(sys.modules[__name__], "CLIENT")
        self.extra_values = extra_values
        self.payload = {
            "@timestamp":  datetime.datetime.utcnow().isoformat(),
            "name":        name,
            "human_time":  human_time,
            "attacker_ip": attacker_ip,
            "target_ip":   target_ip,
            "target_user": target_user,
            "alert_desc":  alert_desc
        }

    def index(self):
        self.logger.info("indexing alert")
        self.client.es.index(index=self.client.index.name, body=self.payload)

    def format_syslog(self):
        raw = "<133>[qradar-offense] [{alert_desc}] [{human_time}] [{attacker_ip}] [{target_ip}] [{target_user}] [{name}]".format_map(self.payload)
        for value in self.extra_values:
            raw = "{} [{}]".format(raw, value)
        return raw


class BaseUsecase:
    def __init__(self, name, query_index, query_body, th_gte=0, th_lte="now", th_fields=[], extra_values=[]):
        """Initializes a BaseUsecase and derivates instance.

        Arguments:
            name (str): Use case name.
            query_index (str): Elasticsearch DSL query's index.
            query_body (dict): Elasticsearch DSL query's body.
            th_gte (str, int, optional): Threshold time boundary (from past).
            th_lte (str, int, optional): Threshold time boundary (to now).
            th_fields (list, optional): Threshold fields.
            extra_values (list, optional): Extra values to add to the generated alert.
        """
        self.logger = logging.getLogger("soc.siemapp.elk.Usecase({})".format(name.split(' ')[0]))
        self.client = getattr(sys.modules[__name__], "CLIENT")
        self.name = name
        self.query_index = query_index
        self.query_body = query_body
        self.th_gte = th_gte
        self.th_lte = th_lte
        self.th_fields = th_fields
        self.extra_values = extra_values
        self.response = None

    def find(self, gte="now-1d/d", lte="now"):
        """Search alerts raised (indexed) by this usecase.

        Arguments:
            gte (string, int, optional): Start time boundary (from past).
            lte (string, int, optional): End time boundary (to now).
        """
        body = {
            "query": {
                "bool": {
                    "filter": [
                        {
                            "term": {"name": self.name}
                        },
                        {
                            "range": {"@timestamp": {"gte": gte, "lte": lte}}
                        }
                    ]
                }
            }
        }
        self.logger.info("running write-back index search")
        response = self.client.es.search(index=self.client.index.name, body=body)
        for hit in [h["_source"] for h in response["hits"]["hits"]]:
            yield Alert(name=hit["name"],
                        human_time=hit["human_time"],
                        attacker_ip=hit["attacker_ip"],
                        target_ip=hit["target_ip"],
                        target_user=hit["target_user"],
                        alert_desc=hit["alert_desc"],
                        extra_values=self.extra_values)

    def run(self):
        """Run usecase's query on Elassticsearch.
        """
        self.logger.info("running search")
        self.response = self.client.es.search(index=self.query_index, body=self.query_body)

    def filter_thresholds(self, results):
        """Returns the new alerts between the past batch and the new one (`results`).

        The difference is calculated using the usecase's `th_fields`, `th_gte` and `th_lte` values.
        Yields any alert which cannot be matched with the historicl results set.

        Arguments:
            results (list of alerts): List of alerts (new batch).
        """
        self.logger.info("filtering results set by thresholds")
        past_results = [r for r in self.find(gte=self.th_gte, lte=self.th_lte)]
        self.logger.info("comparing new result batch ({} alerts) with past batch ({} alerts)".format(len(results), len(past_results)))
        for alert in results:
            has_breaked = False
            for past_alert in past_results:
                matched = 0
                if len(self.th_fields) > 0:
                    for field in self.th_fields:
                        if alert.payload[field] == past_alert.payload[field]:
                            matched += 1
                    if matched == len(self.th_fields):
                        self.logger.info("threshold match found, discarding one")
                        has_breaked = True
                        break
            if has_breaked is False:
                yield alert
