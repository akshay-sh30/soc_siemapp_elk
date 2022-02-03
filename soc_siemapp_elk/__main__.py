import sys
import os
import importlib
import imp
import argparse
import logging
import logging.handlers
import json
import glob
import ssl
import socket
from pkg_resources import resource_filename as pkgrs
from elasticsearch import Elasticsearch
from . import Client, Index, BaseUsecase


logger = logging.getLogger("soc.siemapp.elk.__main__")


class Config:
    """Configuration file handler.
    """

    # Elasticsearch client configuration.
    # No default fields (JSON-deserialized block.)
    default_elasticsearch = {
        "hosts": [
            {"hosts": "127.0.0.1", "port": 9200}
        ]
    }

    # SSL configuration.
    # Fields:
    # - ca_file: path to PEM
    default_ssl = None

    # Usecases configuration.
    # - index: write-back index
    # - path: usecases source directory
    default_usecases = {
        "path": "usecases.d",
        "index": "xlm_alerting",
        "mapping": {
            "mappings": {
                "properties": {
                    "@timestamp":  {"type": "date"},
                    "name":        {"type": "keyword"},
                    "human_time":  {"type": "text"},
                    "attacker_ip": {"type": "ip"},
                    "target_ip":   {"type": "ip"},
                    "target_user": {"type": "text"},
                    "alert_desc":  {"type": "text"}
                }
            }
        }
    }

    # SOC link configuration.
    # - host: SOC IP address
    # - port: SOC port.
    default_notify = {
        "host": "127.0.0.1",
        "port": 514
    }

    def __init__(self, path):
        self.logger = logging.getLogger("soc.siemapp.elk.__main__.Config")
        self.logger.info("loading configuration from '{}'".format(path))
        with open(path, 'r') as fd:
            self.jsdata = json.load(fd)
        # Extract config and setup default if required.
        self.elasticsearch = self.jsdata.get("elasticsearch", self.default_elasticsearch)
        self.ssl = self.jsdata.get("ssl", self.default_ssl)
        self.usecases = self.jsdata.get("usecases", self.default_usecases)
        self.notify = self.jsdata.get("notify", self.default_notify)


def prepare(args):
    """Initialize tool context.
    """
    logger.info("initializing")
    cfg = Config(args.config)
    if cfg.ssl is not None:
        logger.info("setting-up SSL context ('ssl' block provided in configuration)")
        ssl_context = ssl.create_default_context(cafile=cfg.ssl["ca_file"])
        logger.info("injecting SSL context in Elasticsearch configuration")
        cfg.elasticsearch["ssl_context"] = ssl_context
    logger.info("creating Elasticsearch client instance")
    es = Elasticsearch(**cfg.elasticsearch)
    client = Client(es, index=cfg.usecases["index"], mapping=cfg.usecases["mapping"], noindex=args.noindex)
    return (cfg, client)


def send_syslog(payload, host, port):
    """Send the processed alert to the EyeSight / ArcSight connector.

    Arguments:
        payload (str): Alert content.
    """
    logger.info("sending alert: {alert} -> {host}:{port}".format(alert=str(payload), host=host, port=port))
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.sendto(payload.encode(), (host, port))
    except Exception as error:
        logger.warning("cannot send alert: {err}".format(err=str(error)))


def command_run(args):
    cfg, client = prepare(args)
    uc_file = os.path.join(cfg.usecases["path"], "{}.py".format(args.usecase))
    uc_name = args.usecase.split(" ")[0]
    if sys.version_info[0] == 2:
        logger.info("running Python2.X - importing UC module using 'imp.load_source'")
        uc = imp.load_source("soc.siemapp.elk.usecases.{}".format(uc_name), uc_file).Usecase()
    else:
        logger.info("running Python3.X - importing UC module using 'importlib.machinery'")
        uc = importlib.machinery.SourceFileLoader("soc.siemapp.elk.usecases.{}".format(uc_name), uc_file).load_module().Usecase()
    # Run usecase and fetch results.
    results = [r for r in uc.results()]
    # Manage results.
    if args.nofilter is True or args.noindex is True:
        logger.warning("thresholds filtering is disabled")
        alerts = results
    else:
        alerts = [r for r in uc.filter_thresholds(results)]
    for alert in alerts:
        if args.noindex is False:
            alert.index()
        if args.dump is True:
            print(alert.format_syslog())
        if args.notify is True:
            send_syslog(payload=alert.format_syslog(), host=cfg.notify["host"], port=cfg.notify["port"])


def command_find(args):
    cfg, client = prepare(args)
    uc_file = os.path.join(cfg.usecases["path"], "{}.py".format(args.usecase))
    uc_name = args.usecase.split(" ")[0]
    uc = importlib.machinery.SourceFileLoader("soc.siemapp.elk.usecases.{}".format(uc_name), uc_file).load_module().Usecase()
    for alert in uc.find():
        print(alert.format_syslog())


def command_list(args):

    def list_usecases(cfg, client):
        for uc_file in glob.glob(os.path.join(cfg.usecases["path"], "*.py")):
            print(os.path.basename(uc_file.split(".py")[0]))

    cfg, client = prepare(args)
    objects = {
        "usecases": list_usecases
    }
    if args.object in objects:
        objects[args.object](cfg, client)
    else:
        for k, v in objects.items():
            print(k)


def main():
    # Arguments parser.
    parser = argparse.ArgumentParser(description="SOC ELK alerting tool")
    # Globals arguments.
    parser.add_argument("--config", type=str, default=pkgrs(__name__, "static/config.json"), help="Tool configuration file")
    parser.add_argument("--logfile", type=str, default=None)
    parser.add_argument("--noindex", dest="noindex", action="store_const", const=True, default=False, help="Do not create nor use write-back index")
    # Commands sub-parsers.
    sp = parser.add_subparsers(dest="command", help="Command")
    sp.required = True
    # 'list' command.
    p_list = sp.add_parser("list", help="List a given object type.")
    p_list.set_defaults(func=command_list)
    p_list.add_argument("object", type=str, default="", help="Object name")
    # 'run' command.
    p_run = sp.add_parser("run", help="Run a given usecase")
    p_run.set_defaults(func=command_run)
    p_run.add_argument("usecase", type=str, help="Usecase's script name (without path nor extension)")
    p_run.add_argument("--nofilter", dest="nofilter", action="store_const", const=True, default=False)
    p_run.add_argument("--dump", dest="dump", action="store_const", const=True, default=False)
    p_run.add_argument("--notify", dest="notify", action="store_const", const=True, default=False)
    # 'find' command.
    p_run = sp.add_parser("find", help="Find a usecase alerts")
    p_run.set_defaults(func=command_find)
    p_run.add_argument("usecase", type=str, help="Usecase's script name (without path nor extension)")
    # Parse arguments.
    args = parser.parse_args()
    # Logging.
    logger = logging.getLogger("soc.siemapp.elk")
    logger.propagate = False
    logger.setLevel(logging.INFO)
    logger.addHandler(logging.StreamHandler())
    if args.logfile is not None:
        logger.addHandler(logging.handlers.RotatingFileHandler(filename=args.logfile, mode='a', maxBytes=1000000, backupCount=0))
    # Set log format on all handlers.
    logformatter = logging.Formatter("%(asctime)s - %(name)s - %(levelname)s - %(message)s")
    for handler in logger.handlers:
        handler.setFormatter(logformatter)
    # Execution.
    try:
        args.func(args)
    except Exception as error:
        print("Error: {err}".format(err=str(error)))
        logger.exception(error)
        raise



if __name__ == "__main__":
    main()
