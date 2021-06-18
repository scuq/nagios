#!/usr/bin/python
# coding=utf-8
# -*- coding: <utf-8> -*-
# vim: set fileencoding=<utf-8> :
"""
notify_webhook
"""

ME="notify_webhook"

import sys
import requests
import json
import os
from optparse import OptionParser # pylint: disable=deprecated-module
import logging
import time

from logging.handlers import SysLogHandler

logger = logging.getLogger(ME)
logger.setLevel(logging.INFO)
#hdlr = logging.StreamHandler(sys.stderr)
hdlr = logging.handlers.SysLogHandler(address = '/dev/log')
formatter = logging.Formatter('[%(asctime)s] [%(levelname)-8s] \
                               [%(filename)s:%(lineno)4d] %(message)s',
                               datefmt="%Y-%m-%d %H:%M:%S")
hdlr.setFormatter(formatter)
logger.addHandler(hdlr)
logger.propagate = False


class NotificationMode():
    """
    notification mode, "host" or "service"
    """
    host = 0
    service = 1

class WebHookNotification():
    """
    WebHookNotification
    """
    def __init__(self, webhook_endpoint, _logger=logger):

        self.webhookEndpoint = webhook_endpoint
        self.logger = _logger
        self.message = {}
        self.message["subject"]=""
        self.message["plainText"]=""
        self.message["markdownText"]=""
        self.message["link"]=""

    def prepareMessage(self,mode,link_base_url,nagios_env_vars):
        """
        WebHookNotification - prepareMessage
        """
        eyecatcher=""


        if mode == NotificationMode.host:
            downtimeNotification = False
            downtimeString=""
            logger.info("NAGIOS_HOSTSTATE: %s", nagios_env_vars["NAGIOS_HOSTSTATE"])
            logger.info("NAGIOS_HOSTSTATE: %s", str(nagios_env_vars))


            if nagios_env_vars["NAGIOS_HOSTSTATE"] == "DOWN":
                eyecatcher="❌"
            elif nagios_env_vars["NAGIOS_HOSTSTATE"] == "UP":
                eyecatcher="✅"
            elif nagios_env_vars["NAGIOS_HOSTSTATE"] == "UNREACHABLE":
                eyecatcher="❗"

            if "NAGIOS_NOTIFICATIONTYPE" in nagios_env_vars:
                if nagios_env_vars["NAGIOS_NOTIFICATIONTYPE"] == "DOWNTIMESTART":
                    eyecatcher="💤"
                    downtimeNotification = True
                    downtimeString="downtime scheduled"
                if nagios_env_vars["NAGIOS_NOTIFICATIONTYPE"] == "DOWNTIMECANCELLED":
                    eyecatcher="😳"
                    downtimeNotification = True
                    downtimeString="scheduled downtime canceled"
                if nagios_env_vars["NAGIOS_NOTIFICATIONTYPE"] == "DOWNTIMEEND":
                    eyecatcher="😳"
                    downtimeNotification = True
                    downtimeString="scheduled downtime expired"

            if downtimeNotification:
                subject = "{} Host: `{}` is `{}` - {}".format(eyecatcher,nagios_env_vars["NAGIOS_HOSTNAME"], nagios_env_vars["NAGIOS_HOSTSTATE"],downtimeString)
            else:
                subject = "{} Host: `{}` is `{}`".format(eyecatcher,nagios_env_vars["NAGIOS_HOSTNAME"], nagios_env_vars["NAGIOS_HOSTSTATE"])

            description = "Checkoutput: `{}`".format(nagios_env_vars["NAGIOS_HOSTOUTPUT"])
            link = "{}{}".format(link_base_url,nagios_env_vars["NAGIOS_HOSTNAME"])

        elif mode == NotificationMode.service:
            downtimeNotification = False
            downtimeString=""
            logger.info("NAGIOS_SERVICESTATE: %s", nagios_env_vars["NAGIOS_SERVICESTATE"])
            logger.info("NAGIOS_HOSTSTATE: %s", str(nagios_env_vars))
            if nagios_env_vars["NAGIOS_SERVICESTATE"] == "CRITICAL":
                eyecatcher="❌"
            elif nagios_env_vars["NAGIOS_SERVICESTATE"] == "OK":
                eyecatcher="✅"
            elif nagios_env_vars["NAGIOS_SERVICESTATE"] == "WARNING":
                eyecatcher="⚠️"
            elif nagios_env_vars["NAGIOS_SERVICESTATE"] == "UNKNOWN":
                eyecatcher="❓"


            if "NAGIOS_NOTIFICATIONTYPE" in nagios_env_vars:
                if nagios_env_vars["NAGIOS_NOTIFICATIONTYPE"] == "DOWNTIMESTART":
                    eyecatcher="💤"
                    downtimeNotification = True
                    downtimeString="downtime scheduled"
                if nagios_env_vars["NAGIOS_NOTIFICATIONTYPE"] == "DOWNTIMECANCELLED":
                    eyecatcher="😳"
                    downtimeNotification = True
                    downtimeString="scheduled downtime canceled"
                if nagios_env_vars["NAGIOS_NOTIFICATIONTYPE"] == "DOWNTIMEEND":
                    eyecatcher="😳"
                    downtimeNotification = True
                    downtimeString="scheduled downtime expired"

            if downtimeNotification:
                subject = "{} Service `{}` of Host: `{}` is `{}` - {}".format(
                        eyecatcher,
                        nagios_env_vars["NAGIOS_SERVICEDESC"],
                        nagios_env_vars["NAGIOS_HOSTNAME"],
                        nagios_env_vars["NAGIOS_SERVICESTATE"],
                        downtimeString
                    )
            else:
                subject = "{} Service `{}` of Host: `{}` is `{}`".format(
                        eyecatcher,
                        nagios_env_vars["NAGIOS_SERVICEDESC"],
                        nagios_env_vars["NAGIOS_HOSTNAME"],
                        nagios_env_vars["NAGIOS_SERVICESTATE"]
                    )
            description = "Checkoutput: `{}`\n{}".format(nagios_env_vars["NAGIOS_SERVICEOUTPUT"],nagios_env_vars["NAGIOS_LONGSERVICEOUTPUT"])
            link = "{}{}".format(link_base_url,nagios_env_vars["NAGIOS_HOSTNAME"])

        self.message["subject"] = subject
        self.message["description"] = description
        self.message["link"] = link

        return

    def send(self):
        """
        WebHookNotification - send
        """
        return

    def printmessage(self):
        """
        WebHookNotification - send
        """
        print (self.message)
        return

class WebHookNotificationCiscoWebex(WebHookNotification):
    """
    Cisco Webex (Teams) WebHookNotification
    goto https://apphub.webex.com/applications/incoming-webhooks-cisco-systems-38054
    and register an incoming webhook url
    """
    def send(self):
        """
        WebHookNotification - send
        """
        _message = {}
        _message["markdown"] = "Event:\n{}\n{}\nLink: {}".format(self.message["subject"],self.message["description"],self.message["link"])
        self.logger.info("WebHookNotificationCiscoWebex - sending message")

        response = requests.post(self.webhookEndpoint["url"],
                                 data=json.dumps(_message),
                                 allow_redirects=False,
                                 headers=self.webhookEndpoint["headers"],
                                 verify=self.webhookEndpoint["sslVerify"],
                                 proxies=self.webhookEndpoint["proxy"]
                                )
        self.logger.info(response.text)
        cnt = 0
        while "Retry-After" in response.headers:
            cnt += 1
            if cnt >= 5:
                break
            self.logger.info("got Retry-After, waiting %s",str(int(response.headers["Retry-After"])+2))
            time.sleep(int(response.headers["Retry-After"])+2)
            response = requests.post(self.webhookEndpoint["url"],
                                    data=json.dumps(_message),
                                    allow_redirects=False,
                                    headers=self.webhookEndpoint["headers"],
                                    verify=self.webhookEndpoint["sslVerify"],
                                    proxies=self.webhookEndpoint["proxy"]
                                    )
            self.logger.info(response.headers)
        self.logger.info(response.text)

        return

class WebHookNotificationDiscord(WebHookNotification):
    """
    Discord WebHookNotification
    goto https://support.discord.com/hc/en-us/articles/228383668-Intro-to-Webhooks
    """
    def send(self):
        """
        WebHookNotification - send
        """
        logger.error("not implemented.")

class WebHookNotificationMattermost(WebHookNotification):
    """
    Mattermost WebHookNotification
    goto https://docs.mattermost.com/developer/webhooks-incoming.html
    """
    def send(self):
        """
        WebHookNotification - send
        """
        logger.error("not implemented.")

class WebHookNotificationSlack(WebHookNotification):
    """
    Slack WebHookNotification
    goto https://api.slack.com/messaging/webhooks
    """
    def send(self):
        """
        WebHookNotification - send
        """
        logger.error("not implemented.")



def getNagiosEnvVars():
    """
    Read and return ENV variables starting with "NAGIOS"
    """
    nagiosEnvVars = {}
    nagiosEnvVarsFound = False

    for var, value in os.environ.items():
        if var.startswith("NAGIOS"):
            nagiosEnvVars[var]=value

    if len(nagiosEnvVars.keys()) > 0:
        nagiosEnvVarsFound = True

    return nagiosEnvVarsFound, nagiosEnvVars

def main():
    """
    main
    """
    parser = OptionParser()
    parser.add_option("-u", "--webhook-url", dest="webhook_url", help="webhook url")
    parser.add_option("-b", "--link-base-url", dest="link_base_url", help="base url for link in message")
    parser.add_option("", "--proxy", dest="http_proxy", help="http proxy e.g. http://127.0.0.1:8080")
    parser.add_option("", "--insecure", action="store_true", dest="ssl_insecure", default=False, help="don't verify ssl certificates")
    parser.add_option("", "--host", action="store_true", dest="host", default=False, help="use as host notification command, default is service")
    parser.add_option("", "--use-ciscowebex", action="store_true", dest="use_ciscowebex", default=False, help="send to cisco webex incoming webhook")
    parser.add_option("", "--use-discord", action="store_true", dest="use_discord", default=False, help="send to discord incoming webhook")
    parser.add_option("", "--use-mattermost", action="store_true", dest="use_mattermost", default=False, help="send to mattermost incoming webhook")
    parser.add_option("", "--use-slack", action="store_true", dest="use_slack", default=False, help="send to slack incoming webhook")

    (options, args) = parser.parse_args() # pylint: disable=unused-variable

    mode = NotificationMode.service
    linkBaseUrl = ""

    webhookEndpoint = {}
    webhookEndpoint["url"] = None
    webhookEndpoint["proxy"] = None
    webhookEndpoint["sslVerify"] = True
    webhookEndpoint["headers"] = {"Accept": "application/json; charset=utf-8",
                       "Content-type": "application/json",
                       "Cache-Control": "no-cache"
                     }

    if options.host:
        mode = NotificationMode.host

    if options.ssl_insecure:
        webhookEndpoint["sslVerify"] = False

    if options.http_proxy:
        webhookEndpoint["proxy"] = options.http_proxy

    if options.link_base_url:
        linkBaseUrl = options.link_base_url

    if not options.webhook_url:
        logger.error("please specify a webhook url")
        sys.exit(1)
    else:
        webhookEndpoint["url"] = options.webhook_url

    nagiosEnvVarsFound, nagiosEnvVars = getNagiosEnvVars()

    if webhookEndpoint["url"] and \
       nagiosEnvVarsFound:
        if options.use_ciscowebex:
            notify = WebHookNotificationCiscoWebex(webhookEndpoint,logger)
            notify.prepareMessage(mode,linkBaseUrl,nagiosEnvVars)
            notify.send()
        elif options.use_discord:
            notify = WebHookNotificationDiscord(webhookEndpoint,logger)
            notify.prepareMessage(mode,linkBaseUrl,nagiosEnvVars)
            notify.send()
        elif options.use_mattermost:
            notify = WebHookNotificationMattermost(webhookEndpoint,logger)
            notify.prepareMessage(mode,linkBaseUrl,nagiosEnvVars)
            notify.send()
        elif options.use_slack:
            notify = WebHookNotificationSlack(webhookEndpoint,logger)
            notify.prepareMessage(mode,linkBaseUrl,nagiosEnvVars)
            notify.send()
        else:
            logger.error("specify your receiving webhook service, see --help")
    else:
        logger.error("no NAGIOS env variables found.")

if __name__ == '__main__':
    main()
