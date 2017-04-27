# --
# File: elsa_consts.py
#
# Copyright (c) Phantom Cyber Corporation, 2016-2017
#
# This unpublished material is proprietary to Phantom Cyber.
# All rights reserved. The methods and
# techniques described herein are considered trade secrets
# and/or confidential. Reproduction or distribution, in whole
# or in part, is forbidden except by express written permission
# of Phantom Cyber Corporation.
#
# --

ELSA_BASE_URL = "base_url"
ELSA_QUERY_URL = "%s/elsa-query/API/query"
TEST_QUERY = "qryGetSelectFields?type=EVENT&groupType=NO_GROUP"
ELSA_JSON_QUERY_STRING = "query_type"

ELSA_ERR_QUERY = "ELSA query failed"
ELSA_SUCC_QUERY = "ELSA query successful"
ELSA_ERR_QUERY_RETURNED_NO_DATA = "ELSA query did not return any information"
ELSA_ERR_QUERY_RETURNED_INVALID_DATA = "ELSA query results were not able formatted as expected."
ELSA_ERR_FORMAT_QUERY_FAILED = "Failed to correctly format the query using the data provided."
ELSA_ERR_SERVER_CONNECTION = "Connection to server failed"
ELSA_ERR_CONNECTIVITY_TEST = "Connectivity test failed"
ELSA_SUCC_CONNECTIVITY_TEST = "Connectivity test passed"
DEFAULT_CEF_MAP = {"program": "deviceEventCategory",
    "dstport": "destinationPort",
    "dstip": "destinationAddress",
    "srcip": "sourceAddress",
    "srcport": "sourcePort",
    "site": "destinationDnsName",
    "uri": "requestURL",
    "bytesout": "bytesOut"}

CEF_EXCLUDE = [u'', '', "0", u'0', '-']
DATETIME_FORMAT = "%Y-%m-%d %H:%M:%S"
ELSA_JSON_QUERY_TIMEOUT = "query_timeout"
ELSA_DEFAULT_TIMEOUT_SECS = 20
ELSA_QUERY_TIMEOUT_ERR = "Query not completed in the configured time. Please increase the query_timeout value in the asset config and try again."
ELSA_JSON_POLL_HOURS = "poll_hours"
ELSA_JSON_LAST_DATE_TIME = "last_date_time"
ELSA_JSON_TIMEZONE = "timezone"
ELSA_JSON_MAX_CONTAINERS = "max_containers"
ELSA_JSON_FIRST_MAX_CONTAINERS = "first_run_max_events"
ELSA_DEFAULT_MAX_CONTAINERS = 10
ELSA_DEFAULT_POLL_HOURS = 1
CREATE_CONTAINER_RESPONSE = "save_container returns, value: {0}, reason: {1}, id: {2}"
