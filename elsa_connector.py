# --
# File: elsa_connector.py
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

# Phantom imports
import phantom.app as phantom

from phantom.base_connector import BaseConnector
from phantom.action_result import ActionResult

# Imports local to this App
from elsa_consts import *

import requests
import urllib
from datetime import datetime, timedelta
import time
import hashlib
import json
from pytz import timezone
import pytz
import os
import inspect
import re


_container_common = {
    "description": "Container added by Phantom ELSA App",
    "run_automation": False  # Don't run any playbooks, when this artifact is added
}

_artifact_common = {
    "label": "artifact",
    "type": "network",
    "description": "Artifact added by Phantom ELSA App",
    "run_automation": False  # Don't run any playbooks, when this artifact is added
}

requests.packages.urllib3.disable_warnings()


# Define the App Class
class ElsaConnector(BaseConnector):

    ACTION_ID_TEST_CONNECTIVITY = "test_asset_connectivity"
    ACTION_ID_ON_POLL = "on_poll"
    ACTION_ID_RUN_QUERY = "run_query"

    def __init__(self):

        # Call the BaseConnectors init first
        super(ElsaConnector, self).__init__()
        self._state = {}

    def _handle_error_response(self, response, result):

        data = response.text

        if ('application/json' in response.headers.get('Content-Type')) and (data):
            data = data.replace('{', '[').replace('}', ']')

        message = "Status Code: {0}. Data: {1}".format(response.status_code, data if data else 'Not Specified')

        self.debug_print("Rest error: {0}".format(message))

        return result.set_status(phantom.APP_ERROR, message)

    def _load_state(self):

        # get the directory of the class
        dirpath = os.path.dirname(inspect.getfile(self.__class__))
        asset_id = self.get_asset_id()
        self._state_file_path = "{0}/{1}_serialized_data.json".format(dirpath, asset_id)
        try:
            with open(self._state_file_path, 'r') as f:
                in_json = f.read()
                self._state = json.loads(in_json)
        except Exception as e:
            self.debug_print("In _load_state: Exception: {0}".format(str(e)))
            pass
        self.debug_print("Loaded state: ", self._state)
        return phantom.APP_SUCCESS

    def _save_state(self):

        self.debug_print("Saving state: ", self._state)
        if (not self._state_file_path):
            self.debug_print("_state_file_path is None in _save_state")
            return phantom.APP_SUCCESS
        try:
            with open(self._state_file_path, 'w+') as f:
                f.write(json.dumps(self._state))
        except Exception as e:
            self.debug_print("Exception in _save_state", e)
            pass
        return phantom.APP_SUCCESS

    def initialize(self):
        self._load_state()
        return phantom.APP_SUCCESS

    def finalize(self):
        self._save_state()
        return phantom.APP_SUCCESS

    def _make_rest_call(self, action_result, headers={}, data=None, method="post"):

        config = self.get_config()
        query_url = ELSA_QUERY_URL % config["base_url"]

        request_func = getattr(requests, method)

        # handle the error in case the caller specified a non-existant method
        if (not request_func):
            return (action_result.set_status(phantom.APP_ERROR, "API Unsupported method: {0}".format(method)), None)

        if (method == 'delete'):
            headers = dict(headers)
            del(headers['Content-Type'])

        try:
            response = request_func(query_url, data=data if data else None, headers=headers, verify=config["verify_server_cert"])
            self.debug_print("Just after the request_func")
        except Exception as e:
            return (action_result.set_status(phantom.APP_ERROR, "Error connecting to Device: {0}".format(e)), None)

        # The only status code that is success for posts is 200
        if response.status_code != 200:
            self.save_progress("Non-200 error code: " + str(response.status_code))
            return (self._handle_error_response(response, action_result), None)

        if method == "delete":
            return (phantom.APP_SUCCESS, None)

        try:
            # self.debug_print("In rest call, before converting response to JSON: " + str(response.text))
            resp_json = response.json()
            # self.debug_print("In rest call, converted response to JSON: " + str(resp_json))
        except Exception as e:
            return (action_result.set_status(phantom.APP_ERROR, "Error converting response to json"), None)

        return (phantom.APP_SUCCESS, resp_json)

    def _build_auth_string(self):
        config = self.get_config()
        epoch_time = str(int(time.time()))
        username = config["username"]
        apikey = config["apikey"]
        calculated_api_key = hashlib.sha512(epoch_time + apikey).hexdigest()
        auth_string = "ApiKey " + username + ":" + epoch_time + ":" + calculated_api_key
        self.debug_print("Calculated auth_string: " + auth_string)

        return auth_string

    def _format_query(self, full_query_dict):
        config = self.get_config()
        query_url = ELSA_QUERY_URL % config["base_url"]
        try:
            self.debug_print("In the #Format Query# try loop")
            auth_string = self._build_auth_string()
            query_headers = {"Content-Type": "application/x-www-form-urlencoded", "Authorization": auth_string}
            permissions = urllib.quote('{"class_id":{"0":1},"program_id":{"0":1},"node_id":{"0":1},"host_id":{"0":1}}')
            full_query = str(full_query_dict)
            full_query = full_query.replace(" ", "")
            full_query = full_query.replace("'", '"')
            query_json = urllib.quote(full_query)
            body = 'permissions=' + permissions + '&q=' + query_json
            self.debug_print("Just before query - body:" + str(body))
            self.save_progress(phantom.APP_PROG_CONNECTING_TO_ELLIPSES, query_url)

        except Exception as e:
            self.set_status(phantom.APP_ERROR, ELSA_ERR_SERVER_CONNECTION, e)
            self.append_to_message(ELSA_ERR_FORMAT_QUERY_FAILED)
            return self.get_status()

        return query_headers, body

    def _test_connectivity(self, param):

        config = self.get_config()

        action_result = self.add_action_result(ActionResult(param))
        ret_val = self._validate_my_config(action_result)

        self.save_progress("Querying the server to check connectivity")
        test_query_params = {}

        try:
            self.debug_print("In the try loop")
            test_query_params["start"] = self._get_first_start_time()
            test_query_params["limit"] = config["max_containers"]
            test_query_params["end"] = self._get_end_time()
            test_query_params["timeout"] = config[ELSA_JSON_QUERY_TIMEOUT]

            # update test_query_params with remaining items:
            test_query_params.update({"cutoff": "",
                "offset": 0,
                "orderby": "",
                "orderby_dir": "asc",
                "groupby": "",
                "node": "",
                "datasource": "",
                "archive": 0,
                "analytics": 0,
                "nobatch": 0})

            full_query_dict = {"query_string": "class=BRO_CONN", "query_meta_params": test_query_params}

            query_headers, body = self._format_query(full_query_dict)
            ret_val, response = self._make_rest_call(action_result, headers=query_headers, data=body)

            if (phantom.is_fail(ret_val)):
                self.save_progress("Test Connectivity failed")
                return action_result.get_status()

            self.save_progress("Test connectivity Passed")
            # self.debug_print("Length of results value: {0}".format(len(response["results"])))

            action_result.set_status(phantom.APP_SUCCESS)

            return action_result.get_status()

        except Exception as e:
            self.set_status(phantom.APP_ERROR, ELSA_ERR_SERVER_CONNECTION, e)
            self.append_to_message(ELSA_ERR_CONNECTIVITY_TEST)
            return self.get_status()

    def _get_next_start_time(self, last_time):

        config = self.get_config()
        device_tz_string = config[ELSA_JSON_TIMEZONE]
        to_tz = timezone(device_tz_string)

        # get the time string passed into a datetime object
        last_time = datetime.strptime(last_time, DATETIME_FORMAT)
        last_time = last_time.replace(tzinfo=to_tz)

        # add a second to it
        last_time = last_time + timedelta(seconds=1)

        # format it
        return last_time.strftime(DATETIME_FORMAT)

    def _get_first_start_time(self):

        config = self.get_config()

        # Get the poll hours
        poll_hours = config[ELSA_JSON_POLL_HOURS]

        # get the device timezone
        device_tz_string = config[ELSA_JSON_TIMEZONE]
        to_tz = timezone(device_tz_string)

        # get the start time to use, i.e. current - poll hours in UTC
        start_time = datetime.utcnow() - timedelta(hours=poll_hours)
        start_time = start_time.replace(tzinfo=pytz.utc)

        # convert it to the timezone of the device
        to_dt = to_tz.normalize(start_time.astimezone(to_tz))

        return to_dt.strftime(DATETIME_FORMAT)

    def _get_end_time(self):

        config = self.get_config()

        # get the timezone of the device
        device_tz_string = config[ELSA_JSON_TIMEZONE]
        to_tz = timezone(device_tz_string)

        # get the start time to use, i.e. current - poll hours in UTC
        start_time = datetime.utcnow().replace(tzinfo=pytz.utc)

        # convert it to the timezone of the device
        to_dt = to_tz.normalize(start_time.astimezone(to_tz))

        return to_dt.strftime(DATETIME_FORMAT)

    def _get_query_params(self, param):

        # function to separate on poll and poll now
        config = self.get_config()
        limit = config["max_containers"]
        query_params = dict()
        last_time = self._state.get(ELSA_JSON_LAST_DATE_TIME)

        if self.is_poll_now():
            limit = param.get("container_count", 100)
            query_params["start"] = self._get_first_start_time()
        elif (self._state.get('first_run', True)):
            self._state['first_run'] = False
            limit = config.get("first_run_max_events", 100)
            query_params["start"] = self._get_first_start_time()
        elif (last_time):
            query_params["start"] = str(last_time)
        else:
            query_params["start"] = self._get_first_start_time()

        query_params["timeout"] = config[ELSA_JSON_QUERY_TIMEOUT]
        query_params["limit"] = limit
        query_params["end"] = self._get_end_time()

        if (not self.is_poll_now()):
            self._state[ELSA_JSON_LAST_DATE_TIME] = query_params["end"]

        return query_params

    def _validate_my_config(self, action_result):

        config = self.get_config()

        # validate the query timeout
        query_timeout = config.get(ELSA_JSON_QUERY_TIMEOUT, int(ELSA_DEFAULT_TIMEOUT_SECS))

        try:
            query_timeout = int(query_timeout)
        except Exception as e:
            return action_result.set_status(phantom.APP_ERROR, "Invalid query timeout value", e)

        if (query_timeout < int(ELSA_DEFAULT_TIMEOUT_SECS)):
            return action_result.set_status(phantom.APP_ERROR,
                    "Please specify a query timeout value greater or equal to {0}".format(ELSA_DEFAULT_TIMEOUT_SECS))

        config[ELSA_JSON_QUERY_TIMEOUT] = query_timeout

        poll_hours = config.get(ELSA_JSON_POLL_HOURS, int(ELSA_DEFAULT_POLL_HOURS))

        try:
            poll_hours = int(poll_hours)
        except Exception as e:
            return action_result.set_status(phantom.APP_ERROR, "Invalid Poll Hours value", e)

        if (poll_hours < int(ELSA_DEFAULT_POLL_HOURS)):
            return action_result.set_status(phantom.APP_ERROR,
                    "Please specify the poll hours interval value greater than {0}".format(ELSA_DEFAULT_POLL_HOURS))

        config[ELSA_JSON_POLL_HOURS] = poll_hours

        first_max_containers = config.get(ELSA_JSON_FIRST_MAX_CONTAINERS, int(ELSA_DEFAULT_MAX_CONTAINERS))

        try:
            first_max_containers = int(first_max_containers)
        except Exception as e:
            return action_result.set_status(phantom.APP_ERROR, "Invalid {0} value".format(ELSA_JSON_FIRST_MAX_CONTAINERS), e)

        if (first_max_containers < int(ELSA_DEFAULT_MAX_CONTAINERS)):
            return action_result.set_status(phantom.APP_ERROR,
                    "Please specify the {0} value greater than {1}. Ideally this value should be greater than the max events generated within a second on the device.".format(
                        ELSA_JSON_FIRST_MAX_CONTAINERS, ELSA_DEFAULT_MAX_CONTAINERS))

        config[ELSA_JSON_FIRST_MAX_CONTAINERS] = first_max_containers

        return phantom.APP_SUCCESS

    def _validate_time_format(self, query_parameters, action_result):

        try:
            datetime.strptime(query_parameters["start"], DATETIME_FORMAT)
            datetime.strptime(query_parameters["end"], DATETIME_FORMAT)
        except Exception as e:
            return action_result.set_status(phantom.APP_ERROR, "Invalid time parameter(s) for 'run query' action.", e)

        return phantom.APP_SUCCESS

    def _on_poll(self, param):

        config = self.get_config()
        action_result = self.add_action_result(ActionResult(dict(param)))

        ret_val = self._validate_my_config(action_result)

        if (phantom.is_fail(ret_val)):
            return action_result.get_status()

        # Get the start and end times based on the type of poll
        query_meta_params = self._get_query_params(param, )

        # update query_meta_params with remaining items:
        query_meta_params.update({"cutoff": "",
            "offset": 0,
            "orderby": "",
            "orderby_dir": "asc",
            "groupby": "",
            "node": "",
            "datasource": "",
            "archive": 0,
            "analytics": 0,
            "nobatch": 0})

        self.save_progress("Query Params set. Timeout: " + str(query_meta_params["timeout"]))

        full_query_dict = {"query_string": str(config["query_type"]), "query_meta_params": query_meta_params}

        message = "Getting max {0} event(s) between {1} and {2}".format(
                query_meta_params.get('limit', '-'),
                query_meta_params.get('start', '-'),
                query_meta_params.get('end', '-'))

        self.save_progress(message)

        try:

            self.debug_print("In the #On Poll# try loop")
            query_headers, body = self._format_query(full_query_dict)
            ret_val, response = self._make_rest_call(action_result, headers=query_headers, data=body)

            if (phantom.is_fail(ret_val)):
                self.save_progress("On Poll failed during make rest call")
                return action_result.get_status()

            self.debug_print("On Poll passed make rest call")

        except Exception as e:
            self.set_status(phantom.APP_ERROR, ELSA_ERR_SERVER_CONNECTION, e)
            self.append_to_message(ELSA_ERR_CONNECTIVITY_TEST)
            return self.get_status()

        self.debug_print("Number of items retrieved before _handle_pull_data: {0}".format(len(response["results"])))

        ret_val = self._handle_pull_data(response["results"])

        if (phantom.is_fail(ret_val)):
            self.save_progress("Polling Failed")
            return action_result.set_status(phantom.APP_ERROR, "Polling failed")

        self.save_progress("Event polling successful")

        return action_result.set_status(phantom.APP_SUCCESS, "Polling event success")

    def _handle_pull_data(self, pull_results):

        no_of_events = len(pull_results)
        cef_data = []
        self.save_progress("Got {0} event{1}", no_of_events, '' if (no_of_events == 1) else 's')

        for event_no in range(no_of_events):

            self.send_progress("Working on Event # {0}".format(event_no))
            raw_event_data = pull_results[event_no]
            # framing the cef dict
            cef_dict = self._frame_cef_dict(raw_event_data["_fields"])

            action_id = self.get_action_identifier()
            # check if we ran query as an action or are ingesting
            if (action_id == self.ACTION_ID_RUN_QUERY):
                cef_data.append(cef_dict)
                return phantom.APP_SUCCESS, cef_dict
            else:
                # create the container for the ingest action
                self._create_container(raw_event_data, cef_dict)

        # store the date time of the last event
        if ((no_of_events) and (not self.is_poll_now())):

            config = self.get_config()
            last_date_time_epoch = float(pull_results[-1]["timestamp"])
            # datetime.datetime.fromtimestamp(1347517370).strftime('%c')
            #    '2012-09-13 02:22:50'
            self._state[ELSA_JSON_LAST_DATE_TIME] = datetime.fromtimestamp(last_date_time_epoch).strftime(DATETIME_FORMAT)
            date_strings = [float(x["timestamp"]) for x in pull_results]
            date_strings = set(date_strings)

            if (len(date_strings) == 1):
                self.debug_print("Getting all containers with the same date, down to the second." +
                        " That means the device is generating max_containers=({0}) per second.".format(config[ELSA_JSON_MAX_CONTAINERS]) +
                        " Skipping to the next second to not get stuck.")
                self._state[ELSA_JSON_LAST_DATE_TIME] = self._get_next_start_time(self._state[ELSA_JSON_LAST_DATE_TIME])

        return phantom.APP_SUCCESS

    def _frame_cef_keys(self, key, cef_map):

        # changing the keys to camel case to match cef formatting
        name = re.sub('[^A-Za-z0-9]+', '', key)
        name = name[0].lower() + name[1:]
        if name in cef_map.keys():
            name = cef_map[name]
        return name

    def _frame_cef_dict(self, raw_event_data, cef_map=DEFAULT_CEF_MAP):

        # framing the cef dict
        cef_dict = {}

        for field in raw_event_data:
            # remove out all the empty entries and the default entries
            if field["value"] not in CEF_EXCLUDE and "any" not in field["class"]:
                # change the keys to cef format
                name = self._frame_cef_keys(field["field"], cef_map)
                # pick the corresponding entry from the combined raw event data
                cef_dict[name] = field["value"]
        return cef_dict

    def _create_container(self, event_data, cef_dict):

        container = {}

        container.update(_container_common)
        container['source_data_identifier'] = event_data["id"]
        event_time = time.strftime(DATETIME_FORMAT, time.localtime(float(event_data["timestamp"])))
        container['name'] = event_data["program"] + " event at " + event_time
        container['data'] = {'raw_event': event_data}

        ret_val, message, container_id = self.save_container(container)
        self.debug_print(CREATE_CONTAINER_RESPONSE.format(ret_val, message, container_id))

        if (phantom.is_fail(ret_val)):
            message = "Failed to add Container error msg: {0}".format(message)
            self.debug_print(message)
            return phantom.APP_ERROR, "Failed Creating container"

        if (not container_id):
            message = "save_container did not return a container_id"
            self.debug_print(message)
            return phantom.APP_ERROR, "Failed creating container"

        artifact = {}
        artifact.update(_artifact_common)
        artifact['container_id'] = container_id
        artifact['source_data_identifier'] = 0  # We are only going to add a single artifact
        artifact['cef'] = cef_dict
        artifact['cef_types'] = {'destinationDnsName': [ "domain" ] }
        if event_data["program"] == "bro_http" and artifact['cef']['requestURL'] and artifact['cef']['destinationDnsName']:
            artifact['cef']['fullRequestURL'] = artifact['cef']['destinationDnsName'] + artifact['cef']['requestURL']
            artifact['cef_types']["fullRequestURL"] = [ "domain" ]
        artifact['name'] = "Event Artifact"
        artifact['run_automation'] = True
        ret_val, status_string, artifact_id = self.save_artifact(artifact)

        if (phantom.is_fail(ret_val)):
            return phantom.APP_ERROR, "Failed to add artifact"

        return phantom.APP_SUCCESS, "Successfully created container and added artifact"

    def _run_query(self, param):

        config = self.get_config()

        action_result = self.add_action_result(ActionResult(dict(param)))

        ret_val = self._validate_my_config(action_result)

        if (phantom.is_fail(ret_val)):
            return action_result.get_status()

        query_meta_params = {}
        query_meta_params["limit"] = param.get("limit", int(ELSA_DEFAULT_MAX_CONTAINERS))
        query_meta_params["start"] = param.get("start_time", self._get_first_start_time())
        query_meta_params["end"] = param.get("end_time", self._get_end_time())
        query_meta_params["timeout"] = config[ELSA_JSON_QUERY_TIMEOUT]

        ret_val_time = self._validate_time_format(query_meta_params, action_result)
        if (phantom.is_fail(ret_val_time)):
            return action_result.get_status()

        # update query_meta_params with remaining items:
        query_meta_params.update({"cutoff": "",
            "offset": 0,
            "orderby": "",
            "orderby_dir": param["orderby_dir"],
            "node": "",
            "datasource": "",
            "archive": 0,
            "analytics": 0,
            "nobatch": 0})
        self.save_progress("Query Params set. Timeout: " + str(query_meta_params["timeout"]))

        # build the full query dictionary for submission
        full_query_dict = {"query_string": str(param["query_string"]), "query_meta_params": query_meta_params}

        # update the user
        message = "Getting max {0} event(s) between {1} and {2} matching query {3}".format(
                query_meta_params.get('limit', '-'),
                query_meta_params.get('start', '-'),
                query_meta_params.get('end', '-'),
                param.get("query_string", "-"))
        self.save_progress(message)

        try:

            query_headers, body = self._format_query(full_query_dict)
            ret_val, run_query_response = self._make_rest_call(action_result, headers=query_headers, data=body)

            if (phantom.is_fail(ret_val)):
                self.save_progress("Run Query failed during make rest call")
                return action_result.get_status()
            self.debug_print("Run query passed make rest call")

        except Exception as e:
            self.set_status(phantom.APP_ERROR, ELSA_ERR_SERVER_CONNECTION, e)
            self.append_to_message(ELSA_ERR_CONNECTIVITY_TEST)
            return self.get_status()

        self.debug_print("Number of items retrieved before returning data: {0}".format(run_query_response["recordsReturned"]))

        try:
            action_result.update_summary({'total_records': run_query_response["totalRecords"]})
            action_result.update_summary({'records_returned': run_query_response["recordsReturned"]})
            action_result.update_summary({'query_id': run_query_response["qid"]})
            cef_data = []
            cef_map_to_use = param.get("output_cef_map", DEFAULT_CEF_MAP)

            for event_no in range(len(run_query_response["results"])):
                raw_event_data = run_query_response["results"][event_no]
                # framing the cef dict
                cef_dict = self._frame_cef_dict(raw_event_data["_fields"], cef_map=cef_map_to_use)
                cef_data.append(cef_dict)
                # run_query_response["results"][event_no]["cef"] = cef_dict

            # action_result.add_data({'raw_results': run_query_response["results"]})
            action_result.add_data({'cef': cef_data})

        except Exception as e:
            self.set_status(phantom.APP_ERROR, ELSA_ERR_QUERY_RETURNED_INVALID_DATA, e)
            return self.get_status()

        if (phantom.is_fail(ret_val)):
            self.save_progress("Run Query Failed")
            return action_result.set_status(phantom.APP_ERROR, "Run Query failed")

        self.save_progress("Run Query successful")

        return action_result.set_status(phantom.APP_SUCCESS, "Run Query event success")

    def handle_action(self, param):

        ret_val = phantom.APP_SUCCESS

        # Get the action that we are supposed to execute for this App Run
        action_id = self.get_action_identifier()

        self.debug_print("action_id", self.get_action_identifier())

        if (action_id == self.ACTION_ID_TEST_CONNECTIVITY):
            ret_val = self._test_connectivity(param)
        elif (action_id == self.ACTION_ID_ON_POLL):
            ret_val = self._on_poll(param)
        elif (action_id == self.ACTION_ID_RUN_QUERY):
            ret_val = self._run_query(param)

        return ret_val


if __name__ == '__main__':

    import sys
    import pudb
    pudb.set_trace()

    if (len(sys.argv) < 2):
        print "No test json specified as input"
        exit(0)

    with open(sys.argv[1]) as f:
        in_json = f.read()
        in_json = json.loads(in_json)
        print(json.dumps(in_json, indent=4))

        connector = ElsaConnector()
        connector.print_progress_message = True
        ret_val = connector._handle_action(json.dumps(in_json), None)
        print (json.dumps(json.loads(ret_val), indent=4))

    exit(0)
