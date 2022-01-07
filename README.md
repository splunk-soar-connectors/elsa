[comment]: # "Auto-generated SOAR connector documentation"
# ELSA \(Security Onion\)

Publisher: Phantom  
Connector Version: 1\.0\.15  
Product Vendor: Security Onion  
Product Name: ELSA  
Product Version Supported (regex): "\.\*"  
Minimum Product Version: 3\.0\.251  

This app integrates with the ELSA service included in the Security Onion security distribution

[comment]: # "File: readme.md"
[comment]: # "Copyright (c) 2018 Splunk Inc."
[comment]: # ""
[comment]: # "Licensed under the Apache License, Version 2.0 (the 'License');"
[comment]: # "you may not use this file except in compliance with the License."
[comment]: # "You may obtain a copy of the License at"
[comment]: # ""
[comment]: # "    http://www.apache.org/licenses/LICENSE-2.0"
[comment]: # ""
[comment]: # "Unless required by applicable law or agreed to in writing, software distributed under"
[comment]: # "the License is distributed on an 'AS IS' BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND,"
[comment]: # "either express or implied. See the License for the specific language governing permissions"
[comment]: # "and limitations under the License."
[comment]: # ""
Security Onion is a popular Linux distribution pre-loaded with numerous Network Security Monitoring
tools such as Snort, Bro, and Suricata. Security Onion uses ELSA (Enterprise Log Search and Archive)
to store all the IDS alerts from Snort, Bro and Suricata. This app collects the events and event
details from ELSA into Phantom containers and artifacts.

First, create an ELSA asset in Phantom and supply the Device URL, the User name and the Apikey. The
User name and ApiKey are found in the /etc/elsa_web.conf file on the Security Onion machine. You
will need to have root privileges to access this file. See the below screenshot for an example of
the /etc/elsa_web.conf file that you are looking for.  
[![](img/elsa_web_conf.png)](img/elsa_web_conf.png)

You will also need to the set the "event type" you want to pull in from ELSA. Currently, three basic
queries are supported as shown below.  
[![](img/type.png)](img/type.png)

The other values can be left in the default state for now.

Select a label for the containers that this asset will create. Either pick from the existing list,
or select **New Entry** and type a new label. In this screenshot we are using **Event** :

[![](img/ingest_settings.png)](img/ingest_settings.png)

Once the asset is saved, run Test Connectivity and make sure it passes. The Test Connectivity action
attempts to validate the User name and the ApiKey that the user has provided by connecting to the
configured Device URL. The connection is tested by running a basic query and checking that the HTTP
response is valid.

## Containers created

The app will create a single container for each event that it ingests with a single artifact called
Event Artifact.

## Event Artifact

The details regarding the event that are acquired from the API call to ELSA will be collected and
the data that are related to the type of event are all stored into the CEF fields and are added to
the artifact. There are some default CEF field mappings in the app for Snort and BRO_CONN and
BRO_HTTP event types. The fields that are present in the artifact greatly depend upon the type of
the event that was created. Different events will have different types of values in the artifacts.  
[![](img/event_artifact.png)](img/event_artifact.png)  

## Run Query

Finally, there is a "run query" action that enables the user to run a query in ELSA either as a
manual action or as a chained action in a playbook in order to gather more data. This action allows
the user to fill in the details for the exact query string to run. This can be as simple as an IP
address or use the ELSA query language to get back more specific information. For information, click
[here](https://github.com/Security-Onion-Solutions/security-onion/wiki/ELSAQueryTips) for some tips
on what to use for query strings in ELSA. The action also takes a JSON formatted "cef_map" parameter
that allows the user to properly map the fields they expect to the proper CEF field so the output
results can be used to further chain actions in a playbook. The following is an example "cef_map"
parameter:

                {"program": "deviceEventCategory", "dstport": "destinationPort", "dstip": "destinationAddress", "srcip": "sourceAddress", "srcport": "sourcePort", "site": "destinationDnsName", "uri": "requestURL", "bytesout": "bytesOut"}
            

The other parameters are fairly self-explanatory.  
[![](img/query.png)](img/query.png)  


### Configuration Variables
The below configuration variables are required for this Connector to operate.  These variables are specified when configuring a ELSA asset in SOAR.

VARIABLE | REQUIRED | TYPE | DESCRIPTION
-------- | -------- | ---- | -----------
**base\_url** |  required  | string | Device URL, e\.g\. https\://security\-onion\.local OR https\://192\.168\.100\.100
**verify\_server\_cert** |  required  | boolean | Verify server certificate
**username** |  required  | string | User name corresponding to the api key \(found in /etc/elsa\_web\.conf file on Security Onion machine\)
**apikey** |  required  | password | Apikey for username \(found in /etc/elsa\_web\.conf file on Security Onion machine\)
**query\_type** |  required  | string | Type/class of events to pull in from ELSA\.
**max\_containers** |  required  | numeric | Maximum events for scheduled polling
**first\_run\_max\_events** |  required  | numeric | Maximum events to poll first time
**poll\_hours** |  optional  | numeric | Ingest events in last N hours \(POLL NOW and First Run\)
**query\_timeout** |  optional  | numeric | Max Time to wait for query to finish \(seconds\)
**timezone** |  required  | timezone | Timezone configured on device

### Supported Actions  
[test connectivity](#action-test-connectivity) - Validate the asset configuration for connectivity  
[on poll](#action-on-poll) - Callback action for the on\_poll ingest functionality  
[run query](#action-run-query) - Run a query against ELSA  

## action: 'test connectivity'
Validate the asset configuration for connectivity

Type: **test**  
Read only: **True**

#### Action Parameters
No parameters are required for this action

#### Action Output
No Output  

## action: 'on poll'
Callback action for the on\_poll ingest functionality

Type: **ingest**  
Read only: **True**

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**container\_id** |  optional  | Container IDs to limit the ingestion to\. | string | 
**start\_time** |  optional  | Start of time range, in epoch time \(milliseconds\) | numeric | 
**end\_time** |  optional  | End of time range, in epoch time \(milliseconds\) | numeric | 
**container\_count** |  optional  | Maximum number of container records to query for\. | numeric | 
**artifact\_count** |  optional  | Maximum number of artifact records to query for\. | numeric | 

#### Action Output
No Output  

## action: 'run query'
Run a query against ELSA

Type: **investigate**  
Read only: **True**

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**query\_string** |  required  | Exact query string to run into ELSA\. See https\://goo\.gl/zEIoYO for query help\. | string | 
**output\_cef\_map** |  optional  | json dictionary for mapping expected query output to cef values\. | string | 
**start\_time** |  optional  | Start of time range, in YYYY\-MM\-DD HH\:MM\:SS format\.  Example\: 2017\-01\-23 19\:12\:39 | string | 
**end\_time** |  optional  | End of time range, in YYYY\-MM\-DD HH\:MM\:SS format\.  Example\: 2017\-01\-23 19\:12\:39 | string | 
**limit** |  optional  | Number of results to limit the query to\. | numeric | 
**orderby\_dir** |  optional  | Direction to sort results\. | string | 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.data\.\*\.cef\.\*\.method | string | 
action\_result\.data\.\*\.cef\.\*\.useragent | string | 
action\_result\.data\.\*\.cef\.\*\.requestURL | string | 
action\_result\.data\.\*\.cef\.\*\.sourcePort | string |  `port` 
action\_result\.data\.\*\.cef\.\*\.statuscode | string | 
action\_result\.data\.\*\.cef\.\*\.sourceAddress | string |  `ip` 
action\_result\.data\.\*\.cef\.\*\.destinationPort | string |  `port` 
action\_result\.data\.\*\.cef\.\*\.destinationAddress | string |  `ip` 
action\_result\.data\.\*\.cef\.\*\.destinationDnsName | string |  `domain` 
action\_result\.data\.\*\.cef\.\*\.proto | string | 
action\_result\.data\.\*\.cef\.\*\.sigmsg | string | 
action\_result\.data\.\*\.cef\.\*\.sigsid | string | 
action\_result\.data\.\*\.cef\.\*\.sigpriority | string | 
action\_result\.data\.\*\.cef\.\*\.sigclassification | string | 
action\_result\.data\.\*\.cef\.\*\.mimetype | string | 
action\_result\.data\.\*\.cef\.\*\.contentlength | string | 
action\_result\.data\.\*\.cef\.\*\.pktsin | string | 
action\_result\.data\.\*\.cef\.\*\.bytesin | string | 
action\_result\.data\.\*\.cef\.\*\.pktsout | string | 
action\_result\.data\.\*\.cef\.\*\.service | string | 
action\_result\.data\.\*\.cef\.\*\.bytesOut | string | 
action\_result\.data\.\*\.cef\.\*\.connduration | string | 
action\_result\.data\.\*\.cef\.\*\.respcountrycode | string | 
action\_result\.data\.\*\.cef\.\*\.md5 | string | 
action\_result\.data\.\*\.cef\.\*\.sha1 | string | 
action\_result\.data\.\*\.cef\.\*\.source | string | 
action\_result\.data\.\*\.cef\.\*\.rxhosts | string | 
action\_result\.data\.\*\.cef\.\*\.txhosts | string | 
action\_result\.data\.\*\.cef\.\*\.seenbytes | string | 
action\_result\.data\.\*\.cef\.\*\.totalbytes | string | 
action\_result\.status | string | 
action\_result\.message | string | 
action\_result\.summary\.query\_id | string | 
action\_result\.summary\.total\_records | numeric | 
action\_result\.summary\.records\_returned | numeric | 
action\_result\.parameter\.limit | string | 
action\_result\.parameter\.end\_time | string | 
action\_result\.parameter\.start\_time | string | 
action\_result\.parameter\.orderby\_dir | string | 
action\_result\.parameter\.query\_string | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric | 
action\_result\.data\.\*\.cef\.\*\.deviceEventCategory | string | 
action\_result\.data\.\*\.cef\.\*\.class | string | 
action\_result\.data\.\*\.cef\.\*\.host | string |  `ip` 
action\_result\.data\.\*\.cef\.\*\.referer | string |  `url` 
action\_result\.data\.\*\.cef\.\*\.versionminor2 | string | 
action\_result\.data\.\*\.cef\.\*\.softwaretype | string | 
action\_result\.data\.\*\.cef\.\*\.name | string | 
action\_result\.data\.\*\.cef\.\*\.versionmajor | string | 
action\_result\.data\.\*\.cef\.\*\.version | string | 
action\_result\.data\.\*\.cef\.\*\.versionminor3 | string | 
action\_result\.parameter\.output\_cef\_map | string | 