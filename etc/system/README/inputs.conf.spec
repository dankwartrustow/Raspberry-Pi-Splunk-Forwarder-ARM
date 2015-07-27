#   Version 6.0 

# This file contains possible attributes and values you can use to configure inputs,
# distributed inputs such as forwarders, and file system monitoring in inputs.conf.
#
# There is an inputs.conf in $SPLUNK_HOME/etc/system/default/.  To set custom configurations, 
# place an inputs.conf in $SPLUNK_HOME/etc/system/local/.  For examples, see inputs.conf.example.
# You must restart Splunk to enable new configurations.
#
# To learn more about configuration files (including precedence), see the documentation 
# located at http://docs.splunk.com/Documentation/Splunk/latest/Admin/Aboutconfigurationfiles
#

# GLOBAL SETTINGS
# Use the [default] stanza to define any global settings.
#     * You can also define global settings outside of any stanza, at the top of the file.
#     * Each conf file should have at most one default stanza. If there are multiple default
#       stanzas, attributes are combined. In the case of multiple definitions of the same
#       attribute, the last definition in the file wins.
#     * If an attribute is defined at both the global level and in a specific stanza, the
#       value in the specific stanza takes precedence.

#*******
# GENERAL SETTINGS:
# The following attribute/value pairs are valid for all input types (except file system change monitor,
# which is described in a separate section in this file).
# You must first enter a stanza header in square brackets, specifying the input type. See further down 
# in this file for examples.   
# Then, use any of the following attribute/value pairs.
#*******

host = <string>
* Sets the host key/field to a static value for this stanza.
* Primarily used to control the host field, which will be used for events coming in
  via this input stanza.
* Detail: Sets the host key's initial value. The key is used during parsing/indexing, 
  in particular to set the host field. It is also the host field used at search time.
* As a convenience, the chosen string is prepended with 'host::'.
* WARNING: Do not quote the <string> value: host=foo, not host="foo".
* If set to '$decideOnStartup', will be interpreted as hostname of executing machine;
  such interpretation will occur on each splunkd startup.  This is the default.

index = <string>
* Sets the index to store events from this input.
* Primarily used to specify the index to store events coming in via this input stanza.
* Detail: Sets the index key's initial value. The key is used when selecting an
  index to store the events.
* Defaults to "main" (or whatever you have set as your default index).

source = <string>
* Sets the source key/field for events from this input.
* NOTE: Overriding the source key is generally not recommended.  Typically, the
  input layer will provide a more accurate string to aid problem
  analysis and investigation, accurately recording the file from which the data
  was retreived.  Please consider use of source types, tagging, and search
  wildcards before overriding this value.
* Detail: Sets the source key's initial value. The key is used during
  parsing/indexing, in particular to set the source field during
  indexing.  It is also the source field used at search time.
* As a convenience, the chosen string is prepended with 'source::'.
* WARNING: Do not quote the <string> value: source=foo, not source="foo".
* Defaults to the input file path.

sourcetype = <string>
* Sets the sourcetype key/field for events from this input.
* Primarily used to explicitly declare the source type for this data, as opposed
  to allowing it to be determined via automated methods.  This is typically
  important both for searchability and for applying the relevant configuration for this
  type of data during parsing and indexing.
* Detail: Sets the sourcetype key's initial value. The key is used during
  parsing/indexing, in particular to set the source type field during
  indexing. It is also the source type field used at search time.
* As a convenience, the chosen string is prepended with 'sourcetype::'.
* WARNING: Do not quote the <string> value: sourcetype=foo, not sourcetype="foo".
* If unset, Splunk picks a source type based on various aspects of the data.
  There is no hard-coded default.

queue = [parsingQueue|indexQueue]
* Specifies where the input processor should deposit the events it reads.
* Set queue to "parsingQueue" to apply props.conf and other parsing rules to your data. For more 
information about props.conf and rules for timestamping and linebreaking, refer to props.conf and the 
online documentation at http://docs.splunk.com/Documentation.
* Set queue to "indexQueue" to send your data directly into the index.
* Defaults to parsingQueue.

# Pipeline Key defaulting.

* Pipeline keys in general can be defaulted in inputs stanzas.
* The list of user-available modifiable pipeline keys is described in transforms.conf.spec,
  See transforms.conf.spec for further information on these keys.
* The currently-defined keys which are available literally in inputs stanzas
  are as follows:
queue = <value>
_raw  = <value>
_meta = <value>
_time = <value>
* Inputs have special support for mapping host, source, sourcetype, and index
  to their metadata names such as host -> Metadata:Host
* Defaulting these values is not recommended, and is
  generally only useful as a workaround to other product issues.
* Defaulting these keys in most cases will override the default behavior of
  input processors; but this behavior is not guaranteed in all cases.
* Values defaulted here, as with all values provided by inputs, may be
  altered by transforms at parse-time.

# ***********
# This section contains options for routing data using inputs.conf rather than outputs.conf. 
# Note concerning routing via inputs.conf:
# This is a simplified set of routing options you can use as data is coming in. 
# For more flexible options or details on configuring required or optional settings, refer to 
# outputs.conf.spec.

_TCP_ROUTING = <tcpout_group_name>,<tcpout_group_name>,<tcpout_group_name>, ...
* Comma-separated list of tcpout group names.
* Using this, you can selectively forward the data to specific indexer(s).
* Specify the tcpout group the forwarder should use when forwarding the data.
  The tcpout group names are defined in outputs.conf with [tcpout:<tcpout_group_name>].
* Defaults to groups specified in "defaultGroup" in [tcpout] stanza in outputs.conf.
* To forward data from the "_internal" index, _TCP_ROUTING must explicitly be set to either "*" or
  a specific splunktcp target group.

_SYSLOG_ROUTING = <syslog_group_name>,<syslog_group_name>,<syslog_group_name>, ...
* Comma-separated list of syslog group names. 
* Using this, you can selectively forward the data to specific destinations as syslog events.
* Specify the syslog group to use when forwarding the data.
  The syslog group names are defined in outputs.conf with [syslog:<syslog_group_name>].
* Defaults to groups present in "defaultGroup" in [syslog] stanza in outputs.conf.
* The destination host must be configured in outputs.conf, using "server=[<ip>|<servername>]:<port>".

_INDEX_AND_FORWARD_ROUTING = <string>
* Only has effect if using selectiveIndexing feature in outputs.conf.
* If set for any input stanza, should cause all data coming from that input
  stanza to be labeled with this setting.
* When selectiveIndexing is in use on a forwarder:
  * data without this label will not be indexed by that forwarder.
  * data with this label will be indexed in addition to any forwarding.
* This setting does not actually cause data to be forwarded or not forwarded in
  any way, nor does it control where the data is forwarded in multiple-forward path
  cases.
* Defaults to not present.

#*******
# Valid input types follow, along with their input-specific attributes:
#*******


#*******
# MONITOR:
#*******

[monitor://<path>]
* This directs Splunk to watch all files in <path>. 
* <path> can be an entire directory or just a single file.
* You must specify the input type and then the path, so put three slashes in your path if you are starting 
at the root (to include the slash that goes before the root directory).

# Additional attributes:

host_regex = <regular expression>
* If specified, <regular expression> extracts host from the path to the file for each input file. 
    * Detail: This feature examines the source key; if source is set
      explicitly in the stanza, that string will be matched, not the original filename.
* Specifically, the first group of the regex is used as the host. 
* If the regex fails to match, the default "host =" attribute is used.
* If host_regex and host_segment are both set, host_regex will be ignored.
* Defaults to unset.

host_segment = <integer>
* If set to N, the Nth "/"-separated segment of the path is set as host. If host_segment=3, for example,
  the third segment is used.
* If the value is not an integer or is less than 1, the default "host =" attribute is used.
* Defaults to unset.

whitelist = <regular expression>
* If set, files from this input are monitored only if their path matches the specified regex.
* Takes precedence over the deprecated _whitelist attribute, which functions the same way.

blacklist = <regular expression>
* If set, files from this input are NOT monitored if their path matches the specified regex.
* Takes precedence over the deprecated _blacklist attribute, which functions the same way.

Note concerning wildcards and monitor:
* You can use wildcards to specify your input path for monitored input. Use "..." for recursive directory 
  matching and "*" for wildcard matching in a single directory segment.
* "..." recurses through directories. This means that /foo/.../bar will match foo/bar, foo/1/bar, 
  foo/1/2/bar, etc. 
* You can use multiple "..." specifications in a single input path. For example: /foo/.../bar/...
* The asterisk (*) matches anything in a single path segment; unlike "...", it does not recurse.  For example, 
  /foo/*/bar matches the files /foo/bar, /foo/1/bar, /foo/2/bar, etc. However, it does not match /foo/1/2/bar. 
  A second example: /foo/m*r/bar matches /foo/mr/bar, /foo/mir/bar, /foo/moor/bar, etc.
* You can combine "*" and "..." as needed: foo/.../bar/* matches any file in the bar directory within the 
  specified path.

crcSalt = <string>
* Use this setting to force Splunk to consume files that have matching CRCs (cyclic redundancy checks). (Splunk only 
  performs CRC checks against the first few lines of a file. This behavior prevents Splunk from indexing the same 
  file twice, even though you may have renamed it -- as, for example, with rolling log files. However, because the 
  CRC is based on only the first few lines of the file, it is possible for legitimately different files to have 
  matching CRCs, particularly if they have identical headers.)
* If set, <string> is added to the CRC.
* If set to the literal string <SOURCE> (including the angle brackets), the full directory path to the source file 
  is added to the CRC. This ensures that each file being monitored has a unique CRC.   When crcSalt is invoked, 
  it is usually set to <SOURCE>.
* Be cautious about using this attribute with rolling log files; it could lead to the log file being re-indexed 
  after it has rolled. 
* Defaults to empty. 

initCrcLength = <integer>
* This setting adjusts how much of a file Splunk reads before trying to identify whether it is a file that has
  already been seen.  You may want to adjust this if you have many files with common headers (comment headers,
  long CSV headers, etc) and recurring filenames.
* CAUTION: Improper use of this setting will cause data to be reindexed.  You may wish to consult with Splunk
  Support before adjusting this value - the default is fine for most installations.
* Defaults to 256 (bytes).
* Must be in the range 256-1048576.

ignoreOlderThan = <nonnegative integer>[s|m|h|d]
* Causes the monitored input to stop checking files for updates if their modtime has passed this threshold.
  This improves the speed of file tracking operations when monitoring directory hierarchies with large numbers
  of historical files (for example, when active log files are colocated with old files that are no longer
  being written to).
  * As a result, do not select a cutoff that could ever occur for a file
    you wish to index.  Take downtime into account!  
    Suggested value: 14d , which means 2 weeks
* A file whose modtime falls outside this time window when seen for the first time will not be indexed at all.
* Default: 0, meaning no threshold.

followTail = [0|1]
* WARNING: Use of followTail should be considered an advanced administrative action.
* Treat this setting as an 'action'.  That is, bring splunk up with this
  setting enabled.  Wait enough time for splunk to identify the related files,
  then disable the setting and restart splunk without it.
* DO NOT leave followTail enabled in an ongoing fashion.
* Do not use for rolling log files, or files whose names or paths vary.
* Can be used to force splunk to skip past all current data for a given stanza. 
  * In more detail: this is intended to mean that if you start up splunk with a
    stanza configured this way, all data in the file at the time it is first
    encountered will not be read.  Only data arriving after that first
    encounter time will be read.
  * This can be used to "skip over" data from old log files, or old portions of
    log files, to get started on current data right away.
* If set to 1, monitoring begins at the end of the file (like tail -f).
* If set to 0, Splunk will always start at the beginning of the file. 
* Defaults to 0.

alwaysOpenFile = [0|1]
* Opens a file to check whether it has already been indexed.
* Only useful for files that do not update modtime.
* Only needed when monitoring files on Windows, mostly for IIS logs.
* This flag should only be used as a last resort, as it increases load and slows down indexing.
* Defaults to 0.

time_before_close = <integer>
* Modtime delta required before Splunk can close a file on EOF.
* Tells the system not to close files that have been updated in past <integer> seconds.
* Defaults to 3.

recursive = [true|false]
* If false, Splunk will not monitor subdirectories found within a monitored directory.
* Defaults to true.

followSymlink = [true|false]
* Tells Splunk whether or not to follow any symbolic links within a directory it is monitoring.
* If set to false, Splunk will ignore symbolic links found within a monitored directory.
* If set to true, Splunk will follow symbolic links and monitor files at the symbolic link's destination.
* Additionally, any whitelists or blacklists defined for the stanza also apply to files at the symbolic link's destination.
* Defaults to true. 

_whitelist = ...
* This setting is deprecated.  It is still honored, unless "whitelist" attribute also exists.

_blacklist = ...
* This setting is deprecated.  It is still honored, unless "blacklist" attribute also exists.

dedicatedFD = ...
* This setting has been removed.  It is no longer needed.

  
#****************************************
# BATCH  ("Upload a file" in Splunk Web):
#****************************************

NOTE: Batch should only be used for large archives of historic data. If you want to continuously monitor a directory 
or index small archives, use monitor (see above). Batch reads in the file and indexes it, and then deletes the file 
from the Splunk instance. 

[batch://<path>]
* One time, destructive input of files in <path>.
* For continuous, non-destructive inputs of files, use monitor instead.

# Additional attributes:

move_policy = sinkhole
* IMPORTANT: This attribute/value pair is required. You *must* include "move_policy = sinkhole" when defining batch 
  inputs.
* This loads the file destructively.  
* Do not use the batch input type for files you do not want to consume destructively.
* As long as this is set, Splunk won't keep track of indexed files. Without the "move_policy = sinkhole" setting, 
  it won't load the files destructively and will keep a track of them. 

host_regex = see MONITOR, above.
host_segment = see MONITOR, above.
crcSalt = see MONITOR, above.

# IMPORTANT: The following attribute is not used by batch:
# source = <string>

followSymlink = [true|false]
* Works similarly to monitor, but will not delete files after following a symlink out of the monitored directory.

# The following settings work identically as for [monitor::] stanzas, documented above
host_regex = <regular expression>
host_segment = <integer>
crcSalt = <string>
recursive = [true|false]
whitelist = <regular expression>
blacklist = <regular expression>
initCrcLength = <integer>

#*******
# TCP: 
#*******

[tcp://<remote server>:<port>]
* Configure Splunk to listen on a specific port. 
* If a connection is made from <remote server>, this stanza is used to configure the input.
* If <remote server> is empty, this stanza matches all connections on the specified port.
* Will generate events with source set to tcp:portnumber,  for example: tcp:514
* If sourcetype is unspecified, will generate events with set sourcetype to tcp-raw.

# Additional attributes:

connection_host = [ip|dns|none]
* "ip" sets the host to the IP address of the system sending the data. 
* "dns" sets the host to the reverse DNS entry for IP address of the system sending the data.
* "none" leaves the host as specified in inputs.conf, typically the splunk system hostname.
* Defaults to "dns".

queueSize = <integer>[KB|MB|GB]
* Maximum size of the in-memory input queue. 
* Defaults to 500KB.

persistentQueueSize = <integer>[KB|MB|GB|TB]
* Maximum size of the persistent queue file.
* Defaults to 0 (no persistent queue).
* If set to some value other than 0, persistentQueueSize must be larger than the in-memory queue size 
  (set by queueSize attribute in inputs.conf or maxSize settings in [queue] stanzas in server.conf).
* Persistent queues can help prevent loss of transient data. For information on persistent queues and how the 
  queueSize and persistentQueueSize settings interact, see the online documentation.

requireHeader = <bool>
* Require a header be present at the beginning of every stream.
* This header may be used to override indexing settings.
* Defaults to false.

listenOnIPv6 = <no | yes | only>
* Toggle whether this listening port will listen on IPv4, IPv6, or both
* If not present, the setting in the [general] stanza of server.conf will be used

acceptFrom = <network_acl> ...
* Lists a set of networks or addresses to accept connections from.  These rules are separated by commas or spaces
* Each rule can be in the following forms:
*   1. A single IPv4 or IPv6 address (examples: "10.1.2.3", "fe80::4a3")
*   2. A CIDR block of addresses (examples: "10/8", "fe80:1234/32")
*   3. A DNS name, possibly with a '*' used as a wildcard (examples: "myhost.example.com", "*.splunk.com")
*   4. A single '*' which matches anything
* Entries can also be prefixed with '!' to cause the rule to reject the
  connection.  Rules are applied in order, and the first one to match is
  used.  For example, "!10.1/16, *" will allow connections from everywhere
  except the 10.1.*.* network.
* Defaults to "*" (accept from anywhere)

rawTcpDoneTimeout = <seconds>
* Specifies timeout value for sending Done-key.
* If a connection over this port remains idle after receiving data for specified seconds,
  it adds a Done-key, thus declaring the last event has been completely received.
* Defaults to 10 second.

#*******
# Data distribution:
#*******

# Global settings for splunktcp. Used on the receiving side for data forwarded from a forwarder.

[splunktcp]
route = [has_key|absent_key:<key>:<queueName>;...]
* Settings for the light forwarder.
* Splunk sets these parameters automatically -- you DO NOT need to set them.
* The property route is composed of rules delimited by ';'.
* Splunk checks each incoming data payload via cooked tcp port against the route rules. 
* If a matching rule is found, Splunk sends the payload to the specified <queueName>.
* If no matching rule is found, Splunk sends the payload to the default queue
  specified by any queue= for this stanza. If no queue= key is set in
  the stanza or globally, the events will be sent to the parsingQueue. 

enableS2SHeartbeat = [true|false]
* This specifies the global keepalive setting for all splunktcp ports.
* This option is used to detect forwarders which may have become unavailable due to network, firewall, etc., problems.
* Splunk will monitor each connection for presence of heartbeat, and if the heartbeat is not seen for 
  s2sHeartbeatTimeout seconds, it will close the connection.
* Defaults to true (heartbeat monitoring enabled).

s2sHeartbeatTimeout = <seconds>
* This specifies the global timeout value for monitoring heartbeats.
* Splunk will close a forwarder connection if heartbeat is not seen for s2sHeartbeatTimeout seconds.
* Defaults to 600 seconds (10 minutes).

inputShutdownTimeout = <seconds>
* Used during shutdown to minimize data loss when forwarders are connected to a receiver. 
  During shutdown, the tcp input processor waits for the specified number of seconds and then 
  closes any remaining open connections. If, however, all connections close before the end of 
  the timeout period, shutdown proceeds immediately, without waiting for the timeout.

listenOnIPv6 = <no | yes | only>
* Toggle whether this listening port will listen on IPv4, IPv6, or both
* If not present, the setting in the [general] stanza of server.conf will be used

acceptFrom = <network_acl> ...
* Lists a set of networks or addresses to accept connections from.  These rules are separated by commas or spaces
* Each rule can be in the following forms:
*   1. A single IPv4 or IPv6 address (examples: "10.1.2.3", "fe80::4a3")
*   2. A CIDR block of addresses (examples: "10/8", "fe80:1234/32")
*   3. A DNS name, possibly with a '*' used as a wildcard (examples: "myhost.example.com", "*.splunk.com")
*   4. A single '*' which matches anything
* Entries can also be prefixed with '!' to cause the rule to reject the
  connection.  Rules are applied in order, and the first one to match is
  used.  For example, "!10.1/16, *" will allow connections from everywhere
  except the 10.1.*.* network.
* Defaults to "*" (accept from anywhere)

negotiateNewProtocol = [true|false]
* If set to true, allow forwarders that connect to this indexer (or specific port) to send data using the new forwarder protocol.
* If set to false, deny the use of the new forwarder protocol during connection negotation.
* Defaults to true.

concurrentChannelLimit = <unsigned integer>
* Each forwarder that connects to this indexer may use up to <concurrentChannelLimit> unique channel codes.
* In other words, each forwarder may have up to <concurrentChannelLimit> channels in flight concurrently.
* Splunk will close a forwarder connection if a forwarder attempts to exceed this value.
* This setting only applies when the new forwarder protocol is in use.
* Defaults to 300.

# Forwarder-specific settings for splunktcp. 

[splunktcp://[<remote server>]:<port>]
* This input stanza is used with Splunk instances receiving data from forwarders ("receivers"). See the topic 
  http://docs.splunk.com/Documentation/Splunk/latest/deploy/Aboutforwardingandreceivingdata for more information.
* This is the same as TCP, except the remote server is assumed to be a Splunk instance, most likely a forwarder. 
* <remote server> is optional.  If specified, will only listen for data from <remote server>.

connection_host = [ip|dns|none]
* For splunktcp, the host or connection_host will be used if the remote Splunk instance does not set a host, 
  or if the host is set to "<host>::<localhost>".
* "ip" sets the host to the IP address of the system sending the data. 
* "dns" sets the host to the reverse DNS entry for IP address of the system sending the data.
* "none" leaves the host as specified in inputs.conf, typically the splunk system hostname.
* Defaults to "ip".

compressed = [true|false]
* Specifies whether receiving compressed data.
* Applies to non-SSL receiving only. There is no compression setting required for SSL.
* If set to true, the forwarder port(s) should also have compression turned on; otherwise, the receiver will 
  reject the connection.
* Defaults to false.

enableS2SHeartbeat = [true|false]
* This specifies the keepalive setting for the splunktcp port.
* This option is used to detect forwarders which may have become unavailable due to network, firewall, etc., problems.
* Splunk will monitor the connection for presence of heartbeat, and if the heartbeat is not seen for 
  s2sHeartbeatTimeout seconds, it will close the connection.
* This overrides the default value specified at the global [splunktcp] stanza.
* Defaults to true (heartbeat monitoring enabled).

s2sHeartbeatTimeout = <seconds>
* This specifies the timeout value for monitoring heartbeats.
* Splunk will will close the forwarder connection if heartbeat is not seen for s2sHeartbeatTimeout seconds.
* This overrides the default value specified at global [splunktcp] stanza.
* Defaults to 600 seconds (10 minutes).

queueSize = <integer>[KB|MB|GB]
* Maximum size of the in-memory input queue.
* Defaults to 500KB.

negotiateNewProtocol = [true|false]
* See comments for [splunktcp].

concurrentChannelLimit = <unsigned integer>
* See comments for [splunktcp].

# SSL settings for data distribution:

[splunktcp-ssl:<port>]
* Use this stanza type if you are receiving encrypted, parsed data from a forwarder.
* Set <port> to the port on which the forwarder is sending the encrypted data.
* Forwarder settings are set in outputs.conf on the forwarder.
* Compression for SSL is enabled by default. On forwarder you can still specify compression
  using 'useClientSSLCompression' setting in outputs.conf. 'compressed' setting is used for
  non-SSL. However, if 'compressed' is still specified for SSL, ensure that 'compressed'
  setting is same as forwarder, as splunktcp protocol expects same 'compressed' setting from 
  forwarder as well.

connection_host = [ip|dns|none]
* For SplunkTCP, the host or connection_host will be used if the remote Splunk instance does not set a host, 
  or if the host is set to "<host>::<localhost>".
* "ip" sets the host to the IP address of the system sending the data. 
* "dns" sets the host to the reverse DNS entry for IP address of the system sending the data.
* "none" leaves the host as specified in inputs.conf, typically the splunk system hostname.
* Defaults to "ip".

enableS2SHeartbeat = true|false
* See comments for [splunktcp:<port>].

s2sHeartbeatTimeout = <seconds>
* See comments for [splunktcp:<port>].

listenOnIPv6 = <no | yes | only>
* Toggle whether this listening port will listen on IPv4, IPv6, or both
* If not present, the setting in the [general] stanza of server.conf will be used

acceptFrom = <network_acl> ...
* Lists a set of networks or addresses to accept connections from.  These rules are separated by commas or spaces
* Each rule can be in the following forms:
*   1. A single IPv4 or IPv6 address (examples: "10.1.2.3", "fe80::4a3")
*   2. A CIDR block of addresses (examples: "10/8", "fe80:1234/32")
*   3. A DNS name, possibly with a '*' used as a wildcard (examples: "myhost.example.com", "*.splunk.com")
*   4. A single '*' which matches anything
* Entries can also be prefixed with '!' to cause the rule to reject the
  connection.  Rules are applied in order, and the first one to match is
  used.  For example, "!10.1/16, *" will allow connections from everywhere
  except the 10.1.*.* network.
* Defaults to "*" (accept from anywhere)

negotiateNewProtocol = [true|false]
* See comments for [splunktcp].

concurrentChannelLimit = <unsigned integer>
* See comments for [splunktcp].

[tcp-ssl:<port>]
* Use this stanza type if you are receiving encrypted, unparsed data from a forwarder or third-party system.
* Set <port> to the port on which the forwarder/third-party system is sending unparsed, encrypted data.
	
listenOnIPv6 = <no | yes | only>
* Toggle whether this listening port will listen on IPv4, IPv6, or both
* If not present, the setting in the [general] stanza of server.conf will be used

acceptFrom = <network_acl> ...
* Lists a set of networks or addresses to accept connections from.  These rules are separated by commas or spaces
* Each rule can be in the following forms:
*   1. A single IPv4 or IPv6 address (examples: "10.1.2.3", "fe80::4a3")
*   2. A CIDR block of addresses (examples: "10/8", "fe80:1234/32")
*   3. A DNS name, possibly with a '*' used as a wildcard (examples: "myhost.example.com", "*.splunk.com")
*   4. A single '*' which matches anything
* Entries can also be prefixed with '!' to cause the rule to reject the
  connection.  Rules are applied in order, and the first one to match is
  used.  For example, "!10.1/16, *" will allow connections from everywhere
  except the 10.1.*.* network.
* Defaults to "*" (accept from anywhere)

[SSL]
* Set the following specifications for SSL underneath this stanza name:

serverCert = <path>
* Full path to the server certificate.
	
password = <string>
* Server certificate password, if any.

rootCA = <string>
* Certificate authority list (root file).

requireClientCert = [true|false]
* Determines whether a client must authenticate.
* Defaults to false.

supportSSLV3Only = [true|false]
* If true, tells the inputproc to accept connections only from SSLv3 clients.
* Defaults to false.

cipherSuite = <cipher suite string>
* If set, uses the specified cipher string for the input processors.
* If not set, the default cipher string is used.
* Provided by OpenSSL. This is used to ensure that the server does not
  accept connections using weak encryption protocols.

allowSslRenegotiation = true|false
* In the SSL protocol, a client may request renegotiation of the connection
  settings from time to time.
* Setting this to false causes the server to reject all renegotiation
  attempts, breaking the connection.  This limits the amount of CPU a
  single TCP connection can use, but it can cause connectivity problems
  especially for long-lived connections.
* Defaults to true.

#*******
# UDP:
#*******

[udp://<remote server>:<port>]
* Similar to TCP, except that it listens on a UDP port.
* Only one stanza per port number is currently supported.
* Configure Splunk to listen on a specific port. 
* If <remote server> is specified, the specified port will only accept data from that server.
* If <remote server> is empty - [udp://<port>] - the port will accept data sent from any server.
* Will generate events with source set to udp:portnumber, for example: udp:514
* If sourcetype is unspecified, will generate events with set sourcetype to udp:portnumber .

# Additional attributes:

connection_host = [ip|dns|none]
* "ip" sets the host to the IP address of the system sending the data. 
* "dns" sets the host to the reverse DNS entry for IP address of the system sending the data.
* "none" leaves the host as specified in inputs.conf, typically the splunk system hostname.
* Defaults to "ip".

_rcvbuf = <integer>
* Specifies the receive buffer for the UDP port (in bytes).  
* If the value is 0 or negative, it is ignored.  
* Defaults to 1,572,864.
* Note: If the default value is too large for an OS, Splunk will try to set the value to 1572864/2. If that value also fails, 
  Splunk will retry with 1572864/(2*2). It will continue to retry by halving the value until it succeeds.

no_priority_stripping = [true|false]
* Setting for receiving syslog data. 
* If this attribute is set to true, Splunk does NOT strip the <priority> syslog field from received events. 
* NOTE: Do NOT include this attribute if you want to strip <priority>.
* Default is false.

no_appending_timestamp = [true|false]
* If this attribute is set to true, Splunk does NOT append a timestamp and host to received events.
* NOTE: Do NOT include this attribute if you want to append timestamp and host to received events.
* Default is false.
 
queueSize = <integer>[KB|MB|GB]
* Maximum size of the in-memory input queue.
* Defaults to 500KB.

persistentQueueSize = <integer>[KB|MB|GB|TB]
* Maximum size of the persistent queue file.
* Defaults to 0 (no persistent queue).
* If set to some value other than 0, persistentQueueSize must be larger than the in-memory queue size 
  (set by queueSize attribute in inputs.conf or maxSize settings in [queue] stanzas in server.conf).
* Persistent queues can help prevent loss of transient data. For information on persistent queues and how the 
  queueSize and persistentQueueSize settings interact, see the online documentation.

listenOnIPv6 = <no | yes | only>
* Toggle whether this port will listen on IPv4, IPv6, or both
* If not present, the setting in the [general] stanza of server.conf will be used

acceptFrom = <network_acl> ...
* Lists a set of networks or addresses to accept data from.  These rules are separated by commas or spaces
* Each rule can be in the following forms:
*   1. A single IPv4 or IPv6 address (examples: "10.1.2.3", "fe80::4a3")
*   2. A CIDR block of addresses (examples: "10/8", "fe80:1234/32")
*   3. A DNS name, possibly with a '*' used as a wildcard (examples: "myhost.example.com", "*.splunk.com")
*   4. A single '*' which matches anything
* Entries can also be prefixed with '!' to cause the rule to reject the
  connection.  Rules are applied in order, and the first one to match is
  used.  For example, "!10.1/16, *" will allow connections from everywhere
  except the 10.1.*.* network.
* Defaults to "*" (accept from anywhere)

#*******
# FIFO:
#*******

[fifo://<path>]
* This directs Splunk to read from a FIFO at the specified path.

queueSize = <integer>[KB|MB|GB]
* Maximum size of the in-memory input queue.
* Defaults to 500KB.

persistentQueueSize = <integer>[KB|MB|GB|TB]
* Maximum size of the persistent queue file.
* Defaults to 0 (no persistent queue).
* If set to some value other than 0, persistentQueueSize must be larger than the in-memory queue size 
  (set by queueSize attribute in inputs.conf or maxSize settings in [queue] stanzas in server.conf).
* Persistent queues can help prevent loss of transient data. For information on persistent queues and how the 
  queueSize and persistentQueueSize settings interact, see the online documentation.


#*******
# Scripted Input:
#*******

[script://<cmd>]
* Runs <cmd> at a configured interval (see below) and indexes the output.  
* The <cmd> must reside in one of 
  *  $SPLUNK_HOME/etc/system/bin/
  *  $SPLUNK_HOME/etc/apps/$YOUR_APP/bin/
  *   $SPLUNK_HOME/bin/scripts/
* Script path can be an absolute path, make use of an environment variable such as $SPLUNK_HOME, 
  or use the special pattern of an initial '.' as the first directory to
  indicate a location inside the current app.   Note that the '.' must be
  followed by a platform-specific directory separator.
  * For example, on UNIX:
        [script://./bin/my_script.sh]
    Or on Windows:
        [script://.\bin\my_program.exe]
    This '.' pattern is strongly recommended for app developers, and necessary
    for operation in search head pooling environments.
* Splunk on Windows ships with several Windows-only scripted inputs. Check toward the end of the inputs.conf.example 
  for examples of the stanzas for specific Windows scripted inputs that you must add to your inputs.conf file.
* <cmd> can also be a path to a file that ends with a ".path" suffix. A file with this suffix is a special type of 
  pointer file that points to a command to be executed.  Although the pointer file is bound by the same location
  restrictions mentioned above, the command referenced inside it can reside anywhere on the file system.  
  This file must contain exactly one line: the path to the command to execute, optionally followed by 
  command line arguments.  Additional empty lines and lines that begin with '#' are also permitted and will be ignored.

interval = [<number>|<cron schedule>]
* How often to execute the specified command (in seconds), or a valid cron schedule. 
* NOTE: when a cron schedule is specified, the script is not executed on start-up.
* If specified as a number, may have a fractional component; e.g., 3.14
* Defaults to 60.0 seconds.

passAuth = <username>
* User to run the script as.
* If you provide a username, Splunk generates an auth token for that user and passes it to the script via stdin.
    
queueSize = <integer>[KB|MB|GB]
* Maximum size of the in-memory input queue.
* Defaults to 500KB.

persistentQueueSize = <integer>[KB|MB|GB|TB]
* Maximum size of the persistent queue file.
* Defaults to 0 (no persistent queue).
* If set to some value other than 0, persistentQueueSize must be larger than the in-memory queue size 
  (set by queueSize attribute in inputs.conf or maxSize settings in [queue] stanzas in server.conf).
* Persistent queues can help prevent loss of transient data. For information on persistent queues and how the 
  queueSize and persistentQueueSize settings interact, see the online documentation.

index = <index name>
* The index to which the output will be indexed to.
* Note: this parameter will be passed as a command-line argument to <cmd> in the format: -index <index name>.
  If the script does not need the index info, it can simply ignore this argument.
* If no index is specified, the default index will be used for the script output.

start_by_shell = [true|false]
* If set to true, the specified command will be run via the OS's shell ("/bin/sh -c" on UNIX,
  "cmd.exe /c" on Windows)
* If set to false, the program will be run directly without attempting to expand shell
  metacharacters.
* Defaults to true on UNIX, false on Windows.
* Usually the default is fine, but you may want to explicitly set this to false for scripts
  that you know do not need UNIX shell metacharacter expansion.

#*******
# File system change monitor (fschange monitor)
#*******

NOTE: You cannot simultaneously watch a directory using both fschange monitor and monitor (described above).

[fschange:<path>]
* Monitors all add/update/deletes to this directory and its subdirectories.
* NOTE: <path> is the direct path.  You do not need to preface it with // like other inputs.
* Sends an event for every change.

# Additional attributes:
# NOTE: fschange does not use the same attributes as other input types (described above).  Use only the following attributes:

index = <indexname>
* The index in which to store all generated events. 
* Defaults to _audit, unless you do not set signedaudit (below) or set signedaudit = false, in which case events go 
  into the default index.

signedaudit = [true|false]
* Send cryptographically signed add/update/delete events.
* If set to true, events are *always* sent to the _audit index and will *always* have the source type "audittrail".
* If set to false, events are placed in the default index and the source type is whatever you specify (or 
 "fs_notification" by default).
* You must set signedaudit to false if you want to set the index.
* NOTE: You must also enable auditing in audit.conf.
* Defaults to false.

filters = <filter1>,<filter2>,...
* Each filter is applied left to right for each file or directory found during the monitor poll cycle. 
* See "File System Monitoring Filters" below for help defining a filter.

recurse = [true|false]
* If true, recurse directories within the directory specified in [fschange].
* Defaults to true.

followLinks = [true|false]
* If true, follow symbolic links. 
* It is recommended that you do not set this to true; file system loops can occur. 
* Defaults to false.

pollPeriod = <integer>
* Check this directory for changes every <integer> seconds. 
* Defaults to 3600 seconds (1 hour).

hashMaxSize = <integer>
* Calculate a SHA256 hash for every file that is less than or equal to <integer> bytes. 
* This hash is used as an additional method for detecting changes to the file/directory. 
* Defaults to -1 (disabled).

fullEvent = [true|false]
* Set to true to send the full event if an add or update change is detected. 
* Further qualified by the sendEventMaxSize attribute. 
* Defaults to false.

sendEventMaxSize  = <integer>
* Only send the full event if the size of the event is less than or equal to <integer> bytes. 
* This limits the size of indexed file data. 
* Defaults to -1, which is unlimited.

sourcetype = <string>
* Set the source type for events from this input.
* "sourcetype=" is automatically prepended to <string>.
* Defaults to audittrail (if signedaudit=true) or fs_notification (if signedaudit=false).

host = <string>
* Set the host for events from this input.
* Defaults to whatever host sent the event.

filesPerDelay = <integer>
* Injects a delay specified by delayInMills after processing <integer> files.
* This is used to throttle file system monitoring so it consumes less CPU.
* Defaults to 10.

delayInMills = <integer>
* The delay in milliseconds to use after processing every <integer> files, as specified in filesPerDelay.
* This is used to throttle file system monitoring so it consumes less CPU.
* Defaults to 100.


#*******
# File system monitoring filters:
#*******

[filter:<filtertype>:<filtername>]
* Define a filter of type <filtertype> and name it <filtername>.
* <filtertype>:
  * Filter types are either 'blacklist' or 'whitelist.' 
  * A whitelist filter processes all file names that match the regex list.
  * A blacklist filter skips all file names that match the regex list.
* <filtername>
  * The filter name is used in the comma-separated list when defining a file system monitor.
	
regex<integer> = <regex>	
* Blacklist and whitelist filters can include a set of regexes.
* The name of each regex MUST be 'regex<integer>', where <integer> starts at 1 and increments. 
* Splunk applies each regex in numeric order:
  regex1=<regex>
  regex2=<regex>
  ...

#*******
# WINDOWS INPUTS:
#*******

* Windows platform specific input processor.
# ***********
# Splunk for Windows ships with several Windows-only scripted inputs. They are defined in the default inputs.conf.  
 
* This is a list of the Windows scripted input stanzas:
    [script://$SPLUNK_HOME\bin\scripts\splunk-wmi.path]
    [script://$SPLUNK_HOME\bin\scripts\splunk-regmon.path]
    [script://$SPLUNK_HOME\bin\scripts\splunk-admon.path]

* By default, some of the scripted inputs are enabled and others are disabled.  
* Use the "disabled=" parameter to enable/disable any of them.
* Here's a short summary of the inputs:
  * WMI: Retrieves event logs remotely and locally. It can also gather
    performance data remotely, as well as receive various system notifications.
  * RegMon: Uses a driver to track and report any changes that occur in the
    local system's Registry.
  * ADMon: Indexes existing AD objects and listens for AD changes.

###
# The following Windows input specifications are for parsing on non-Windows platforms.
###
###
# Performance Monitor
###

[perfmon://<name>]

* This section explains possible attribute/value pairs for configuring Splunk's
  Windows Performance Monitor.  
* Each perfmon:// stanza represents an individually configured performance
  monitoring input. If you configure the input through Splunk Web, then the
  value of "$NAME" will match what was specified there. While you can add
  performance monitor inputs manually, Splunk recommends that you use Splunk Web
  to configure them, because it is easy to mistype the values for
  Performance Monitor objects, counters and instances.
* Note: The perfmon stanza is for local systems ONLY. To define performance
  monitor inputs for remote machines, use wmi.conf.

object = <string>
* This is a valid Performance Monitor object as defined within Performance
  Monitor (for example, "Process," "Server," "PhysicalDisk.")
* You can specify a single valid Performance Monitor object, or use a 
  regular expression to specify multiple objects.
* This attribute is required, and the input will not run if the attribute is not
  present.
* The object name can be a regular expression (regex).
* There is no default.

counters = <semicolon-separated strings>
* This can be a single counter, or multiple valid Performance Monitor counters.
* This attribute is required, and the input will not run if the attribute is not
  present.
* '*' is equivalent to all available counters for a given Performance Monitor object.
* There is no default.

instances = <semicolon-separated strings>
* This can be a single instance, or multiple valid Performance Monitor
  instances.
* '*' is  equivalent to all available instances for a given Performance Monitor
  counter.
* If applicable instances are available for a counter and this attribute is not
  present, then the input logs data for all available instances (this is the same as
  setting 'instances = *').
* If there are no applicable instances for a counter, then this attribute
  can be safely omitted.
* There is no default.

interval = <integer>
* How often, in seconds, to poll for new data.
* This attribute is required, and the input will not run if the attribute is not
  present.
* The recommended setting depends on the Performance Monitor object,
  counter(s) and instance(s) that you define in the input, and how much 
  performance data you require.  Objects with numerous instantaneous
  or per-second counters, such as "Memory," "Processor" and
  "PhysicalDisk" should have shorter interval times specified (anywhere
  from 1-3 seconds). Less volatile counters such as "Terminal Services,"
  "Paging File" and "Print Queue" can have longer times configured.
* There is no default.

mode = <output mode>
* Specifies output mode. 
* Possible values: single, multikv

samplingInterval = <sampling interval in ms>
* Advanced setting. How often, in milliseconds, to poll for new data.
* Enables high-frequency performance sampling. The input collects performance data 
  every sampling interval. It then reports averaged data and other statistics at every interval.
* The minimum legal value is 100, and the maximum legal value must be less than what the
  'interval' attribute to.
* If not specified, high-frequency sampling does not take place.
* Defaults to not specified (disabled).

stats = <min;max;dev;count>
* Advanced setting. Reports statistics for high-frequency performance sampling. 
* Allows values: min, max, dev, count. 
* Can be specified as a semicolon separated list.
* If not specified, the input does not produce high-frequency sampling statistics.
* Defaults to not specified (disabled).

disabled = [0|1]
* Specifies whether or not the input is enabled.
* 1 to disable the input, 0 to enable it.
* Defaults to 0 (enabled).

index = <string>
* Specifies the index that this input should send the data to.
* This attribute is optional.
* If no value is present, defaults to the default index.

showZeroValue = [0|1]
* Specfies whether or not zero value event data should be collected.
* 1 captures zero value event data, 0 ignores zero value event data.
* Defaults to 0 (ignores zero value event data)


###
# Direct Access File Monitor (does not use file handles)
# For Windows systems only.
###

[MonitorNoHandle://<path>]

* This stanza directs Splunk to intercept file writes to the specific file.
* <path> must be a fully qualified path name to a specific file.
* There can only be one of these stanzas in a configuraton file. If you 
  specify more than one, Splunk only uses the first.

disabled = [0|1]
* Tells Splunk whether or not the input is enabled.
* Defaults to 0 (enabled).

index = <string>
* Tells Splunk which index to store incoming data into for this stanza.
* This field is optional.
* Defaults to the default index.

###
# Windows Event Log Monitor
###

[WinEventLog://<name>]

* This section explains possible attribute/value pairs for configuring Splunk's
  Windows event log Monitor.  
* Each WinEventLog:// stanza represents an individually configured WinEventLog
  monitoring input. If you you configure the input through Splunk Web, the
  value of "$NAME" will match what was specified there. While you can add
  event log monitor inputs manually, Splunk recommends that you use the
  Manager interface to configure Windows event log monitor inputs because it is
  easy to mistype the values for event log channels.
* Note: The WinEventLog stanza is for local systems ONLY. To define event log
  monitor inputs for remote machines, use wmi.conf.

start_from = <string>
* Specifies how Splunk should chronologically read the event log channels.
* Setting this attribute to 'oldest' tells Splunk to start reading Windows event logs
  from oldest to newest.
* Setting this attribute to 'newest' tells Splunk to start reading Windows event logs 
  in reverse, from newest to oldest.  Once the input consumes the backlog of events,
  Splunk will start picking up the newest events.
* 'newest' is not supported in combination with current_only = 1 (This
    combination does not make much sense.)
* Defaults to oldest.

current_only = [0|1]
* Specifies how Splunk should index events after it starts.
* If set to 1, the input will only acquire events that arrive after the input
  starts for the first time, like 'tail -f' on *nix systems.
  * current_only = 1 is not supported with start_from = 'newest'. (It would
    not really make sense.)
* If set to 0, the input will first get all existing events in the log and then
  continue to monitor events coming in real time.
* Defaults to 0 (false), gathering stored events first before monitoring live events.

checkpointInterval = <integer>
* Sets how frequently the Windows Event Log input should save a checkpoint.
* Checkpoints store the eventID of acquired events. This allows Splunk to continue
  monitoring at the correct event after a shutdown or outage.
* The default value is 5.

disabled = [0|1]
* Specifies whether or not the input is enabled.
* 1 to disable the input, 0 to enable it.
* The default is 0 (enabled).

evt_resolve_ad_obj = [1|0] 
* Specifies how Splunk should interact with Active Directory while indexing Windows
  Event Log events.
* A value of 1 tells Splunk to resolve Active Directory objects like
  Globally Unique IDentifier (GUID) and Security IDentifier (SID) objects to their
  canonical names for a specific Windows event log channel.
* When you set this value to 1, you can optionally specify the Domain Controller name
  and/or DNS name of the domain to bind to, which Splunk will then use to resolve the AD objects.
* A value of 0 tells Splunk not to attempt any resolution.  
* By default, this attribute is enabled (1) for Security event logs and disabled for all others.
* The default is 0 (disabled.)

evt_dc_name = <string> 
* Tells Splunk which Active Directory domain controller it should bind to in order to 
  resolve AD objects.
* Optional. This parameter can be left empty. 
* This name can be the NetBIOS name of the domain controller or the fully-
qualified DNS name of the domain controller. Either name type can, optionally,
be preceded by two backslash characters.  The following examples represent
correctly formatted domain controller names:

    * "FTW-DC-01"
    * "\\FTW-DC-01"
    * "FTW-DC-01.splunk.com"
    * "\\FTW-DC-01.splunk.com"

evt_dns_name = <string> 
* Tells Splunk the fully-qualified DNS name of the domain it should bind to in order to
  resolve AD objects.
* Optional. This parameter can be left empty.  

index = <string>
* Specifies the index that this input should send the data to.
* This attribute is optional.
* If no value is present, defaults to the default index.

whitelist = <list>
* Tells Splunk which event IDs and/or event ID ranges that incoming events must have 
  in order to be indexed.
* Optional. This parameter can be left empty.
* A comma-separated list of event ID and event ID ranges to include (example: 4,5,7,100-200).
* If no value is present, defaults to include all event IDs. 
* If you specify both the "whitelist" and "blacklist" attributes, the input ignores the
  "blacklist" attribute.

blacklist = <list>
* Tells Splunk which event IDs and/or event ID ranges that incoming events must NOT have 
  in order to be indexed.
* Optional. This parameter can be left empty.
* A comma separated list of event ID and event ID ranges to exclude (example: 4,5,7,100-200).
* If no value is present, then there is no effect.
* If you specify both the "whitelist" and "blacklist" attributes, the input ignores the
  "blacklist" attribute.

suppress_text = [0|1]
* Tells Splunk whether or not to include the description of the event text for a given 
  Event Log event.
* Optional. This parameter can be left empty.
* A value of 1 suppresses the inclusion of the event text description.
* A value of 0 includes the event text description.
* If no value is present, defaults to 0.

###
# Active Directory Monitor
###

[admon://<name>]

* This section explains possible attribute/value pairs for configuring Splunk's
  Active Directory Monitor.  
* Each admon:// stanza represents an individually configured Active Directory
  monitoring input. If you configure the input with Splunk Web, then the value 
  of "$NAME" will match what was specified there. While you can add
  Active Directory monitor inputs manually, Splunk recommends that you use the 
  Manager interface to configure Active Directory monitor inputs because it is 
  easy to mistype the values for Active Directory monitor objects.

targetDc = <string>
* Specifies a fully qualified domain name of a valid, network-accessible Active
  Directory domain controller. 
* If not specified, Splunk obtains the local computer's DC by default, and
  binds to its root Distinguished Name (DN).

startingNode = <string>
* Tells Splunk where in the Active Directory directory tree to start monitoring. 
* If not specified, Splunk attempts to start at the root of the directory
  tree.
* The user that you configure Splunk to run as at installation determines where Splunk 
  starts monitoring.

monitorSubtree = [0|1]
* Tells Splunk whether or not to monitor the subtree(s) of a given Active Directory
  tree path.
* Defaults to 1 (monitor subtrees of a given directory tree path).

disabled = [0|1]
* Tells Splunk whether or not the input is enabled.
* Defaults to 0 (enabled.)

index = <string>
* Tells Splunk which index to store incoming data into for this input.
* This field is optional.
* Defaults to the default index.

printSchema = [0|1]
* Tells Splunk whether or not to print the Active Directory schema.
* Defaults to 1 (print schema of Active Directory).

baseline = [0|1]
* Tells Splunk whether or not to query baseline objects.
* Baseline objects are objects which currently reside in Active Directory.
* Baseline objects also include previously deleted objects.
* Defaults to 1 (query baseline objects).

### 
# Windows Registry Monitor
###

[WinRegMon://<name>]

* This section explains possible attribute/value pairs for configuring Splunk's
  Windows Registry Monitor.  
* Each WinRegMon:// stanza represents an individually configured WinRegMon monitoring input.
  If you configure the inputs with Splunk Web, the value of "$NAME" will match what
  was specified there. While you can add event log monitor inputs manually, recommends
  that you use the Manager interface to configure Windows registry monitor inputs because
  it is easy to mistype the values for Registry hives and keys.
* Note: WinRegMon is for local systems ONLY.

proc = <string>
* Tells Splunk which processes this input should monitor for Registry access.
* If set, matches against the process name which performed the Registry
  access.
* Events generated by processes that do not match the regular expression get
  filtered out.
* Events generated by processes that match the regular expression pass
  through.
* There is no default.

hive = <string>
* Tells Splunk the Registry hive(s) that this input should monitor for Registry access.
* If set, matches against the Registry key which was accessed.
* Events that contain hives that do not match the regular expression get
  filtered out.
* Events that contain hives that match the regular expression pass
  through.
* There is no default.

type = <string>
* A regular expression that specifies the type(s) of Registry event(s)
  that you want Splunk to monitor.
* There is no default.

baseline = [0|1]
* Specifies whether or not Splunk should get a baseline of Registry events when it starts.
* If set to 1, the input will capture a baseline for the specified hive when the input
  starts for the first time.
* Defaults to 0 (do not baseline the specified hive first before monitoring live events).

baseline_interval = <integer>
* Specifies how often, in seconds, that the Registry Monitor input should capture a baseline
  for a specific Registry hive or key.
* Defaults to 0 (do not establish a baseline).

disabled = [0|1]
* Specifies whether or not the input is enabled.
* 1 to disable the input, 0 to enable it.
* Defaults to 0 (enabled).

index = <string>
* Specifies the index that this input should send the data to.
* This attribute is optional.
* If no value is present, defaults to the default index.

###
# Windows Host Monitoring
###

[WinHostMon://<name>]

* This section explains possible attribute/value pairs for configuring Splunk's
  Windows host monitor.  
* Each WinHostMon:// stanza represents an WinHostMon monitoring input.
  If you configure the input in SPlunk web, the value of "$NAME" will match what 
  was specified there.
* Note: WinHostMon is for local Windows systems ONLY. You can not monitor Windows host
  information remotely.

type = <semicolon-separated strings>
* An expression that specifies the type(s) of host inputs
  that you want Splunk to monitor.

interval = <integer>
* Specifies the interval, in minutes, between when the input runs to gather Windows host information. 

disabled = [0|1]
* Specifies whether or not the input is enabled.
* 1 to disable the input, 0 to enable it.
* Defaults to 0 (enabled).

index = <string>
* Specifies the index that this input should send the data to.
* This attribute is optional.
* If no value is present, defaults to the default index.

[WinPrintMon://<name>]

* This section explains possible attribute/value pairs for configuring Splunk's
  Windows print Monitor.  
* Each WinPrintMon:// stanza represents an WinPrintMon monitoring input.
  The value of "$NAME" will match what was specified in
  Splunk Web.
* Note: WinPrintMon is for local systems ONLY.

type = <semicolon-separated strings>
* An expression that specifies the type(s) of print inputs
  that you want Splunk to monitor.

baseline = [0|1]
* If set to 1, the input will baseline the current print objects when the input
  is turned on for the first time.
* Defaults to 0 (false), not baseline.

disabled = [0|1]
* Specifies whether or not the input is enabled.
* 1 to disable the input, 0 to enable it.
* Defaults to 0 (enabled).

index = <string>
* Specifies the index that this input should send the data to.
* This attribute is optional.
* If no value is present, defaults to the default index.

[WinNetMon://<name>]

* This section explains possible attribute/value pairs for configuring Splunk's
  Network Monitor.  
* Each WinNetMon:// stanza represents an individually configured network
  monitoring input.  The value of "$NAME" will match what was specified in
  Splunk Web. Splunk recommends that you use the Manager interface to configure
  Network Monitor inputs because it is easy to mistype the values for
  Network Monitor monitor objects, counters and instances.

remoteAddress = <regular expression>
* If set, matches against the remote address.
* Events with remote addresses that do not match the regular expression get
  filtered out.
* Events with remote addresses that match the regular expression pass
  through.
* Example: 192\.163\..*
* Default (missing or empty setting) includes all events

process = <regular expression>
* If set, matches against the process/application name which performed network access
* Events generated by processes that do not match the regular expression are
  filtered out.
* Events generated by processes that match the regular expression are passed
  through.
* Default (missing or empty proc setting) includes all processes/applications

user = <regular expression>
* If set, matches against the user name which performed network access
* Events generated by users that do not match the regular expression are
  filtered out.
* Events generated by users that match the regular expression are passed
  through.
* Default (missing or empty user setting) includes access by all users

addressFamily = ipv4;ipv6
* If set, matches against address family.
* Accepts semicolon separated values, e.g. ipv4;ipv6
* Default (missing or empty address family setting) includes ipv4 and ipv6 traffic

packetType = connect;accept;transport.
* If set, matches against packet type
* Accepts semicolon separated values, e.g. connect;transport
* Default (missing or empty setting) includes all types

direction = inbound;outbound
* If set, matches against direction.
* Accepts semicolon separated values, e.g. incoming;outgoing
* Default (missing or empty setting) includes all types

protocol = tcp;udp
* If set, matches against protocol ids.
* Accepts semicolon separated values
* Protocol are defined in http://www.ietf.org/rfc/rfc1700.txt
* Example of protocol ids: tcp;udp
* Default (missing or empty setting) includes all types

readInterval = <integer>
* Read network driver every readInterval milliseconds.
* Advanced option. We recommend that the default value is used unless there is a problem with input performance.
* Allows adjusting frequency of calls into kernel driver driver. Higher frequencies may affect network performance, while lower frequencies can cause event loss.
* Default value: 100 msec
* Minumum: 10 msec, maximum: 1 sec

driverBufferSize = <integer>
* Keep maximum number of network packets in network driver buffer.
* Advanced option. We recommend that the default value is used unless there is a problem with input performance.
* Controls amount of packets cached in the driver. Lower values may result in event loss. Higher values may increase the size of non-paged memory.
* Default: 32768 packets.
* Minumum: 128 packets, maximum: 32768 packets

userBufferSize = <integer>
* Maximum size in MB of user mode event buffer.
* Advanced option. We recommend that the default value is used unless there is a problem with input performance.
* Controls amount of packets cached in the the usre mode. Lower values may result in event loss. Higher values may increase the size of Splunk network monitor memory.
* Default: 20 MB.
* Minumum: 5 MB, maximum: 500 MB.

mode = single,multikv
* Specifies output mode. Output each event individually or in multikv format.
* Default: single.

multikvMaxEventCount = <integer>
* Advanced option. When multikv mode is used output at most  multikvMaxEventCount events.
* Default: 100 events
* Minumum: 10 events, maximum: 500 events

multikvMaxTimeMs = <integer>
* Advanced option. When multikv mode is used output no later than multikvMaxTimeMs milliseconds.
* Default: 1000 ms
* Minumum: 100 ms, maximum: 5000 ms

disabled = [0|1]
* Tells Splunk whether or not the input is enabled.
* Defaults to 0 (enabled.)

index = <string>
* Tells Splunk which index to store incoming data into for this stanza.
* This field is optional.
* Defaults to the default index.
