#   Version 6.0
#
# This file contains possible attributes and values you can use to configure auditing
# and event signing in audit.conf.
#
# There is NO DEFAULT audit.conf. To set custom configurations, place an audit.conf in
# $SPLUNK_HOME/etc/system/local/. For examples, see audit.conf.example.  You must restart 
# Splunk to enable configurations.
#
# To learn more about configuration files (including precedence) please see the documentation 
# located at http://docs.splunk.com/Documentation/Splunk/latest/Admin/Aboutconfigurationfiles

# GLOBAL SETTINGS
# Use the [default] stanza to define any global settings.
#     * You can also define global settings outside of any stanza, at the top of the file.
#     * Each conf file should have at most one default stanza. If there are multiple default
#       stanzas, attributes are combined. In the case of multiple definitions of the same
#       attribute, the last definition in the file wins.
#     * If an attribute is defined at both the global level and in a specific stanza, the
#       value in the specific stanza takes precedence.

#########################################################################################
# EVENT HASHING: turn on SHA256 event hashing.
#########################################################################################

[eventHashing]
	* This stanza turns on event hashing -- every event is SHA256 hashed. 
 	* The indexer will encrypt all the signatures in a block.
 	* Follow this stanza name with any number of the following attribute/value pairs.


filters=mywhitelist,myblacklist...
	* (Optional) Filter which events are hashed.
	* Specify filtername values to apply to events.
	* NOTE: The order of precedence is left to right. Two special filters are provided by default:
blacklist_all and whitelist_all, use them to terminate the list of your filters. For example
if your list contains only whitelists, then terminating it with blacklist_all will result in 
signing of only events that match any of the whitelists. The default implicit filter list 
terminator is whitelist_all.
 
# FILTER SPECIFICATIONS FOR EVENT HASHING

[filterSpec:<event_whitelist | event_blacklist>:<filtername>]
	* This stanza turns on whitelisting or blacklisting for events.
	* Use filternames in "filters" entry (above).
	* For example [filterSpec:event_whitelist:foofilter].
	
all=[true|false]
	* The 'all' tag tells the blacklist to stop 'all' events.
	* Defaults to 'false.'

source=[string]
host=[string]
sourcetype=[string]
# Optional list of blacklisted/whitelisted sources, hosts or sourcetypes (in order from left to right). 
	* Exact matches only, no wildcarded strings supported.
	* For example:
	source=s1,s2,s3...
	host=h1,h2,h3...
	sourcetype=st1,st2,st3...


#########################################################################################
# KEYS: specify your public and private keys for encryption.
#########################################################################################

[auditTrail]
	* This stanza turns on cryptographic signing for audit trail events (set in inputs.conf) 
and hashed events (if event hashing is enabled above).

privateKey=/some/path/to/your/private/key/private_key.pem
publicKey=/some/path/to/your/public/key/public_key.pem
	* You must have a private key to encrypt the signatures and a public key to decrypt them.
	* Set a path to your own keys
	 * Generate your own keys using openssl in $SPLUNK_HOME/bin/.

queueing=[true|false]
	* Turn off sending audit events to the indexQueue -- tail the audit events instead.
	* If this is set to 'false', you MUST add an inputs.conf stanza to tail
	  the audit log in order to have the events reach your index.
	* Defaults to true.
