# ZEEK-JQ
## The following commands are useful when working with ZEEK logs that are in JSON format.

Print out source host and port, destination host and port
<pre><code>cat conn.log | jq -j '.["id.orig_h"], ", ", .["id.orig_p"], ", ",.["id.resp_h"], ", ", .["id.resp_p"], "\n"</code></pre>

Print out source host and port, destination host and port along with connection state.  Look for port 22, sort and unique
<pre><code>zcat conn.* | jq -j 'select(.["id.resp_p"] == 22 and .conn_state == "SF") | .["id.orig_h"], ", ", .["id.resp_h"], ", ", .["id.resp_p"], ", ", .["conn_state"], "\n"' | sort -u</code></pre>

Print smb_share information
<pre><code>cat smb_mapping.log | jq -j '.["id.orig_h"], "\t", .["id.resp_h"], "\t", .["path"], "\t", .["share_type"],"\n"' | grep -v null | sort -u</code></pre>

Print syslog.log messages (source host and message) if the facility field is equal to "LOCAL0"
<pre><code>zcat syslog* | jq -j 'select(.facility == "LOCAL0") | .["id.orig_h"], "\t", .["message"], "\n"'</code></pre>

Print the originating host of a DNS query for the query type "TKEY"
<pre><code>zcat dns* | jq -j 'select(.qtype_name == "TKEY") | "Originator", ": ", .["id.orig_h"], "\n"'</code></pre>

Print a column header with source, destination and duration names.  Select the source and destination from conn.log where the duration is # greater than 10000 seconds.
<pre><code>echo -e "source\t\tdestination\t\tduration" && zcat conn.* | jq -j 'select(.duration > 10000) | .["id.orig_h"], "\t", .["id.resp_h"], "\t", .duration, "\n"'</code></pre>

Print and sort all users who's accounts were locked out from Zeek kerberos log archive.
<pre><code>zcat kerberos.* | jq -j 'select(.error_msg == "KDC_ERR_CLIENT_REVOKED") | .["id.orig_h"], "\t", .["error_msg"], "\t", .["client"], "\n"' | grep -v null | sort | uniq -c | sort -n -r</code></pre>

Print log messages associated with a specific zeek uid from all archived logs
<pre><code>ls -la *.gz | awk '{print $9}' | while read line; do zcat $line |jq 'select(.uid == "Cb0Tr91RJWdZQCia4")' ;done 2>/dev/null</code></pre>

Iterate through all Zeek log directories.  Find kerberos failed login messages.  Write out source ip and kerberos clients with count # totals to a csv file
<pre><code>ls -dl 2021-0* | awk '{print $9}' | while read line; do ls $line | while read file; do echo $line/$file | grep kerberos | while read line; do zcat $line |jq -j 'select(.error_msg == "KDC_ERR_PREAUTH_FAILED") | ",", .["id.orig_h"], ",", .client, "\n"' ;done; done; done | sort | uniq -c | sort -n -r >> /home/hunter/top_failed_logons.csv</code></pre>

Iterate through all Zeek log directories.  Find Kerberos Locked Account messages.  Write out source ip and kerberos clients with count totals to a csv file.
<pre><code>ls -dl 2021-0* | awk '{print $9}' | while read line; do ls $line | while read file; do echo $line/$file | grep kerberos | while read line; do zcat $line |jq -j 'select(.error_msg == "KDC_ERR_CLIENT_REVOKED") | ",", .["id.orig_h"], ",", .client, "\n"' ;done; done; done | sort | uniq -c | sort -n -r >> /home/hunter/top_locked_accounts.csv</code></pre>

Iterate through all Zeek log directories. Find conn logs. Print out all SSL connections that are less than 1 second in duration with a connection state of 'SF' and a responding port of 443. Write the count, requesting host, responding host, responding port and connection state in csv format to a file.
<pre><code>ls -dl 2021-0* | awk '{print $9}' | while read line; do ls $line | while read file; do echo $line/$file | grep -P "conn\." | while read line; do zcat $line | jq -j 'select((.duration < 1) and .conn_state == "SF" and .["id.resp_p"] == 443) | ",",.["id.orig_h"], ",", .["id.resp_h"], ",", .["id.resp_p"], ",",.conn_state, "\n"' ;done; done; done | sort | uniq -c |sort -n -r > ~/ssl_short_duration.csv</code></pre>
