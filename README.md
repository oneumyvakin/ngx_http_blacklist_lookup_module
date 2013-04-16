# Simple HTTP DNS blacklist lookup module for Nginx

##Description

This module can be used to protect your server from malicious HTTP bots.<br/>
Modules makes DNS queries to uceprotect.net, blocklist.de and projecthoneypot.org(optional).<br/>
There is internal cache for already checked IP addresses. 

## Installation

   1. Configure Nginx adding this module with:
          
          ./configure (...) --add-module=/path/to/nginx-black-list-module
       
   2. Build Nginx as usual with `make`.
   
   3. Configure the module. **server** and **location** context are supported. 
      It's better to apply on location where the application is working, like .php or uwsgi_pass.
      
      Example:
          
          location = /test {
             
            blacklist_lookup on;
            blacklist_lookup_honeyPotAccessKey "KeyString"; # optional, get this from your Project Honey Pot account (free to register) at http://www.projecthoneypot.org/httpbl_configure.php
            blacklist_lookup_verbose on;                    # optional
            blacklist_lookup_bounce "en";                   # optional, "en" - default, "ru" or "en" are supported
          }
	
	4. 
      
## TODO

	1. Replace internal resolver with ngx_resolver
 
	2. Make using uceprotect.net and blocklist.de are optional
