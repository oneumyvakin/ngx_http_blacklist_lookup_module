# Simple HTTP DNS blacklist lookup module for Nginx

##Description

This module can be used to protect your server from malicious HTTP bots.<br/>
Modules makes DNS queries to uceprotect.net, blocklist.de and projecthoneypot.org(optional).<br/>
There is internal cache for already checked IP addresses. 

## Installation

   1. Extract module archive into nginx sources folder like nginx-1.3.5/ngx_http_blacklist_lookup_module

   2. Configure Nginx adding this module with:
          
          ./configure (...) --add-module=./ngx_http_blacklist_lookup_module

   3. Build Nginx as usual with `make`, `make install`
   
   4. Configure the module. **server** and **location** context are supported. 
      It's better to apply on location where the application is working, like .php or uwsgi_pass.
      
      Example:
          
          location = /test {
             
            blacklist_lookup on;
            blacklist_lookup_honeyPotAccessKey "KeyString"; # optional, get this from your Project Honey Pot account (free to register) at http://www.projecthoneypot.org/httpbl_configure.php
            blacklist_lookup_verbose on;                    # optional
            blacklist_lookup_hits 2;                        # optional, 1 - default, 3 - max, but has sence if all services are on
            blacklist_lookup_blocklist_de on;               # optional, enables checks on blocklist.de
            blacklist_lookup_uceprotect_net on;             # optional, enables checks on uceprotect.net
            blacklist_lookup_projecthoneypot_org on;        # optional, enables checks on projecthoneypot.org
            blacklist_lookup_bounce "en";                   # optional, "en" - default, "ru" or "en" are supported
          }
	

      
## TODO

	1. Replace internal resolver with ngx_resolver

## ISSUES

	1. Performance degradation is highly possible.
