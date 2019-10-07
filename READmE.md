This script gets certificates from the Apache config file, and checks their expiration. If they are about to expire, or are already expired, it shoots an email to the helpdesk so that proper action can be taken.

You must add the proper SMTP settings in the config.ini.template file, and rename this file to config.ini