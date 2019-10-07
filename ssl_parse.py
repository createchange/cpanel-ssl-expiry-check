#! /usr/bin/env python2.7
import subprocess
from datetime import datetime, timedelta
import smtplib, ssl
import socket
import sys
import configparser

def get_cert_paths():
        '''
        Gets all cert paths from apache config, discards entry not related to account.
        Returns list of certificate paths.
        '''
        cert_paths = []

        x = subprocess.Popen("grep SSLCertificateFile /usr/local/apache/conf/httpd.conf", shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT).communicate()[0].split("\n")

        for line in x:
                if "mycpanel.pem" in line or line == "":
                        pass
                else:
                        cert_paths.append(line.lstrip().split(" ")[1])

        return cert_paths


def get_cert_info(cert_paths):
        '''
        Retrieves certificate information using openssl utility, Creates and returns a list of dicts. Each dict is comprised as such:
        {domain: issuer[0], notbefore[1], notafter[2]}
        '''
        cert_info = []
        for cert_path in cert_paths:
                domain_info = {}
                cert_subject = subprocess.Popen("openssl x509 -noout -in %s -subject" % cert_path, shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT).communicate()[0].split("CN=")
		try:
                	cert_subject = cert_subject[1].strip("\n")
		except:
			print("Failed.\n\nPlease run as root.")
			exit()

                cert_issuer = subprocess.Popen("openssl x509 -noout -in %s -issuer" % cert_path, shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT).communicate()[0].split("CN=")
                cert_issuer = cert_issuer[1].strip("\n")

                cert_startDate = subprocess.Popen('date -d "`openssl x509 -dates -noout -in %s |grep Before | cut -d= -f2-`" "+%%F"' % cert_path, shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT).communicate()[0].strip('\n')

                cert_endDate = subprocess.Popen('date -d "`openssl x509 -dates -noout -in %s |grep After| cut -d= -f2-`" "+%%F"' % cert_path, shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT).communicate()[0].strip('\n')

                domain_info[cert_subject] = [cert_issuer, cert_startDate, cert_endDate]
                cert_info.append(domain_info)

        return cert_info


def get_time_til_expiry(cert_info):
        '''
        Converts cert expiration in openssl output into datetime object, then use this to find out what is less than 10 days from expiring.
        Returns two lists of dicts, one for certs expiring_soon and one for certs expired_already.
        '''
        expiring_soon = []
        expired_already = []
        for domain in cert_info:
                for k,v in domain.items():
                        cert_expiration = datetime.strptime(v[2], '%Y-%m-%d')
                        current_date = datetime.now()
                        delta = cert_expiration - current_date
                        v.append(delta.days)
                        if delta > timedelta(days=10):
                                pass
                        elif delta <= timedelta(days=10) and delta > timedelta(days=0):
                                print(k)
                                print("Certificate expiring soon!")
                                print("Days til expiration: %s" % delta.days)
                                expiring_soon.append(domain)
                                print('\n')
                        elif delta <= timedelta(days=0):
                                print(k)
                                print("Certificated expired!")
                                print("Expired %s days ago." % int(delta.days))
                                expired_already.append(domain)
                                print('\n')

        if expiring_soon:
                print("Expiring soon:")
                for entry in expiring_soon:
                        print(entry.keys()[0])
                print("\n")
        if expired_already:
                print("Expired already: ")
                for entry in expired_already:
                        print(entry.keys()[0])
                print("\n")

        return expiring_soon, expired_already


def email_results(entry, expired_already=None):
        '''
        Emails users or expiring_soon and expired_already lists, with appropriate text as per the circumstance.
        '''
	for k,v in entry.items():
                smtp_server = ['smtp_settings']['smtp_server']
                port = ['smtp_settings']['port']
                sender = ['smtp_settings']['sender']
                password = ['smtp_settings']['password']
                receiver = ['smtp_settings']['receiver']
                if expired_already:
                        subject = "INT, %s, SSL certificate for %s expired on %s!" % (socket.gethostname()[:8], k, v[2])
                        text = "For domains that have expired already, check the nameserver / DNS records to see where the site/services are actually hosted. Chances are that the domain is hosted elsewhere, and the certificate is a remnant of the past."
                else:
                        subject = "INT, %s, SSL certificate for %s expiring in %s days!" % (socket.gethostname()[:8], k, v[3])
                        text = "Certificate issuer: %s\n\nIf cPanel issued the cert, check for AutoSSL errors. If issued elsewhere, alert Patricia Manu (pnm@intinc.com) to get this resolved before the certificate lapses." % v[0]
                message = 'Subject: {}\n\n{}'.format(subject, text)
		if "--debug" not in sys.argv:
			# Try to log in to server and send email
	                try:
	                        server = smtplib.SMTP(smtp_server,port)
	                        server.ehlo() # Can be omitted
	                        server.starttls() # Secure the connection
	                        server.ehlo() # Can be omitted
	                        server.login(sender, password)
	                        server.sendmail(sender, receiver, message)
	                except Exception as e:
	                    # Print any error messages to stdout
	                        print(e)
	                finally:
	                        server.quit()

if "--debug" in sys.argv:
	print("========== RUNNING IN DEBUG MODE ==========")
print("\n")
print("Getting certificate paths from Apache config file.")
cert_paths = get_cert_paths()
print("Done.")
print("Getting certificate info...")
cert_info = get_cert_info(cert_paths)
print("Done.")
print("Parsing certificate info for expiration dates...")
expiring_soon, expired_already = get_time_til_expiry(cert_info)
print("Done.")

if '--debug' in sys.argv:
	print("Not sending emails as script was run with --debug flag.")  
	
if expiring_soon:
        for entry in expiring_soon:
                email_results(entry)
if expired_already:
        for entry in expired_already:
                email_results(entry, expired_already=True)
