# SSL Certificate expiration check

This Python script can be used to check the expiration date of SSL certificates and post an alert in Slack if the expiration date is within a given number of days. A message is also sent to Slack if all certificates are OK, just to let you know that the script did run.

See additional details [on this website](https://technotes.videre.us/en/python/monitoring-ssl-certificates/).

To install the dependencies, please use:
```
pip3 install -r requirements.txt
```

The list of servers and ports to be checked is configurable by editing the `ssl.yaml` file. Multiple port numbers can be provided for each host. The Slack API token should be passed to the script as the `slack_api` environment variable.

The script is multi-threaded for performance and has http retries enabled.

Note that the script does NOT validate the correctness of the certificate or of the certificate chain.

Sample output:
```
python3 check_certificate_expiration.py
2022-07-22 17:25:53,751 - INFO - --------------------------------------------------------------------------------
2022-07-22 17:25:53,751 - INFO - Version:  1.0.2
2022-07-22 17:25:53,751 - INFO - Path:    /Users/me/SSL-Certificate-Expiration-Check/check_certificate_expiration.py
2022-07-22 17:25:53,767 - INFO - {'www.bing.com': [443], 'www.google.com': [443]}
2022-07-22 17:25:53,767 - INFO - Checking certificate on server www.bing.com port 443
2022-07-22 17:25:53,872 - INFO - TLS Version: TLSv1.2
2022-07-22 17:25:53,872 - INFO - TLS Cipher: ECDHE-RSA-AES256-GCM-SHA384
2022-07-22 17:25:53,872 - INFO - Certificate Issuer: Microsoft RSA TLS CA 01, Microsoft Corporation
2022-07-22 17:25:53,883 - INFO - SSL cert for www.bing.com expires on 2022-12-10T01:15:41
2022-07-22 17:25:53,883 - INFO - 140 days, 3:49:47.116068
2022-07-22 17:25:53,884 - INFO - Cert OK
2022-07-22 17:25:53,884 - INFO - ------------------------------
2022-07-22 17:25:53,884 - INFO - Checking certificate on server www.google.com port 443
2022-07-22 17:25:53,982 - INFO - TLS Version: TLSv1.2
2022-07-22 17:25:53,982 - INFO - TLS Cipher: ECDHE-ECDSA-CHACHA20-POLY1305
2022-07-22 17:25:53,982 - INFO - Certificate Issuer: GTS CA 1C3, Google Trust Services LLC
2022-07-22 17:25:53,982 - INFO - SSL cert for www.google.com expires on 2022-09-26T08:25:17
2022-07-22 17:25:53,982 - INFO - 65 days, 10:59:23.017250
2022-07-22 17:25:53,982 - INFO - Cert OK
2022-07-22 17:25:53,983 - INFO - ------------------------------
2022-07-22 17:25:53,983 - INFO - Duration: 0.0000s  <function sendSlack at 0x10abdc7b8>
2022-07-22 17:25:53,984 - INFO - *** DONE ***

```
