# Container CVE Manager 
>> Web application used to list, manage and export AllowList of CVE for the container development CI/CD platform.

## Requirement
This web application is build using the [Django Framework](https://www.djangoproject.com/), as such it requires some 
software and libraries to be installed on the host computer / server : 
 - Python3 : version >= 3.6
 - Django library : version ~= 3.2.5 
 - Python libraries : 
   - pipenv >= 2021.5.29
   - django-bootstrap-v5 ~= 1.0.4
   - requests ~= 8
   - python-ldap
    
## Installation 
Clone the repository :
```bash
$: cd /opt
$: git clone git@github.com:lucasgrelaud/container_cve_manager.git
$: cd container_cve_manager
```
Setup environment :
```shell
$: pipenv update
$: pipenv shell
$[pipenv_shell]: python -m manage migrate
```
_**Note:** By default Django will use an SQLite database which is not suited for production, please use a proper database 
server for non-development related use._

Configuration can be set in the `container_cve_manager/settings.py`

## Run the web application

### Development:
```shell
$: cd /opt/container_cve_manager
$: pipenv shell
$[pipenv_shell]: python -m manage runserver
```

### Production-like
Check Django documentation on how to setup a server with the WSGI mod of Apache HTTPD : https://docs.djangoproject.com/fr/3.2/howto/deployment/wsgi/modwsgi/

The current configuration is : 

__Please replace <domain.com> with your domain name__
```shell
WSGIPythonPath /opt/container_cve_manager


<VirtualHost *:443>
        ServerName      container-cve-manager.<domain.com>


        # Include specific hearder configuration (security)
        ## The CSP can be configured using https://www.cspisawesome.com
        ## This CSP allow only ressources comming from this host and any of the <domain.com> subdomains
        Header always set Content-Security-Policy: "default-src 'self'; script-src 'self' 'unsafe-inline' unpkg.com cdn.jsdelivr.net cdnjs.cloudflare.com; style-src 'self' 'unsafe-inline' unpkg.com cdn.jsdelivr.net cdnjs.cloudflare.com; img-src 'self' data: unpkg.com cdn.jsdelivr.net cdnjs.cloudflare.com; font-src 'self' unpkg.com cdn.jsdelivr.net cdnjs.cloudflare.com; connect-src 'self' *.<domain.com>"
        ## Change to "*" if you request external ressources (i.e. include analytics script, fetch external API,....)
        Header always set Access-Control-Allow-Origin: "*.<domain.com>"
        Header always set X-XSS-Protection "1; mode=block"
        Header always set X-Content-Type-Options "nosniff"
        ## Set cache control
        Header set Cache-Control no-cache
        Header set Expires: 0
                # Cache static assets for 1 day
                <filesMatch ".(ico|css|js|gif|jpeg|jpg|png|svg|woff|ttf|eot)$">
                        Header set Cache-Control "max-age=86400, public"
                </filesMatch>

        # By default use *.<domain.com> certificate
        SSLCertificateFile /etc/httpd/ssl.crt/cert.<domain.com>.crt
        SSLCertificateKeyFile /etc/httpd/ssl.key/key.<domain.com>.key
        SSLCertificateChainFile /etc/httpd/ssl.crt/cert-chain.<domain.com>.crt-chain


        # Default logs
        ErrorLog /var/log/httpd/container-cve-manager.<domain.com>-error_log
        CustomLog /var/log/httpd/container-cve-manager.<domain.com>-access_log combined


        WSGIScriptAlias / /opt/container_cve_manager/container_cve_manager/wsgi.py

        <Directory /opt/container_cve_manager/container_cve_manager>
                <Files wsgi.py>
                        Require all granted
                </Files>
        </Directory>

</VirtualHost>


<VirtualHost *:80>
        ServerName      container-cve-manager.<domain.com>
        RewriteEngine   On

        RewriteRule ^/(.*) https://container-cve-manager.<domain.com>/$1 [NE]
</VirtualHost>

```