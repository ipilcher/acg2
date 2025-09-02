# ACME Certificate Getter v2

&copy; 2023, 2024, 2025 Ian Pilcher <<arequipeno@gmail.com>>

* [**How it works**](#how-it-works)
  * [Certificate specs](#certificate-specs)
  * [Retrieving certificates](#retrieving-certificates)
  * [Updating services](#updating-services)
* [**Installation**](#installation)
* [**Configuration examples**](#configuration-examples)
  * [Apache HTTP Server](#apache-http-server)

## How it works

**ACG** consists of multiple components that work together to manage
certificates and update dependent services:

* 2 executable programs &mdash; the ACME Certificate Getter (`acg`) and the
  certificate file mover (`acg-cfm`), and

* A set of **systemd** units (service templates, targets, and timers) that
  manage the programs.

`acg` and `acg-cfm` are both simple, one-shot programs.  Each performs just a
few actions and then exits.  Coordination of the two programs, managing
multiple certificates and services, is mostly left to **systemd** (as configured
by the provided unit files).

### Certificate specs

Certificate specifications (specs) are a core concept of **ACG**.  Each managed
certificate is uniquely identifies by its spec, which consists of a hostname,
optionally prefixed by a service name and a colon (`:`).

For example:

* `httpd:www.example.com`
* `httpd:example.com`
* `cups:example.com`
* `www.example.com`

### Retrieving certificates

Certificates are periodically checked and refreshed by the following components.

* The Let's Encrypt client (`/usr/local/bin/acg`) retrieves a certificate for a
  single certificate spec.  If `acg` is successful, and the spec includes a
  service name, it creates (touches) a reload flag file at
  `/run/acg/${SERVICE_NAME}-reload`.

* `/etc/systemd/system/acg-pem@.service` and
  `/etc/systemd/system/acg-pkcs12@.service` are **systemd** service templates
  that use `acg` to download certificates and save them in PEM or PKCS#12
  format respectively.

* `/etc/systemd/system/acg.target` is a **systemd** target that groups
  `acg-pem@.service` and `acg-pkcs12@.service` instances together.

* `/etc/systemd/system/acg.timer` is a **systemd** timer that periodically
  starts `acg.target`, which starts all `acg-pem@service` and
  `acg-pkcs12@.service` instances.

The sequence of events is:

1. `acg.timer` elapses and activates (starts) `acg.target`.

1. `acg.target` starts all instances of `acg-pem@.service` and
   `acg-pkcs12@.service` symlinked in `/etc/systemd/system/acg.target.wants`.

1. Each `acg` instance first looks for an existing certificate at
   `/var/lib/acg/${CERT_SPEC}.crt`.  If it finds one, and that certificate has a
   remaining lifetime of at least 30 days, `acg` immediately exits.

   If `acg` does not find an existing certificate, or the existing certificate
   has a remaining lifetime of less than 30 days, `acg` requests a new
   certificate from Let's Encrypt.

   * When `acg` retrieves a new certificate for a spec that includes a service
     name it touches the reload flag file for that service.

   * `acg` uses advisory locks on `/run/acg/lock` to serialize multiple
     instances.

### Updating services

Copying certificate and private key files into their final locations and
reloading services is handled by another set of components.

* The certificate file mover (`/usr/local/bin/acg-cfm`) copies certificate and
  key files, and sets their ownership, mode, and SELinux context, based on a
  simple configuration file.

* `/etc/systemd/system/acg-cfm@.service` is a **systemd** service template that
  runs `acg-cfm` with a service-specific configuration file and then reloads the
  service.

  Unlike `acg-pem@service` and `acg-pkcs12@.service`, which should be
  instantiated per certificate spec, this service template is intended to be
  instantiated per service name.  Thus, an Apache web server that hosts two
  domains could have the following service instances enabled.

  * `acg-pem@httpd:www.foo.com.service`
  * `acg-pem@httpd:www.bar.com.service`
  * `acg-reload@httpd.service`

* `/etc/systemd/system/acg-reload.target` is a **systemd** target that groups
  `acg-cfm@.service` instances (and other services) together.

  In some cases, `acg-cfm@.service` may not provide all of the functionality
  needed to update a service.  (For example, a service might require its
  certificate to be stored in a format other than PEM or PKCS#12.)  In this
  situation, a custom service unit, that performs the required steps, can be
  added to `acg-reload.target`.

* `/etc/systemd/system/acg-reload.timer` is a **systemd** timer that
  periodically starts `acg-reload.target`, which starts all of the services
  (`acg-cfm@.service` instances and others) that have been added to that target.

The sequence of events is:

1. `acg-reload.timer` elapses and activates (starts) `acg-reload.target`.

1. `acg-reload.target` atempts to start all services that are symlinked in
   `/etc/systemd/system/acg-reload.target.wants`.  These may be instances of
   `acg-cfm@.service` or custom services.

   An `acg-cfm@.service` instance will only start if its corresponding reload
   flag file (`/run/acg/${SERVICE_NAME}-reload`) exists (i.e. at least one new
   certificate has been retrieved for that service).

1. Each instance of `acg-cfm` reads its configuration file
   (`/etc/acg/cfm/${SERVICE_NAME}.conf`) and copies the files listed therein
   to their final locations, setting their ownership, permissions, and
   SELinux contexts as specified in the configuration.

   As a final step (if no errors were encountered), each instance of
   `acg-cfm@.service` deletes its reload flag file, so that it won't run
   again until at least one new certificate has been retrieved for its service.

## Installation

> **NOTES:**
>
> * Commands with a `$` prompt below should be run as a normal user from the
>   top-level directory of this repository.
>
> * Commands with a `#` prompt must be run with `root` privileges, possibly
>   using `sudo`.
>
> * The steps shown below assume that **ACG** is to be installed on the same
>   system that is used to clone this repository and build the SELinux modules
>   and certificate file mover executable.  If that is not the case, adjust the
>   steps to include copying the required files from the build system to the
>   target system.
>
> * These instructions were written using Fedora 42.  On that distribution
>   the following packages are required.
>
>   * Build depencies:
>     * `make` and `selinux-policy-devel` (to build the SELinux policy modules)
>     * `gcc`, `libselinux-devel`, and `systemd-devel` (to build the certificate
>       file mover)
>
>   * Runtime dependencies:
>     * `python3-acme` and `python3-cryptography` (for the Let's Encrypt client)
>     * `libselinux`, `systemd-libs`, and `polkit` (for the certificate file
>       mover)

Build the SELinux policy modules.

```
$ make -C selinux -f /usr/share/selinux/devel/Makefile
make: Entering directory '/home/pilcher/projects/acg2/selinux'
Compiling targeted acg module
Creating targeted acg.pp policy package
Compiling targeted cfm module
Creating targeted cfm.pp policy package
rm tmp/cfm.mod.fc tmp/acg.mod tmp/cfm.mod tmp/acg.mod.fc
make: Leaving directory '/home/pilcher/projects/acg2/selinux'
```

Install the policy modules.

```
# semodule -i selinux/{acg.pp,cfm.pp}
```

Create the `acg` and `acg-cfm` users (and groups).

```
# useradd -c 'ACME Certificate Getter' -d /var/lib/acg -r -s /usr/bin/nologin acg
# useradd -c 'ACG Certificate File Mover' -d /tmp -r -s /usr/bin/nologin acg-cfm
```

Build the `acg-cfm` executable.

```
$ gcc -O2 -Wall -Wextra -o acg-cfm cfm.c -lselinux -lsystemd
```

Install the executables.

```
# cp acg acg-cfm /usr/local/bin/
# restorecon /usr/local/bin/acg*
```

Set up the ACG state directory.

```
# mkdir -p /var/lib/acg/private
# chown -R acg:acg /var/lib/acg
# chmod 0700 /var/lib/acg/private
# restorecon -R /var/lib/acg
```

Set up the configuration directory, which contains certificate signing requests,
Let's Encrypt client key(s), and certificate file mover configuration files.

```
# mkdir -p /etc/acg/{cfm,private}
# chown -R acg:acg /etc/acg
# chmod 0500 /etc/acg/private
# restorecon -R /etc/acg
```

Create the ACME challenge directory.

```
# mkdir /var/www/acme-challenge
# chown acg:acg /var/www/acme-challenge
# restorecon /var/www/acme-challenge
```

Install the `systemd-tmpfiles` configuration, which creates the `/run/acg`
directory when the system starts.

```
# cp tmpfiles.conf /etc/tmpfiles.d/acg.conf
```

Install the `systemd` units.

```
# cp systemd/* /etc/systemd/system/
# systemctl daemon-reload
```

Enable (and start) the timers.

```
# systemctl enable acg.timer acg-reload.timer --now
Created symlink '/etc/systemd/system/timers.target.wants/acg.timer' → '/etc/systemd/system/acg.timer'.
Created symlink '/etc/systemd/system/timers.target.wants/acg-reload.timer' → '/etc/systemd/system/acg-reload.timer'.
```

## Configuration examples

**ACG** is designed to accomodate a wide variety of system and service
configurations, so there is no single correct configuration.  This section
contains configuration examples that illustrate its operation.

### Apache HTTP Server

This example shows a configuration for an Apache HTTP server hosting 3 domains
&mdash; `foo.example.com`, `bar.example.com`, and `baz.example.com`.

> **NOTE:**  This example assumes that HTTP will be used only for Let's Encrypt
> challenges.  All other access to the subject domains will use HTTPS.

Add a virtual host to the Apache configuration for ACME `HTTP-01` challenges.
(**ACG** does not support other challenge types.)

```apacheconf
<VirtualHost 172.31.255.2:80>
    ServerName foo.example.com
    ServerAlias bar.example.com
    ServerAlias baz.example.com
    RedirectMatch 404 "^(?!/.well-known/acme-challenge/)"
    Alias /.well-known/acme-challenge/ /var/www/acme-challenge/
</VirtualHost>
```

Create a `VirtualHost` for each TLS-enabled domain.  (**ACG** does not support
certificates with multiple Subject Alternative Names, so separate certificates
and separate virtual hosts are required.)  A virtual host for `foo.example.com`
might look like this.

```apacheconf
<VirtualHost 172.31.255.2:443>
        ServerName foo.example.com
        DocumentRoot /var/www/foo
        SSLEngine on
        SSLProtocol all -SSLv3 -TLSv1 -TLSv1.1
        SSLHonorCipherOrder on
        SSLCipherSuite PROFILE=SYSTEM
        SSLProxyCipherSuite PROFILE=SYSTEM
        SSLCertificateFile /etc/pki/tls/certs/foo.crt
        SSLCertificateKeyFile /etc/pki/tls/private/foo/foo.key
</VirtualHost>
```

Create a certificate file mover configuration for the `httpd` service
(`/etc/acg/cfm/httpd.conf`).

```
/var/lib/acg/httpd:foo.example.com.crt          /etc/pki.tls/certs/foo.crt          root  root  0644  cert_t
/var/lib/acg/private/httpd:foo.example.com.key  /etc/pki/tls/private/httpd/foo.key  root  root  0600  cert_t
/var/lib/acg/httpd:bar.example.com.crt          /etc/pki/tls/certs/bar.crt          root  root  0644  cert_t
/var/lib/acg/private/httpd:bar.example.com.key  /etc/pki/tls/private/httpd/bar.key  root  root  0600  cert_t
/var/lib/acg/httpd:baz.example.com.crt          /etc/pki/tls/certs/baz.crt          root  root  0644  cert_t
/var/lib/acg/private/httpd:baz.example.com.key  /etc/pki/tls/private/httpd/baz.key  root  root  0600  cert_t
```

> **NOTES:**
>
> * Certificate file mover configurations use a whitespace-separated tabular
>   format.  The fields, in order, are:
>
>   * Source file,
>   * Destination file,
>   * Owning user name,
>   * Owning group name,
>   * Permissions (mode), and
>   * SELinux context.
>
> * The SELinux context field is optional.  If it is omitted, the file mover
>   will not adjust the context of the destination file, which should result in
>   the file inheriting the context of its directory.
>
> * If the context field is present, it can be specified in any of the following
>   ways.
>
>   * A single hyphen (`-`) instructs the file mover to set the destination's
>     context to the default context defined for that path by the system's
>     SELinux policy (as if `restorecon -f` were run on the file).
>
>   * If the context does not include a colon (`:`), the file mover will
>     interpret it as an SELinux type, and the destination's context will be set
>     to `system_u:object_r:${TYPE}:s0`.
>
>   * If the context does include a colon, the file mover will interpret it as a
>     full SELinux file context specification set the destination's context
>     accordingly.

Create a directory for the private keys.  On my Fedora 42 ystem, the
`openssl-libs` RPM sets the permissions of `/etc/pki/tls/private` to `0755`,
which makes it world-readable (which is almost certainly a bad idea).  To
ensure that private keys within this directory can't be accessed
inappropriately, all of its contents should be stored in subdirectories with
more restrictive permissions.  On Fedora, `httpd` starts as `root` before
dropping privileges, so it's private key directory should only be accessible by
the `root` user.

```
# mkdir /etc/pki/tls/private/httpd
# chmod 0700 /etc/pki/tls/private/httpd
```

Create a **PolicyKit** rule (`/etc/polkit-1/rules.d/acg-cfm-httpd.rules`) to
allow the certificate file mover service to reload the `httpd` service.

```javascript
polkit.addRule(function(action, subject) {
    if (subject.user == "acg-cfm"
            && action.id == "org.freedesktop.systemd1.manage-units"
            && action.lookup("unit") == "httpd.service"
            && action.lookup("verb") == "reload-or-restart") {
        return polkit.Result.YES;
    }
})
```

Place the Let's Encrypt account key in the configuration directory.  The account
key can be used for multiple certificates, so use symlinks to create
certificate-specific file paths.

```
# cp acme-client.key /etc/acg/private/
# chmod 0400 /etc/acg/private/acme-client.key
# ln -s acme-client.key /etc/acg/private/httpd:foo.example.com-acme-client.key
# ln -s acme-client.key /etc/acg/private/httpd:bar.example.com-acme-client.key
# ln -s acme-client.key /etc/acg/private/httpd:baz.example.com-acme-client.key
# restorecon /etc/acg/private/*
```

Create a certificate signing request (CSR) for each certificate.  These CSRs
will be used as "templates" to generate a new CSR, signed by a new private key,
for each request that is sent to Let's Encrypt.  Thus, there is no need to save
the private keys used to create these requests.

```
$ openssl req -new -nodes -keyout /dev/null -subj /CN=foo.example.com -out foo.csr
︙
-----

$ openssl req -new -nodes -keyout /dev/null -subj /CN=bar.example.com -out bar.csr
︙
-----


$ openssl req -new -nodes -keyout /dev/null -subj /CN=baz.example.com -out baz.csr
︙
-----
```

> **NOTE:**  Using template CSRs allows for customization of the subject name or
> extensions of certificate requests that are sent to Let's Encrypt.  (It is
> not guaranteed that Let's Encrypt will include all of the requested options in
> the certificates that it generates.)

Copy the CSR templates into the configuration directory.

```
# cp foo.csr /etc/acg/httpd:foo.example.com.csr
# cp bar.csr /etc/acg/httpd:bar.example.com.csr
# cp baz.csr /etc/acg/httpd:baz.example.com.csr
# restorecon /etc/acg/*.csr
```

Finally, enable the service instances for the certificates and `httpd`.

```
# systemctl enable acg-pem@httpd:foo.example.com.service
Created symlink '/etc/systemd/system/acg.target.wants/acg-pem@httpd:foo.example.com.service' → '/etc/systemd/system/acg-pem@.service'.

# systemctl enable acg-pem@httpd:bar.example.com.service
Created symlink '/etc/systemd/system/acg.target.wants/acg-pem@httpd:bar.example.com.service' → '/etc/systemd/system/acg-pem@.service'.

# systemctl enable acg-pem@httpd:baz.example.com.service
Created symlink '/etc/systemd/system/acg.target.wants/acg-pem@httpd:baz.example.com.service' → '/etc/systemd/system/acg-pem@.service'.

# systemctl enable acg-cfm@httpd.service
Created symlink '/etc/systemd/system/acg-reload.target.wants/acg-cfm@httpd.service' → '/etc/systemd/system/acg-cfm@.service'.
```

Rather than waiting for `acg.timer` and `acg-reload.timer` to elapse and start
the services, they can be started manually by starting their associated targets.

To request the certificates:

```
# systemctl start acg.target
```

To check the status of one of the certificates:

```
# systemctl status acg-pem@httpd:foo.example.com.service
︙
```

Or:

```
# journalctl -u acg-pem@httpd:foo.example.com.service
︙
```
