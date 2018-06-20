# letsencrypt-dnsimple

Quick hack to use the letsencrypt [DNS challenge](https://letsencrypt.github.io/acme-spec/#rfc.section.7.4) with dnsimple.

Now using dnsimple api v2.

## Running with installed ruby

Requires ruby 2.4.

```bash
$ gem install bundler
$ bundle install
$ DNSIMPLE_ACCESS_TOKEN=... \
  NAMES=foo.org,www/foo.org \
  ACME_CONTACT=mailto:you@foo.org \
  bundle exec ruby main.rb
```

`.pem` files will be written to files named after the value of `NAMES`:

```
foo.org-fullchain.pem
foo.org-privkey.pem
```

## Running with Docker

Check out https://github.com/meskyanichi/dockerized-letsencrypt-dnsimple which wraps this in a Docker container so a ruby install is not needed.

## Config

Comes from the environment.

* `DNSIMPLE_ACCESS_TOKEN`: get this access token from https://dnsimple.com/user
* `NAMES`: a `,`-separated list of names that will be in the requested cert. Use `/` instead of `.` to denote the separation between subdomain and dnsimple domain. For example, to request a cert for `www.example.net`, where `example.net` is the domain dnsimple knows about, you'd use `www/example.net`.
* `ACME_CONTACT`: the contact to use for [registration](https://letsencrypt.github.io/acme-spec/#rfc.section.6.3)
* `LETSENCRYPT_ENDPOINT`: optional, defaults to the production endpoint at `https://acme-v01.api.letsencrypt.org/`
