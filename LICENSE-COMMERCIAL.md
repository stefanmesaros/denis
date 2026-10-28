# Commercial licensing

Any business, non-profit, government or other organisational use of DENIS — and any installation
monitoring more than 100 devices — needs a commercial license (see `LICENSE`, clause 2), except that an organisation may evaluate the Community
edition free of charge for up to 30 days from its first installation, on up to 100 devices (clause 2A). After that
period, continued use needs a commercial license.

A commercial license is a small signed file that raises the device cap (or removes it) for your
installation. It is issued individually; there is no self-service purchase yet.

**To get one, contact the author:** open an issue at
<https://github.com/stefanmesaros/denis/issues> titled "Commercial license", or see the contact
details on the project's GitHub profile. Include roughly how many devices you expect to monitor,
and your **installation ID** (shown under Settings → License): a license is issued for that one
installation and does not work on any other. Nothing about this goes online — you send the ID
yourself, once, so it works air-gapped too.

Once issued, paste it into Settings → License (it takes effect immediately), or point
`--license-file` at it when running `denis serve`/`denis run` and restart. Settings → License shows
who a license is issued to and when it expires.
