# Sample: How I automate alerts

Short intro: this is a sample article to show images + code blocks.

![Flow diagram](https://i.pinimg.com/736x/dc/4f/11/dc4f1167b9e629747c6f5c632cea42e7.jpg)

## Why

Explain the idea briefly.

## Steps

1. Generate alerts.
2. Push to a small HTTP server.
3. Firewall pulls the list.

```bash
# example cron
*/5 * * * * /usr/bin/curl -s -o /srv/www/iocs/latest.txt /path/to/generate_iocs.sh
