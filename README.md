# nagios

## cisco webex teams

### host notification

```
notify_webhook.py -u https://webexapis.com/v1/webhooks/incoming/xxxxxxxx --host --use-ciscowebex --link-base-url https://nagios/xxxx/
```

### service notification

```
notify_webhook.py -u https://webexapis.com/v1/webhooks/incoming/xxxxxxxx --use-ciscowebex --link-base-url https://nagios/xxxx/
```