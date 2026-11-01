# tapolink-proto

An async Python library for TP-Link Tapo (and current Kasa) devices, written from
scratch under Apache-2.0 with no GPL code. Release 0.1 covers two things.

- **Cloud inventory** (`tapolink_proto.cloud`): sign in to the TP-Link cloud (MFA
  supported), refresh tokens, list the account's devices, and read each device's
  current LAN IP from the IoT API. TLS is pinned to TP-Link's own root
  certificates. The cloud is used for inventory only; this library never controls a
  device through it.
- **TDP identity probe** (`tapolink_proto.discovery`): a unicast probe on UDP 20002
  that returns a device's ID, MAC, model and login scheme. Use it to check that the
  device at an IP is the one the cloud listed before you send it credentials. Each
  probe carries a random serial, and only replies that echo it are accepted.

Local device control (AES / KLAP / TPAP) is not in this release.

The Home Assistant helper
[`tapo_onboard`](https://github.com/lasswellt/tapo-homeassistant) uses this
library.

```python
import aiohttp
from tapolink_proto.cloud import CloudClient, build_cloud_ssl_context

async with aiohttp.ClientSession() as http:
    client = CloudClient(
        http,
        ssl_context=build_cloud_ssl_context(),  # blocking; run in an executor
        terminal_uuid=my_stable_uuid4,          # generate once, keep forever
    )
    session = await client.login(email, password)
    for device in await client.list_devices(session):
        details = await client.device_details(session, device)
        print(device.alias, device.model, details.ip)
```

**Rate limits.** TP-Link locks accounts that call the cloud too often (error
`-20004`). Keep it to one login, a device list about every 30 minutes, and a details
lookup only when you need a device's address.

Not affiliated with or endorsed by TP-Link.
