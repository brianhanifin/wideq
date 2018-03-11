import requests
from urllib.parse import urljoin, urlencode, urlparse, parse_qs
import uuid
import base64
import json
import hashlib 
import wideq
import json
import time
import sys

STATE_FILE = 'wideq_state.json'


def authenticate(gateway):
    """Interactively authenticate the user via a browser to get an OAuth
    session.
    """

    login_url = gateway.oauth_url()
    print('Log in here:')
    print(login_url)
    print('Then paste the URL where the browser is redirected:')
    callback_url = input()
    return wideq.Auth.from_url(gateway, callback_url)


def ls(client):
    """List the user's devices."""

    for device in client.devices:
        print('{0.id}: {0.name} ({0.model_id})'.format(device))


def mon(client, device_id):
    """Monitor any device, displaying generic information about its
    status.
    """

    device = client.get_device(device_id)
    model = client.model_info(device)

    with wideq.Monitor(client.session, device_id) as mon:
        try:
            while True:
                time.sleep(1)
                print('Polling...')
                res = mon.poll()
                        
                if res:
                    if isinstance(res, list):
                        for key, item in enumerate(res):
                            protocol = model.data['Monitoring']['protocol']
                            values = model.data['Value']
                            try:
                                print('key: ', key)
                                desc = protocol[key]['value']
                                print('desc: ', desc)
                                value = values[desc]
                                
                                if value['type'] == "Enum":
                                    info = value['option'][str(item)]
                                elif value['type'] == "Range":
                                    info = item
                                else:
                                    info = 'data not supported: ' + str(item)
                                
                                print('{}:  {}'.format(desc, info))
                            except KeyError as e:
                                print('Invalid Key: {} - {} -- error: {}'.format(key, item, e.args[0]))
                    else:
                        for key, value in res.items():
                            try:
                                desc = model.value(key)
                            except KeyError:
                                print('- {}: {}'.format(key, value))
                            if isinstance(desc, wideq.EnumValue):
                                print('- {}: {}'.format(
                                    key, desc.options.get(value, value)
                                ))
                            elif isinstance(desc, wideq.RangeValue):
                                print('- {0}: {1} ({2.min}-{2.max})'.format(
                                    key, value, desc,

                                ))

        except KeyboardInterrupt:
            pass


def ac_mon(client, device_id):
    """Monitor an AC/HVAC device, showing higher-level information about
    its status such as its temperature and operation mode.
    """

    ac = wideq.ACDevice(client, client.get_device(device_id))

    try:
        ac.monitor_start()
        while True:
            time.sleep(1)
            state = ac.poll()
            if state:
                print(
                    '{1}; '
                    '{0.mode.name}; '
                    'cur {0.temp_cur_f}°F; '
                    'cfg {0.temp_cfg_f}°F'
                    .format(
                        state,
                        'on' if state.is_on else 'off'
                    )
                )

    except KeyboardInterrupt:
        pass
    finally:
        ac.monitor_stop()
        
def appliance_mon(client, device_id):
    """Monitor an Appliance and show high level current information
    
    """
    
    appliance = wideq.ApplianceDevice(client, client.get_device(device_id))
    
    try:
        device_available = appliance.monitor_start()
        if device_available:
            while True:
                time.sleep(2)
                state = appliance.poll()

                if state:
                    print(state.get_polled_data())
                    print(state.is_on)
                    print(state.state)
        else:
            print('Device unreachable, is it powered on?')

    except KeyboardInterrupt:
        pass
    finally:
        appliance.monitor_stop()

def set_temp(client, device_id, temp):
    """Set the configured temperature for an AC device."""

    ac = wideq.ACDevice(client, client.get_device(device_id))
    ac.set_fahrenheit(int(temp))


def turn(client, device_id, on_off):
    """Turn on/off an AC device."""

    ac = wideq.ACDevice(client, client.get_device(device_id))
    ac.set_on(on_off == 'on')


def getDeviceInfo(client, device_id):
    device = client.get_device(device_id)
    deviceName = device.name
    
    with open(deviceName + '_info.json', 'w') as outfile:
        json.dump(device.data, outfile)
    
    
def getModelInfo(client, device_id):
    device = client.get_device(device_id)
    model = client.model_info(device)
    modelName = model.data['Info']['modelName']
    
    with open(modelName + '_info.json', 'w') as outfile:
        json.dump(model.data, outfile)
    
    
    
EXAMPLE_COMMANDS = {
    'ls': ls,
    'mon': mon,
    'ac-mon': ac_mon,
    'set-temp': set_temp,
    'turn': turn,
    'dev': getDeviceInfo,
    'model': getModelInfo,
    'app-mon': appliance_mon,
}


def example_command(client, args):
    if not args:
        ls(client)
    else:
        func = EXAMPLE_COMMANDS[args[0]]
        func(client, *args[1:])
        



def example(args):
    # Load the current state for the example.
    try:
        with open(STATE_FILE) as f:
            state = json.load(f)
    except IOError:
        state = {}

    client = wideq.Client.load(state)

    # Log in, if we don't already have an authentication.
    if not client._auth:
        client._auth = authenticate(client.gateway)

    # Loop to retry if session has expired.
    while True:
        try:
            example_command(client, args)
            break

        except wideq.NotLoggedInError:
            print('Session expired.')
            client.refresh()

    # Save the updated state.
    state = client.dump()
    with open(STATE_FILE, 'w') as f:
        json.dump(state, f)


if __name__ == '__main__':
    example(sys.argv[1:])