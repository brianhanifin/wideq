import logging
import voluptuous as vol
import homeassistant.helpers.config_validation as cv
from homeassistant.const import STATE_UNKNOWN, STATE_OFF
from homeassistant.helpers.entity import Entity
import time
from homeassistant.components.sensor import PLATFORM_SCHEMA

REQUIREMENTS = ['wideq']

LOGGER = logging.getLogger(__name__)

PLATFORM_SCHEMA = PLATFORM_SCHEMA.extend({
    vol.Required('token'): cv.string,
})
MAX_RETRIES = 5

def setup_platform(hass, config, add_devices, discovery_info=None):
    import wideq

    refresh_token = config.get('token')
    client = wideq.Client.from_token(refresh_token)

    add_devices(LGAppliance(client, device) for device in client.devices)

class LGAppliance(Entity):
    def __init__(self, client, device):
        self._client = client
        self._device = device

        import wideq
        self._appliance = wideq.ApplianceDevice(client, device)
        self._appliance.monitor_start()

        # The response from the monitoring query.
        self._state = None


        self.update()
        
    @property
    def name(self):
        return self._device.name
        
    @property
    def state(self):
        if self._state:
            return self._state.status.name
        else:
            return STATE_OFF
            
    @property
    def time_remaining(self):
        
        return self._state.time_remaining
    
    @property
    def current_course(self):
        return self._state.course
        
    @property
    def initial_time(self):
        return self._state.initial_time
    
    @property
    def device_state_attributes(self):
        """Return the state attributes."""
        if self._state is not None:
            return {
                'Course': self.current_course,
                'Initial time': self.initial_time,
                'Time remaining': self.time_remaining,
                
            }
            
    @property
    def entity_picture(self):
        
        return self._device.image('/home/slaframboise/.homeassistant/')
        
    def update(self):
        """Poll for updated device status.
        Set the `_state` field to a new data mapping.
        """

        import wideq

        LOGGER.info('Updating %s.', self.name)
        for _ in range(MAX_RETRIES):
            LOGGER.info('Polling...')
            
            try:
                state = self._appliance.poll()
            except wideq.NotLoggedInError:
                LOGGER.info('Session expired. Refreshing.')
                self._client.refresh()
                self._appliance.monitor_start()

            if state:
                LOGGER.info('Status updated.')
                self._state = state
                return
                
            LOGGER.info('No status available yet.')
            time.sleep(3)

        # We tried several times but got no result.
        LOGGER.info('Status update failed. Appliance(s) probably turned off.')
        