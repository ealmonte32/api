from django.apps import AppConfig


class DeviceRegistryConfig(AppConfig):
    name = 'device_registry'

    def ready(self):
        import jsonfield_compat
        jsonfield_compat.register_app(self)
