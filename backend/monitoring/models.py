from django.db import models


class CeleryPulseTimestamp(models.Model):
    timestamp = models.DateTimeField(auto_now=True)
