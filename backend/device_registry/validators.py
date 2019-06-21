import re

from django.core import validators
from django.utils.deconstruct import deconstructible
from django.utils.translation import gettext_lazy as _

@deconstructible
class UnicodeNameValidator(validators.RegexValidator):
    regex = r'^[\w.@+-:]+$'
    message = _(
        'Enter a valid name. This value may contain only letters, '
        'numbers, and @/./+/-/_/: characters.'
    )
    flags = re.UNICODE

@deconstructible
class LinuxUserNameValidator(validators.RegexValidator):
    regex = r'^[a-z_][a-z0-9_-]*[$]?$'
    message = _(
        'Enter a valid username. This value may contain only lowercase letters, '
        'numbers, and "_" or "-"  characters.'
    )
    flags = re.ASCII
