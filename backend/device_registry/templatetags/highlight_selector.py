from django import template
from django.template.defaultfilters import stringfilter

register = template.Library()


@register.filter
@stringfilter
def is_menu_highlight_id( url_id, value ):
    if isinstance( url_id, str ):
        if url_id == 'root' or url_id.startswith('device-detail'):
            return 'root' == value
    return url_id == value