from django import template
from django.template.defaultfilters import stringfilter

from device_registry.models import PortScan

register = template.Library()


@register.filter
@stringfilter
def split_index(string, args):
    separator, idx = args.split(',')
    idx = int(idx)
    return string.split(separator)[idx]


@register.filter
def keyvalue(dict_obj, key):
    try:
        return dict_obj[key]
    except KeyError:
        return ''


@register.filter
def list_index(list_obj, index):
    try:
        return list_obj[index]
    except IndexError:
        return ''


@register.filter
def get_process_info_html(port_record):
    return PortScan.get_process_info_html(port_record)
