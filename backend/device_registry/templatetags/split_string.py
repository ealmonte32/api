from django import template
from django.template.defaultfilters import stringfilter

register = template.Library()


@register.filter
@stringfilter
def split_index(string, args):
    separator, idx = args.split(',')
    idx = int(idx)
    return string.split(separator)[idx]
