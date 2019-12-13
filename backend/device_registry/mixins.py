from urllib.parse import unquote

from django.utils import timezone
from django.db.models import Q
from django.http import HttpResponseForbidden

from rest_framework.exceptions import ValidationError
import dateutil
import dateutil.parser

from .models import Tag


class DeviceListFilterMixin:
    """
    Mixin with device list filtering functionality
    """
    FILTER_FIELDS = {
        'device-name': (
            ['deviceinfo__fqdn', 'name'],
            'Node Name',
            'str'
        ),
        'hostname': (
            'deviceinfo__fqdn',
            'Hostname',
            'str'
        ),
        'comment': (
            'comment',
            'Comment',
            'str'
        ),
        'last-ping': (
            'last_ping',
            'Last Ping',
            'datetime'
        ),
        'trust-score': (
            'trust_score_prcnt',
            'Trust Score',
            'float'
        ),
        'default-credentials': (
            'deviceinfo__default_password',
            'Default Credentials Found',
            'bool'
        ),
        'tags': (
            'tags__name',
            'Tags',
            'tags'
        )
    }
    PREDICATES = {
        'str': {
            'eq': 'iexact',
            'c': 'icontains'
        },
        'tags': {
            'c': 'in'
        },
        'float': {
            'eq': 'exact',
            'lt': 'lt',
            'gt': 'gt'
        },
        'datetime': {
            'eq': 'exact',
            'lt': 'lt',
            'gt': 'gt'
        },
        'bool': {
            'eq': 'exact'
        }
    }

    def get_filter_q(self, set_filter_dict=False):
        """
        Create Device List Filter Query Object
        GET params:
        filter_by : filter field argument. (see self.FILTER_FIELDS)
        filter_value: value used for filtering
        filter_predicate:
                "eq" - matches
                "neq" - not matches
                "c" - contains
                "nc" - not contains
                "lt" - greater than
                "gt" - less than
        :return: Q object
        """
        query = Q()
        filter_by = self.request.GET.get('filter_by')
        filter_predicate = self.request.GET.get('filter_predicate')
        filter_value = self.request.GET.get('filter_value')
        since = self.request.GET.get('since')

        if filter_by and filter_predicate:
            if filter_by not in self.FILTER_FIELDS:
                raise ValidationError('filter subject is invalid.')

            query_by, _, query_type = self.FILTER_FIELDS[filter_by]
            invert = filter_predicate[0] == 'n'
            orig_filter_predicate = filter_predicate  # Keep original value for restoring filter in the UI.
            if invert:
                filter_predicate = filter_predicate[1:]
            if filter_predicate not in ['', 'eq', 'c', 'lt', 'gt']:
                raise ValidationError('filter predicate is invalid.')

            predicate = self.PREDICATES[query_type][filter_predicate]
            if query_type != 'str' and not filter_value:
                filter_value = None
            if set_filter_dict:
                self.filter_dict = {
                    'by': filter_by,
                    'predicate': orig_filter_predicate,
                    'value': filter_value,
                    'type': query_type
                }

            if query_type == 'datetime':
                if ',' not in filter_value:
                    raise ValidationError('invalid datetime interval argument format.')
                parts = filter_value.split(',')
                if len(parts) != 2:
                    raise ValidationError('invalid datetime interval argument parts.')
                number, measure = parts
                if not number:
                    number = '0'
                if not number.isdigit() or measure not in ['hours', 'days']:
                    raise ValidationError('datetime interval argument is invalid.')

                number = int(number)
                if filter_predicate == 'eq':
                    interval_start = timezone.now() - timezone.timedelta(**{measure: number + 1})
                    interval_end = timezone.now() - timezone.timedelta(**{measure: number})
                    filter_value = (interval_start, interval_end)
                    predicate = 'range'
                else:
                    filter_value = timezone.now() - timezone.timedelta(**{measure: number})
            elif query_type == 'tags':
                filter_value = filter_value.split(',') if filter_value else []
                if filter_value:
                    filter_value = [unquote(v) for v in filter_value]
                    if len(filter_value) != Tag.objects.filter(device__owner=self.request.user,
                                                               name__in=filter_value).distinct().count():
                        raise ValidationError('tags argument list is invalid.')

            if isinstance(query_by, list):
                query = Q()
                for field in query_by:
                    query.add(Q(**{f'{field}__{predicate}': filter_value}), Q.OR)
            else:
                query = Q(**{f'{query_by}__{predicate}': filter_value})

            if invert:
                query = ~query
        else:
            if set_filter_dict:
                self.filter_dict = None

        if since:
            try:
                since_timestamp = dateutil.parser.parse(since)
                if not timezone.is_aware(since_timestamp):
                    raise ValueError
            except ValueError:
                raise ValidationError('"since" is invalid.')
            else:
                query = Q(created__gt=since_timestamp) & query

        return query


class CredentialsQSMixin(object):
    def get_queryset(self):
        return self.request.user.credentials.all()


class PairingKeysQSMixin(object):
    def get_queryset(self):
        return self.request.user.pairing_keys.all()


class ConvertPortsInfoMixin:
    def dicts_to_lists(self, ports):
        if ports:
            return [[d[k] for k in ('address', 'protocol', 'port', 'ip_version')] for d in ports]
        else:
            return []

    def lists_to_dicts(self, ports):
        return [{'address': d[0], 'protocol': d[1], 'port': d[2], 'ip_version': d[3]} for d in ports]


class BlockUnpaidNodeMixin:
    def get(self, request, *args, **kwargs):
        self.object = self.get_object()
        if self.object.payment_status == 'unpaid':
            return HttpResponseForbidden()
        context = self.get_context_data(object=self.object)
        return self.render_to_response(context)
