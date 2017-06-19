# (c) 2017, Kenneth D. Evensen <kevensen@redhat.com>
#
# This file is part of Ansible
#
# Ansible is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# Ansible is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with Ansible.  If not, see <http://www.gnu.org/licenses/>.

from __future__ import (absolute_import, division, print_function)
__metaclass__ = type

from ansible.errors import AnsibleError
from ansible.plugins.lookup import LookupBase
from ansible.module_utils import urls
from ansible.module_utils.six.moves import urllib
from ansible.module_utils.six.moves.urllib.parse import urlencode
from ansible.module_utils.basic import AnsibleModule

import json

class OC(object):
    def __init__(self, host, port, token, validate_certs):
        self.apis           = ['api', 'oapi']
        self.token          = token
        self.validate_certs = validate_certs
        self.host           = host
        self.port           = port
        self.kinds          = {}
        bearer = "Bearer " + self.token
        self.headers = {"Authorization": bearer}

    def build_facts(self):

        for api in self.apis:
            url = "https://"
            url += self.host
            url += ":"
            url += self.port
            url += "/"
            url += api
            url += "/v1"
            response = urls.open_url(url=url,
                                     headers=self.headers,
                                     validate_certs=self.validate_certs,
                                     method='get')
            if response.code >= 300:
                raise AnsibleError("OC Query raised exception with code %s" +
                                   "and message %s against url %s" %
                                   str(response.code, response.read(),
                                   self.url()))

            for resource in json.loads(response.read())['resources']:
                if 'generated' not in resource['name']:
                    self.kinds[resource['kind']] = \
                        {'kind': resource['kind'],
                         'name': resource['name'].split('/')[0],
                         'namespaced': resource['namespaced'],
                         'api': api,
                         'version': 'v1',
                         'baseurl': url
                         }
    def url(self, kind=None, namespace=None, resource_name=None, pretty=False, labelSelector=None, fieldSelector=None, resourceVersion=None):
        firstParam = True
        self.kind = kind

        url = self.kinds[self.kind]['baseurl']
        if self.kinds[self.kind]['namespaced'] is True:
            url += '/namespaces/'
            if namespace is None:
                raise AnsibleError('Kind %s requires a namespace.  \
                                    None provided' % self.kind)
            url += namespace

        url += '/'
        url += self.kinds[self.kind]['name']

        if resource_name is not None:
            url += '/'
            url += resource_name

        if pretty:
            url += '?pretty'
            firstParam = False

        if labelSelector is not None:
            if firstParam:
                url += '?'
            else:
                url += '&'

            url += urlencode({'labelSelector': labelSelector})
            firstParam = False

        if fieldSelector is not None:
            if firstParam:
                url += '?'
            else:
                url += '&'

            url += urlencode({'fieldSelector': fieldSelector})
            firstParam = False

        if resourceVersion is not None:
            if firstParam:
                url += '?'
            else:
                url += '&'

            url += urlencode({'resourceVersion': resourceVersion})
            firstParam = False


        return url

    def query(self, kind=None, namespace=None, resource_name=None, pretty=False, labelSelector=None, fieldSelector=None, resourceVersion=None):
        url = self.url(kind=kind,
                       namespace=namespace,
                       resource_name=resource_name,
                       pretty=pretty,
                       labelSelector=labelSelector,
                       fieldSelector=fieldSelector,
                       resourceVersion=resourceVersion)

        response = urls.open_url(url=url,
                                 headers=self.headers,
                                 validate_certs=self.validate_certs,
                                 method='get')

        if response.code >= 300:
            raise AnsibleError("OC Query raised exception with code %s" +
                               "and message %s against url %s" %
                               str(response.code, response.read(),
                               self.url()))

        return json.loads(response.read())




class LookupModule(LookupBase):
    def run(self, terms, variables=None, **kwargs):

        host            = kwargs.get('host', '127.0.0.1')
        port            = kwargs.get('port', '8443')
        validate_certs  = kwargs.get('validate_certs', True)
        token           = kwargs.get('token', None)

        namespace       = kwargs.get('namespace', None)
        resource_name   = kwargs.get('resource_name', None)
        pretty          = kwargs.get('pretty', False)
        labelSelector   = kwargs.get('labelSelector', None)
        fieldSelector   = kwargs.get('fieldSelector', None)
        resourceVersion = kwargs.get('resourceVersion', None)
        resource        = terms[0]


        oc = OC(host, port, token, validate_certs)
        oc.build_facts()

        search_response = oc.query(kind=resource,
                                   namespace=namespace,
                                   resource_name=resource_name,
                                   pretty=pretty,
                                   labelSelector=labelSelector,
                                   fieldSelector=fieldSelector,
                                   resourceVersion=resourceVersion)
        if search_response is not None and "items" in search_response:
            search_response['item_list'] = search_response.pop('items')

        values = []
        values.append(search_response)

        return values
