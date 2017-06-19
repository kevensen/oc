#!/usr/bin/python
# -*- coding: utf-8 -*-
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


ANSIBLE_METADATA = {'metadata_version': '1.0',
                    'status': ['preview'],
                    'supported_by': 'community'}


DOCUMENTATION = """
author:
  - "Kenneth D. Evensen (@kevensen)"
description:
  - |-
      This module allows management of resources in an OpenShift cluster.  The
      inventory host can be any host with network connectivity to the OpenShift
      cluster; the default port being 8443/TCP.  This module relies on a token
      to authenticate to OpenShift.  This can either be a user or a service
      account.
module: oc
options:
  host:
    description:
      - |-
         Hostname or address of the OpenShift API endpoint.  By default, this is
         expected to be the current inventory host.
    required: false
    default: 127.0.0.1
  port:
    description:
      - |-
         The port number of the API endpoint.
    required: false
    default: 8443
  inline:
    description:
      - "The inline definition of the resource.  This is mutually exclusive
         with name, namespace and kind."
    required: false
  kind:
    description:
      - "The kind of the resource upon which to take action."
    required: true
  name:
    description:
      - "The name of the resource on which to take action."
    required: false
  namespace:
    description:
      - "The namespace of the resource upon which to take action."
    required: false
  toekn:
    description:
      - "The token with which to authenticate agains the OpenShift cluster."
    required: true
  state:
    choices:
      - present
      - absent
    description:
      - "If the state is present, and the resource doesn't exist, it shall be
        created using the inline definition.  If the state is present and the
        resource exists, the definition will be updated, again using an inline
        definition.  If the state is absent, the resource will be deleted if
        it exists."
    required: true
short_description: "Manage OpenShift Resources"
version_added: "2.4"

"""

EXAMPLES = """
- name: Create project
  oc:
    state: present
    inline:
      kind: ProjectRequest
      metadata:
        name: ansibletestproject
      displayName: Ansible Test Project
      description: This project was created using Ansible
      token: << redacted >>
- name: Delete a service
  oc:
    state: absent
    name: myservice
    namespace: mynamespace
    kind: Service
    token: << redacted >>
- name: Add project role Admin to a user
  oc:
    state: present
    inline:
      kind: RoleBinding
      metadata:
        name: admin
        namespace: mynamespace
      roleRef:
        name: admin
      userNames:
      - "myuser"
      token: << redacted >>
- name: Obtain an object definition
  oc:
   state: present
   name: myroute
   namespace: mynamespace
   kind: Route
   token: << redacted >>
"""

RETURN = '''
result:
  description: >
    The resource that was created, changed, or otherwise determined
    to be present.  In the case of a deletion, this is the response from the
    delete request.
  returned: success
  type: string
url:
  description: The URL to the requested resource.
  returned: success
  type: string
method:
  description: The HTTP method that was used to take action upon the resource
  returned: success
  type: string
...
'''

from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils.pycompat24 import get_exception
from ansible.module_utils import urls
from ansible.module_utils.six.moves.urllib.parse import urlencode
import base64
import json
import os
import re
import yaml


class OC(object):
    def __init__(self, token, host, port, module):
        self.apis = ['api', 'oapi']
        self.token = token
        self.module = module
        self.host = host
        self.port = port
        self.kinds = {}

    def build_facts(self):
        bearer = "Bearer " + self.token
        headers = {"Authorization": bearer}
        for api in self.apis:
            url = "https://"
            url += self.host
            url += ":"
            url += str(self.port)
            url += "/"
            url += api
            url += "/v1"
            response, info = urls.fetch_url(module=self.module,
                                            url=url,
                                            headers=headers,
                                            method='get')

            if info['status'] >= 300:
                self.module.fail_json(
                    msg="Failed to get build facts with url %s resulting \
                    in code %s and response %s" %
                    (url, str(info['status']), info['body']))
            self.module.log(msg="URL is %s" % url)
            self.module.log(msg="Response is %s" % response)
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


class Resource(object):
    def __init__(self, token, module, kinds,
                 kind, namespace=None, name=None):
        self.module = module
        self.kinds = kinds
        self.kind = kind
        self.namespace = namespace
        self.name = name
        bearer = "Bearer " + token
        self.headers = {}
        self.headers = {"Authorization": bearer,
                        "Content-type": "application/json"}

    def url(self):
        url = self.kinds[self.kind]['baseurl']
        if self.kinds[self.kind]['namespaced'] is True:
            url += '/namespaces/'
            if self.namespace is None:
                self.module.fail_json(msg='Kind %s requires a namespace.  \
                                      None provided' % self.kind)
            url += self.namespace

        url += '/'
        url += self.kinds[self.kind]['name']

        if self.name is not None:
            url += '/'
            url += self.name
        self.module.log(msg="URL for request is %s" % url)
        return url

    # Attempts to 'kindly' merge the dictionaries into a new object
    # deifinition
    def merge(self, source, destination, changed):

        for key, value in source.items():
            if isinstance(value, dict):
                # get node or create one
                try:
                    node = destination.setdefault(key, {})
                except AttributeError:
                    node = {}
                finally:
                    _, changed = self.merge(value, node, changed)

            elif isinstance(value, list) and key in destination.keys():
                try:
                    if set(destination[key]) != set(destination[key] +
                                                    source[key]):
                        destination[key] = list(set(destination[key] +
                                                    source[key]))
                        changed = True
                except TypeError:
                    for new_dict in source[key]:
                        found = False
                        for old_dict in destination[key]:
                            if ('name' in old_dict.keys() and
                                    'name' in new_dict.keys()):
                                if old_dict['name'] == new_dict['name']:
                                    destination[key].remove(old_dict)
                                    break
                            if old_dict == new_dict:
                                found = True
                                break

                        if not found:
                            destination[key].append(new_dict)
                            changed = True

            elif (key not in destination.keys() or
                  destination[key] != source[key]):
                destination[key] = value
                changed = True
        return destination, changed

    def get(self, fieldSelector=''):
        url = self.url()
        if fieldSelector is not '':
            params = urlencode({'fieldSelector': fieldSelector})
            url += "?"
            url += params

        response, info = urls.fetch_url(module=self.module,
                                        url=url,
                                        headers=self.headers,
                                        method='get')

        self.module.log(msg="Code for GET request is: %s" %
                        str(info['status']))
        if info['status'] == 404:
            return None
        if info['status'] == 403:
            self.module.fail_json(
                msg='Failed to get resource %s in \
                namespace %s with msg %s' % (self.name,
                                             self.namespace,
                                             info['body']))

        self.module.log(msg="Response for GET request is: %s" % str(response))

        json_response = self.module.from_json(response.read())
        if json_response is not None and json_response != {}:
            if (json_response['kind'] == 'Status' and
                    json_response['metadata'] == {}):
                return None

        return json_response

    def exists(self):
        if self.get() is not None:
            return True
        return False

    def create(self, inline):
        changed = False

        inline['kind'] = self.kind
        inline['apiVersion'] = self.kinds[self.kind]['version']
        data = self.module.jsonify(inline)
        self.module.log(msg="JSON body for create request is %s" % data)

        url = self.url()[:self.url().rfind('/')]
        response, info = urls.fetch_url(module=self.module,
                                        headers=self.headers,
                                        url=url,
                                        method='post',
                                        data=data)

        self.module.log(msg="Code for POST request is: %s" %
                        str(info['status']))

        if info['status'] == 404:
            return None, changed
        elif info['status'] == 409:
            return self.get(), changed
        elif info['status'] >= 300:
            self.module.fail_json(
                msg='Failed to create resource %s in \
                namespace %s with msg %s' % (self.name,
                                             self.namespace,
                                             info['body']))

        self.module.log(msg="Response for POST request is: %s" % str(response))
        return self.module.from_json(response.read()), True

    def replace(self, inline):
        changed = False
        resource = self.get()
        new_resource, changed = self.merge(inline, resource, changed)
        data = self.module.jsonify(new_resource)

        if changed:
            self.module.log(
                msg="JSON body for update request is %s"
                % json.dumps(new_resource))
            response, info = urls.fetch_url(module=self.module,
                                            url=self.url(),
                                            headers=self.headers,
                                            method='put',
                                            data=data)
            self.module.log(msg="Code for PUT request is: %s"
                            % str(info['status']))

            if info['status'] >= 300:
                self.module.fail_json(
                    msg='Failed to update resource %s in \
                    namespace %s with msg %s'
                    % (self.name, self.namespace, info['body']))

            return self.module.from_json(response.read()), changed
        return resource, changed

    def delete(self):

        changed = False

        response, info = urls.fetch_url(url=self.url(),
                                        module=self.module,
                                        headers=self.headers,
                                        method='delete')

        self.module.log(msg="Code for DELETE request is: %s"
                        % str(info['status']))

        if info['status'] == 404:
            return None, changed
        elif info['status'] >= 300:
            self.module.fail_json(msg='Failed to delete resource %s in \
                                  namespace %s with msg %s'
                                  % (name, namespace, info['body']))
        self.module.log(msg="Response for DELETE request is: %s"
                        % str(response))
        changed = True
        return self.module.from_json(response.read()), changed


def main():

    module = AnsibleModule(
        argument_spec=dict(
            host=dict(required=False, type='str', default='127.0.0.1'),
            port=dict(required=False, type='int', default=8443),
            inline=dict(required=False, type='dict'),
            kind=dict(required=False, type='str'),
            name=dict(required=False, type='str'),
            namespace=dict(required=False, type='str'),
            token=dict(required=True, type='str', no_log=True),
            fieldSelector=dict(required=False, default='', type='str'),
            state=dict(required=True,
                       choices=['present', 'absent']),
            validate_certs=dict(required=False, type='bool', default='yes')
        ),
        mutually_exclusive=(['kind', 'inline']),
        required_if=([['state', 'absent', ['kind']]]),
        required_one_of=([['kind', 'inline']]),
        no_log=False,
        supports_check_mode=False
    )
    kind = None
    inline = None
    name = None
    namespace = None

    host = module.params['host']
    port = module.params['port']
    inline = module.params['inline']
    state = module.params['state']
    kind = module.params['kind']
    fieldSelector = module.params['fieldSelector']
    name = module.params['name']
    namespace = module.params['namespace']
    token = module.params['token']

    if inline is not None:
        kind = inline['kind']
        try:
            if name is None:
                name = inline['metadata']['name']
            else:
                inline['metadata']['name'] = name
        except KeyError:
            pass

        try:
            if namespace is None:
                namespace = inline['metadata']['namespace']
            else:
                inline['metadata']['namespace'] = namespace
        except KeyError:
            pass

    result = None
    oc = OC(token, host, port, module)
    oc.build_facts()
    changed = False
    method = ''

    resource = Resource(module=module,
                        token=token,
                        kinds=oc.kinds,
                        kind=kind,
                        namespace=namespace,
                        name=name)

    if state == 'present' and resource.exists() and inline is None:
        result = resource.get(fieldSelector=fieldSelector)
        method = 'get'
    elif state == 'present' and resource.exists():
        result, changed = resource.replace(inline=inline)
        method = 'put'
    elif state == 'present' and not resource.exists() and inline is not None:
        result, changed = resource.create(inline=inline)
        method = 'create'
    elif state == 'absent' and resource.exists():
        result, changed = resource.delete()
        method = 'delete'

    facts = {}

    if result is not None and "items" in result:
        result['item_list'] = result.pop('items')
    elif result is None and state == 'present':
        result = 'Resource not present and no inline provided.'
    facts['oc'] = {'result': result,
                   'url': resource.url(),
                   'method': method}

    module.exit_json(changed=changed, ansible_facts=facts)

if __name__ == '__main__':
    main()
