# from filter/OCFilter.py

from ansible.errors import AnsibleError
from ansible.plugins.lookup import LookupBase
from ansible.utils.listify import listify_lookup_plugin_terms
import base64
import re


def dockercfg_change_server(data, newserver, oldserver, default_port=''):
    decoded = base64.b64decode(data['.dockercfg'])

    if isinstance(default_port, int):
        default_port = str(default_port)

    if default_port is not '':
        oldserver += ":" + default_port
    new_config = decoded.replace(oldserver, newserver)
    new_config = re.sub(r',\"docker-registry.default.svc:5000.+[^}]',
                        '',
                        new_config)
    new_config = new_config.replace("}}}", "}}")

    data['.dockercfg'] = base64.b64encode(new_config)

    return data


def remove_image(data, delete=False):
    for container in data['spec']['containers']:
        if not delete:
            container['image'] = ' '
        else:
            del container['image']
    return data


def translate_image_trigger(data, namespace):
    for trigger in data:
        if trigger['type'] in 'ImageChange':
            try:
                del trigger['imageChangeParams']['lastTriggeredImage']
            except KeyError:
                pass
            try:
                if (trigger['imageChangeParams']['from']['namespace'] in
                        namespace):
                    trigger['imageChangeParams']['from']['namespace'] = \
                        namespace
            except KeyError:
                pass
    return data


def remove_system_users(data):
    return [username for username in data if not username.startswith('system:')]


def uniqueify_resource(resource):

    try:
        del resource['metadata']['creationTimestamp']
        del resource['metadata']['resourceVersion']
        del resource['metadata']['uid']
    except KeyError:
        pass

    try:
        del resource['spec']['clusterIP']
    except KeyError:
        pass

    try:
        del resource['status']['ingress']
    except KeyError:
        pass

    return resource


class FilterModule(object):

    def filters(self):
        return {
            'remove_image': remove_image,
            'translate_image_trigger': translate_image_trigger,
            'uniqueify_resource': uniqueify_resource,
            'dockercfg_change_server': dockercfg_change_server,
            'remove_system_users': remove_system_users
        }
