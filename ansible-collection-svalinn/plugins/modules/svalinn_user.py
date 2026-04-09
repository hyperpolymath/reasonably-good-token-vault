#!/usr/bin/python
# SPDX-License-Identifier: PMPL-1.0-or-later

# Ansible module for managing Svalinn Vault users

from __future__ import absolute_import, division, print_function
__metaclass__ = type

DOCUMENTATION = r'''
---
module: svalinn_user

short_description: Manage users in Svalinn Vault

version_added: "1.0.0"

description:
- Create, update, and delete users in Svalinn Vault
- Manage MFA policies
- Set compliance profiles

options:
  username:
    description: Username/email of the user
    required: true
    type: str
  display_name:
    description: Display name of the user
    required: false
    type: str
  mfa_required:
    description: Require MFA for this user
    required: false
    type: bool
    default: true
  compliance_profile:
    description: Compliance profile to apply
    required: false
    type: str
    choices: ["nist_aal2", "iso_27001", "soc_2", "hipaa", "gdpr"]
    default: "nist_aal2"
  state:
    description: User state
    required: false
    type: str
    choices: ["present", "absent", "locked", "disabled"]
    default: "present"
  api_url:
    description: Svalinn Vault API URL
    required: false
    type: str
    default: "http://localhost:8443"
  api_key:
    description: Svalinn Vault API key
    required: false
    type: str

author:
  - "Hyperpolymath (@hyperpolymath)"
'''

EXAMPLES = r'''
- name: Create a new user
  svalinn_user:
    username: "user@example.com"
    display_name: "John Doe"
    mfa_required: true
    compliance_profile: "nist_aal2"
    state: present

- name: Lock a user account
  svalinn_user:
    username: "user@example.com"
    state: locked

- name: Delete a user
  svalinn_user:
    username: "user@example.com"
    state: absent
'''

RETURN = r'''
user:
  description: User information
  type: dict
  returned: success
  contains:
    id:
      description: User ID
      type: str
    username:
      description: Username
      type: str
    display_name:
      description: Display name
      type: str
    mfa_required:
      description: MFA requirement status
      type: bool
    compliance_profile:
      description: Applied compliance profile
      type: str
    status:
      description: User status
      type: str
    created_at:
      description: Creation timestamp
      type: str
    last_login:
      description: Last login timestamp
      type: str
'''

from ansible.module_utils.basic import AnsibleModule
import requests
import json


def run_module():
    # Define available arguments/parameters
    module_args = dict(
        username=dict(type='str', required=True),
        display_name=dict(type='str', required=False, default=''),
        mfa_required=dict(type='bool', required=False, default=True),
        compliance_profile=dict(type='str', required=False, default='nist_aal2',
                               choices=['nist_aal2', 'iso_27001', 'soc_2', 'hipaa', 'gdpr']),
        state=dict(type='str', required=False, default='present',
                  choices=['present', 'absent', 'locked', 'disabled']),
        api_url=dict(type='str', required=False, default='http://localhost:8443'),
        api_key=dict(type='str', required=False, no_log=True),
    )

    # Seed the result dict
    result = dict(
        changed=False,
        user={}
    )

    # Create the Ansible module
    module = AnsibleModule(
        argument_spec=module_args,
        supports_check_mode=True
    )

    # Get parameters
    username = module.params['username']
    display_name = module.params['display_name']
    mfa_required = module.params['mfa_required']
    compliance_profile = module.params['compliance_profile']
    state = module.params['state']
    api_url = module.params['api_url']
    api_key = module.params['api_key']

    # Create HTTP headers
    headers = {
        'Content-Type': 'application/json',
        'Authorization': f'Bearer {api_key}'
    }

    # Check if user exists
    user_url = f"{api_url}/api/v1/users/{username}"
    try:
        response = requests.get(user_url, headers=headers)
        if response.status_code == 200:
            existing_user = response.json()
            result['user'] = existing_user
        elif response.status_code == 404:
            existing_user = None
        else:
            response.raise_for_status()
    except requests.exceptions.RequestException as e:
        module.fail_json(msg=f"API error: {str(e)}")

    # Handle state
    if state == 'absent':
        # Delete user
        if existing_user:
            try:
                response = requests.delete(user_url, headers=headers)
                if response.status_code == 204:
                    result['changed'] = True
                    result['user'] = {}
                    module.exit_json(**result)
                else:
                    response.raise_for_status()
            except requests.exceptions.RequestException as e:
                module.fail_json(msg=f"Failed to delete user: {str(e)}")
        else:
            result['changed'] = False
            module.exit_json(**result)

    elif state in ['locked', 'disabled']:
        # Change user status
        if existing_user:
            update_data = {
                'status': state
            }
            try:
                response = requests.patch(user_url, headers=headers, json=update_data)
                if response.status_code == 200:
                    result['changed'] = True
                    result['user'] = response.json()
                    module.exit_json(**result)
                else:
                    response.raise_for_status()
            except requests.exceptions.RequestException as e:
                module.fail_json(msg=f"Failed to update user: {str(e)}")
        else:
            module.fail_json(msg="User not found")

    elif state == 'present':
        # Create or update user
        user_data = {
            'username': username,
            'display_name': display_name,
            'mfa_required': mfa_required,
            'compliance_profile': compliance_profile
        }

        if existing_user:
            # Update existing user
            try:
                response = requests.put(user_url, headers=headers, json=user_data)
                if response.status_code == 200:
                    result['changed'] = True
                    result['user'] = response.json()
                    module.exit_json(**result)
                else:
                    response.raise_for_status()
            except requests.exceptions.RequestException as e:
                module.fail_json(msg=f"Failed to update user: {str(e)}")
        else:
            # Create new user
            try:
                response = requests.post(f"{api_url}/api/v1/users", headers=headers, json=user_data)
                if response.status_code == 201:
                    result['changed'] = True
                    result['user'] = response.json()
                    module.exit_json(**result)
                else:
                    response.raise_for_status()
            except requests.exceptions.RequestException as e:
                module.fail_json(msg=f"Failed to create user: {str(e)}")

    module.exit_json(**result)


def main():
    run_module()


if __name__ == '__main__':
    main()
