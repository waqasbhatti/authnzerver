#!/usr/bin/env python
# -*- coding: utf-8 -*-
# permissions.py - Waqas Bhatti (wbhatti@astro.princeton.edu) - Aug 2018
# License: MIT - see the LICENSE file for the full text.

'''
This contains the permissions and user-role models for authnzerver.

'''

#############
## LOGGING ##
#############

import logging

# get a logger
LOGGER = logging.getLogger(__name__)

#############
## IMPORTS ##
#############

import json
from hashlib import sha256


###################################
## FUNCTION TO HASH PII FOR LOGS ##
###################################

def pii_hash(item, salt):
    return sha256(
        ("%s%s" % (item, salt)).encode('utf-8')
    ).hexdigest()[:16]


#################################
##  PERMISSION MODEL FUNCTIONS ##
#################################

def load_permissions_json(model_json):
    '''Loads a permissions JSON and returns the model.'''

    with open(model_json,'r') as infd:
        model = json.load(infd)

    # load the item policy
    item_policy = model['item_policy']

    for itemkey in item_policy:
        item_policy[itemkey]['valid_role_actions'] = set(
            item_policy[itemkey]['valid_role_actions']
        )
        item_policy[itemkey]['valid_visibilities'] = set(
            item_policy[itemkey]['valid_visibilities']
        )
        item_policy[itemkey]['invalid_roles'] = set(
            item_policy[itemkey]['invalid_roles']
        )

    # load the role policy
    role_policy = model['role_policy']

    for rolekey in role_policy:
        role_policy[rolekey]['can_own_items'] = set(
            role_policy[rolekey]['can_own_items']
        )
        role_policy[rolekey]['allowed_actions_for_owned'] = set(
            role_policy[rolekey]['allowed_actions_for_owned']
        )
        for actionkey in role_policy[rolekey]['allowed_actions_for_other']:
            role_policy[rolekey]['allowed_actions_for_other'][actionkey] = set(
                role_policy[rolekey]['allowed_actions_for_other'][actionkey]
            )

    model['roles'] = set(model['roles'])
    model['items'] = set(model['items'])
    model['actions'] = set(model['actions'])
    model['visibilities'] = set(model['visibilities'])

    return model


##########################
## CHECKING PERMISSIONS ##
##########################

def get_item_actions(permissions_model,
                     role_name,
                     target_name,
                     target_visibility,
                     target_ownership,
                     debug=False):
    '''Returns the possible actions for a target given a role and target
    status.

    Parameters
    ----------

    permissions_policy : dict
        A permissions model returned by :py:func:`.load_permissions_json`.

    role_name : str
        The name of the role to find the valid actions for.

    target_name : str
        The name of the item to check the valid actions for.

    target_visibility : str
        The visibility of the tiem to check the valid actions for.

    target_ownership: {'for_owned','for_other'}
        If 'for_owned', only the valid actions for the target item available if
        the item is owned by the user will be returned. If 'for_other', only the
        valid actions subject to the visibility of the item owned by other users
        will be returned.

    debug : bool
        If True, will print the policy decisions being taken.

    Returns
    -------

    set
        Returns a set of valid actions for the target item based on the applied
        policy. If the actions don't make sense, returns an empty set, in which
        case access MUST be denied.

    '''

    role_policy = permissions_model['role_policy']
    item_policy = permissions_model['item_policy']

    if debug:
        print(
            'role_name = %s\ntarget_name = %s\n'
            'target_visibility = %s\ntarget_ownership = %s' %
            (role_name, target_name, target_visibility, target_ownership)
        )

    try:
        target_valid_actions = item_policy[
            target_name
        ]['valid_role_actions']
        target_valid_visibilities = item_policy[
            target_name
        ]['valid_visibilities']
        target_invalid_roles = item_policy[
            target_name
        ]['invalid_roles']

        if debug:
            print('%s valid_perms: %r' %
                  (target_name, target_valid_actions))
            print('%s valid_visibilities: %r' %
                  (target_name, target_valid_visibilities))
            print('%s invalid_roles: %r' %
                  (target_name, target_invalid_roles))

        # if the role is not allowed into this target, return
        if role_name in target_invalid_roles:
            return set({})

        # if the target's status is not valid, return
        if target_visibility not in target_valid_visibilities:
            return set({})

        # check the target's ownership

        # if this target is owned by the user, then check target owned
        # actions
        if target_ownership == 'for_owned':
            role_actions = role_policy[role_name]['allowed_actions_for_owned']

        # otherwise, the target is not owned by the user (target_ownership ==
        # 'for_other'), check ownership actions for target status
        else:
            role_actions = (
                role_policy[role_name]['allowed_actions_for_other'][
                    target_visibility
                ]
            )

        # these are the final available actions
        available_actions = role_actions.intersection(
            target_valid_actions
        )

        if debug:
            print("target role actions: %r" % role_actions)
            print('available actions for role: %r' % available_actions)

        return available_actions

    except Exception:
        return set({})


def check_item_access(permissions_model,
                      userid=2,
                      role='anonymous',
                      action='view',
                      target_name='collection',
                      target_owner=1,
                      target_visibility='private',
                      target_sharedwith=None,
                      debug=False):
    '''
    This does a check for user access to a target item.

    Parameters
    ----------

    permissions_policy : dict
        A permissions model returned by :py:func:`.load_permissions_json`.

    userid : int
        The userid of the user requesting access.

    role : str
        The role of the user requesting access.

    action : str
        The action requested to be applied to the item.

    target_name : str
        The name of the item for which the policy will be checked.

    target_owner : int
        The userid of the user that owns the item for which the policy will be
        checked.

    target_visibility : str
        The visibility of the item for which the policy will be checked.

    target_sharedwith: str
        A CSV string of the userids that the target item is shared with.

    debug : bool
        If True, will report the various policy decisions applied.

    Returns
    -------

    bool
        True if access was granted. False otherwise.

    '''

    role_policy = permissions_model['role_policy']

    if debug:
        print('userid = %s\ntarget_owner = %s\nsharedwith_userids = %s' %
              (userid, target_owner, target_sharedwith))

    if role in ('superuser', 'staff'):

        shared_or_owned_ok = True

    elif target_visibility == 'private':

        shared_or_owned_ok = userid == target_owner

    elif target_visibility == 'shared':

        try:

            if (target_sharedwith and
                target_sharedwith != '' and
                target_sharedwith.lower() != 'none'):

                sharedwith_userids = target_sharedwith.split(',')
                sharedwith_userids = [int(x) for x in sharedwith_userids]
                if debug:
                    print('sharedwith_userids = %s' % sharedwith_userids)

                shared_or_owned_ok = (
                    userid in sharedwith_userids or userid == target_owner
                )

                # anything shared with anonymous users is effectively shared for
                # everyone
                if 2 in sharedwith_userids:
                    shared_or_owned_ok = True

            else:
                shared_or_owned_ok = (
                    userid == target_owner
                )

        except Exception:
            shared_or_owned_ok = False

    # unlisted objects are OK to view
    elif target_visibility == 'unlisted':

        shared_or_owned_ok = True

    elif target_visibility == 'public':

        shared_or_owned_ok = True

    else:

        shared_or_owned_ok = False

    if debug:
        print('target shared or owned test passed = %s' % shared_or_owned_ok)

    target_may_be_owned_by_role = (
        target_name in role_policy[role]['can_own_items']
    )

    if debug:
        print("target: '%s' may be owned by role: '%s' = %s" %
              (target_name, role, target_may_be_owned_by_role))

    # validate ownership of the target
    if (userid == target_owner and target_may_be_owned_by_role):
        perms = get_item_actions(permissions_model,
                                 role,
                                 target_name,
                                 target_visibility,
                                 'for_owned',
                                 debug=debug)

    # if the target is not owned, then check if it's accessible under its scope
    # and visibility
    elif userid != target_owner:
        perms = get_item_actions(permissions_model,
                                 role,
                                 target_name,
                                 target_visibility,
                                 'for_other',
                                 debug=debug)

    # if the target cannot be owned by the role, then fail
    else:
        perms = set({})

    if debug:
        print("user action: '%s', permitted actions: %s" % (action, perms))

    return ((action in perms) and shared_or_owned_ok)


def load_policy_and_check_access(
        permissions_json,
        userid=2,
        role='anonymous',
        action='view',
        target_name='collection',
        target_owner=1,
        target_visibility='private',
        target_sharedwith=None,
        debug=False):
    '''
    Does a check for user access to a target item.

    This version loads a permissions JSON from disk every time it is called.

    Parameters
    ----------

    permissions_policy : dict
        A permissions model returned by :py:func:`.load_permissions_json`.

    userid : int
        The userid of the user requesting access.

    role : str
        The role of the user requesting access.

    action : str
        The action requested to be applied to the item.

    target_name : str
        The name of the item for which the policy will be checked.

    target_owner : int
        The userid of the user that owns the item for which the policy will be
        checked.

    target_visibility : str
        The visibility of the item for which the policy will be checked.

    target_sharedwith: str
        A CSV string of the userids that the target item is shared with.

    debug : bool
        If True, will report the various policy decisions applied.

    Returns
    -------

    bool
        True if access was granted. False otherwise.

    '''

    permissions_model = load_permissions_json(permissions_json)
    return check_item_access(
        permissions_model,
        userid=userid,
        role=role,
        action=action,
        target_name=target_name,
        target_owner=target_owner,
        target_visibility=target_visibility,
        target_sharedwith=target_sharedwith
    )


def check_role_limits(permissions_model,
                      role,
                      limit_name,
                      value_to_check):
    '''
    This applies the role limits to a value to check.

    Parameters
    ----------

    permissions_model : dict
        A permissions model returned by :py:func:`.load_permissions_json`.

    role : str
        The name of the role to check the limits for.

    limit_name : str
        The name of limit to check.

    value_to_check : float or int
        The value to check against the limit.

    Returns
    -------

    bool
        Returns True if the limit hasn't been exceeded. Returns False otherwise.

    '''

    role_policy = permissions_model['role_policy']
    limit_defs = permissions_model['limits']

    all_role_limits = role_policy[role]['limits'].get(limit_name)

    # if there's no limit for the requested type, return True to indicate this
    if not all_role_limits:
        return True

    limit_type = all_role_limits["type"]
    limit_to_apply = all_role_limits["limit"]

    # look up the operator to apply
    limit_vartype = limit_defs[limit_type]["type"]
    limit_operator = limit_defs[limit_type]["operator"]

    # cast the value to the appropriate type
    try:
        if limit_vartype == 'int':
            value_to_check = int(value_to_check)
            limit_to_apply = int(limit_to_apply)

        elif limit_vartype == 'float':
            value_to_check = float(value_to_check)
            limit_to_apply = float(limit_to_apply)

    except Exception:
        LOGGER.error("Could not convert value to be checked "
                     "to expected type for limit operator")
        return False

    # parse the operator and apply the limit
    try:
        if limit_operator == 'gt':
            return value_to_check > limit_to_apply
        elif limit_operator == 'lt':
            return value_to_check < limit_to_apply
        else:
            LOGGER.error("unknown operator requested for limit")
            return False

    except Exception:
        LOGGER.error("Could not apply limit operator to value")
        return False


def load_policy_and_check_limits(
        permissions_json,
        role,
        limit_name,
        value_to_check
):
    '''
    Applies the role limits to a value to check.

    This version loads a policy JSON every time it is called.

    Parameters
    ----------

    permissions_model : dict
        A permissions model returned by :py:func:`.load_permissions_json`.

    role : str
        The name of the role to check the limits for.

    limit_name : str
        The name of limit to check.

    value_to_check : float or int
        The value to check against the limit.

    Returns
    -------

    bool
        Returns True if the limit hasn't been exceeded. Returns False otherwise.

    '''

    permissions_model = load_permissions_json(permissions_json)
    return check_role_limits(
        permissions_model,
        role,
        limit_name,
        value_to_check
    )
