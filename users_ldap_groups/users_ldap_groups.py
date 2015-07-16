# -*- coding: utf-8 -*-
##############################################################################
#
#    OpenERP, Open Source Management Solution
#    This module copyright (C) 2012 Therp BV (<http://therp.nl>).
#
#    This program is free software: you can redistribute it and/or modify
#    it under the terms of the GNU Affero General Public License as
#    published by the Free Software Foundation, either version 3 of the
#    License, or (at your option) any later version.
#
#    This program is distributed in the hope that it will be useful,
#    but WITHOUT ANY WARRANTY; without even the implied warranty of
#    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#    GNU Affero General Public License for more details.
#
#    You should have received a copy of the GNU Affero General Public License
#    along with this program.  If not, see <http://www.gnu.org/licenses/>.
#
##############################################################################

from openerp import models
from openerp import fields
from openerp import api
import logging
import users_ldap_groups_operators
import inspect


class CompanyLDAPGroupMapping(models.Model):
    _name = 'res.company.ldap.group_mapping'
    _rec_name = 'ldap_attribute'
    _order = 'ldap_attribute'

    def _get_operators(self):
        operators = []
        members = inspect.getmembers(
            users_ldap_groups_operators,
            lambda cls:
            inspect.isclass(cls) and
            cls != users_ldap_groups_operators.LDAPOperator)
        for name, operator in members:
            operators.append((name, name))
        return tuple(operators)

    ldap_id = fields.Many2one('res.company.ldap', 'LDAP server', required=True)
    ldap_attribute = fields.Char(
        'LDAP attribute', size=64,
        help='The LDAP attribute to check.\n'
             'For active directory, use memberOf.')
    operator = fields.Selection(
        _get_operators, 'Operator',
        help='The operator to check the attribute against the value\n'
        'For active directory, use \'contains\'', required=True)
    value = fields.Char(
        'Value', size=1024,
        help='The value to check the attribute against.\n'
        'For active directory, use the dn of the desired group',
        required=True)
    group = fields.Many2one(
        'res.groups', 'OpenERP group',
        help='The OpenERP group to assign', required=True)


class CompanyLDAP(models.Model):
    _inherit = 'res.company.ldap'

    group_mappings = fields.One2many(
        'res.company.ldap.group_mapping',
        'ldap_id', 'Group mappings',
        help='Define how OpenERP groups are assigned to ldap users')
    only_ldap_groups = fields.Boolean(
        'Only ldap groups',
        help='If this is checked, manual changes to group membership are '
             'undone on every login (so OpenERP groups are always synchronous '
             'with LDAP groups). If not, manually added groups are preserved.')

    _default = {
        'only_ldap_groups': False,
    }

    @api.model
    def get_or_create_user(self, conf, login, ldap_entry):
        id_ = conf['id']
        this = self.browse(id_)
        user_id = super(CompanyLDAP, self).get_or_create_user(
            conf, login, ldap_entry)
        if not user_id:
            return user_id
        userobj = self.env['res.users']
        user = userobj.browse(user_id)
        logger = logging.getLogger('users_ldap_groups')
        if self.only_ldap_groups:
            logger.debug('deleting all groups from user %d' % user_id)
            userobj.write([user_id], {'groups_id': [(5, )]})

        for mapping in this.group_mappings:
            operator = mapping.operator
            operator = getattr(users_ldap_groups_operators, mapping.operator)()
            logger.debug('checking mapping %s' % mapping)
            if operator.check_value(ldap_entry, mapping['ldap_attribute'],
                                    mapping['value'], conf, self, logger):
                logger.debug('adding user %d to group %s' %
                             (user_id, mapping.group.name))
                user.write({'groups_id': [(4, mapping.group.id)]})
        return user_id