# -*- encoding: utf-8 -*-
# Part of Odoo. See LICENSE file for full copyright and licensing details.

{
    'name': 'Website Builder',
    'category': 'Website',
    'sequence': 50,
    'summary': 'Build Your Enterprise Website',
    'website': 'https://www.odoo.com/page/website-builder',
    'version': '1.0',
    'description': """
Odoo Website CMS
===================

        """,
    'depends': ['web', 'web_editor', 'web_planner'],
    'installable': True,
    'data': [
    ],
    'qweb': ['static/src/xml/website.backend.xml'],
    'application': True,
}
