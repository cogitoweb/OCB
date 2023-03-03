# -*- coding: utf-8 -*-
# Part of Odoo. See LICENSE file for full copyright and licensing details.
import logging
import json
from werkzeug.utils import redirect

from odoo import http, registry
from odoo.http import request
_logger = logging.getLogger(__name__)


class GoogleAuth(http.Controller):

    @http.route('/google_account/authentication', type='http', auth="public")
    def oauth2callback(self, **kw):
        """ This route/function is called by Google when user Accept/Refuse the consent of Google """
        state = json.loads(kw['state'])
        dbname = state.get('d')
        service = state.get('s')
        url_return = state.get('f')

        with registry(dbname).cursor() as cr:
            if kw.get('code'):
                access_token, refresh_token, ttl = request.env['google.service']._get_google_tokens(kw['code'], service)
                # LUL TODO only defined in google_calendar
                # non puo funzionare l'utente che fa la richiesta è google uno public user
                # _logger.info(">>> kw: %s<<", kw)
                admin = request.env['res.users'].sudo().search([('id', '=', 21)])
                # _logger.info(">>> admin: %s<<", admin)
                admin._set_auth_tokens(access_token, refresh_token, ttl)
                return redirect(url_return)
            elif kw.get('error'):
                return redirect("%s%s%s" % (url_return, "?error=", kw['error']))
            else:
                return redirect("%s%s" % (url_return, "?error=Unknown_error"))
